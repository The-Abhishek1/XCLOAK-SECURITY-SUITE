package api

import (
	"fmt"
	"strconv"

	"github.com/gin-gonic/gin"

	"xcloak-ngfw/models"
	"xcloak-ngfw/repositories"
	"xcloak-ngfw/services"
)


func CreateSigmaRule(
	c *gin.Context,
) {

	var rule models.SigmaRule

	if err := c.ShouldBindJSON(&rule); err != nil {

		c.JSON(
			400,
			gin.H{
				"error": err.Error(),
			},
		)

		return
	}

	err := services.CreateSigmaRule(
		rule,
		tenantIDFromContext(c),
	)

	if err != nil {

		c.JSON(
			500,
			gin.H{
				"error": err.Error(),
			},
		)

		return
	}

	c.JSON(
		200,
		gin.H{
			"message": "Rule Created",
		},
	)
}

func GetSigmaRules(c *gin.Context) {
	page, _    := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _   := strconv.Atoi(c.DefaultQuery("limit", "50"))
	search     := c.Query("search")
	severity   := c.Query("severity")

	result, err := repositories.GetSigmaRulesPaged(tenantIDFromContext(c), page, limit, search, severity)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, result)
}

func GetSigmaRuleByID(
	c *gin.Context,
) {

	id := c.Param("id")

	rule, err := services.GetSigmaRuleByID(
		id,
		tenantIDFromContext(c),
	)

	if err != nil {

		c.JSON(
			404,
			gin.H{
				"error": "Rule not found",
			},
		)

		return
	}

	c.JSON(
		200,
		rule,
	)
}

func UpdateSigmaRule(
	c *gin.Context,
) {

	id := c.Param("id")

	var rule models.SigmaRule

	if err := c.ShouldBindJSON(&rule); err != nil {

		c.JSON(
			400,
			gin.H{
				"error": err.Error(),
			},
		)

		return
	}

	err := services.UpdateSigmaRule(
		id,
		rule,
		tenantIDFromContext(c),
	)

	if err != nil {

		if err == repositories.ErrSigmaRuleNotFound {
			c.JSON(404, gin.H{"error": "rule not found"})
			return
		}

		c.JSON(
			500,
			gin.H{
				"error": err.Error(),
			},
		)

		return
	}

	c.JSON(
		200,
		gin.H{
			"message": "Rule Updated",
		},
	)
}

func DeleteSigmaRule(
	c *gin.Context,
) {

	id := c.Param("id")

	err := services.DeleteSigmaRule(
		id,
		tenantIDFromContext(c),
	)

	if err != nil {

		if err == repositories.ErrSigmaRuleNotFound {
			c.JSON(404, gin.H{"error": "rule not found"})
			return
		}

		c.JSON(
			500,
			gin.H{
				"error": err.Error(),
			},
		)

		return
	}

	username, _ := c.Get("username")
	services.LogEvent("SIGMA_RULE_DELETE", fmt.Sprintf("id=%s", id), fmt.Sprintf("%v", username))
	c.JSON(
		200,
		gin.H{
			"message": "Rule Deleted",
		},
	)
}

func EnableSigmaRule(
	c *gin.Context,
) {

	id := c.Param("id")

	err := services.EnableSigmaRule(
		id,
		tenantIDFromContext(c),
	)

	if err != nil {

		if err == repositories.ErrSigmaRuleNotFound {
			c.JSON(404, gin.H{"error": "rule not found"})
			return
		}

		c.JSON(
			500,
			gin.H{
				"error": err.Error(),
			},
		)

		return
	}

	c.JSON(
		200,
		gin.H{
			"message": "Rule Enabled",
		},
	)
}

func DisableSigmaRule(
	c *gin.Context,
) {

	id := c.Param("id")

	err := services.DisableSigmaRule(
		id,
		tenantIDFromContext(c),
	)

	if err != nil {

		if err == repositories.ErrSigmaRuleNotFound {
			c.JSON(404, gin.H{"error": "rule not found"})
			return
		}

		c.JSON(
			500,
			gin.H{
				"error": err.Error(),
			},
		)

		return
	}

	c.JSON(
		200,
		gin.H{
			"message": "Rule Disabled",
		},
	)
}

// GetSigmaStats — GET /api/sigma/stats
// Returns hit count and last-matched-at per rule for the calling tenant.
func GetSigmaStats(c *gin.Context) {
	stats, err := services.GetSigmaStats(tenantIDFromContext(c))
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	if stats == nil {
		stats = []repositories.SigmaRuleStat{}
	}
	c.JSON(200, stats)
}
