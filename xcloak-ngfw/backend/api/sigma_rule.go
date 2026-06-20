package api

import (
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

func GetSigmaRules(
	c *gin.Context,
) {

	rules, err := services.GetSigmaRules(tenantIDFromContext(c))

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
		rules,
	)
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
