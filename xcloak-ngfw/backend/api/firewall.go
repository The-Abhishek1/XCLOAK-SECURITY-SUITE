package api

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"xcloak-ngfw/models"
	"xcloak-ngfw/repositories"
	"xcloak-ngfw/services"
)

func CreateRule(c *gin.Context) {

	var rule models.FirewallRule

	if err := c.ShouldBindJSON(&rule); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	err := services.CreateFirewallRule(rule, tenantIDFromContext(c))

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Rule Created",
	})
}

func GetRules(c *gin.Context) {

	rules, err := repositories.GetRulesForTenant(tenantIDFromContext(c))

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, rules)
}

func GetRuleByID(c *gin.Context) {

	id := c.Param("id")

	rule, err := repositories.GetRuleByID(id, tenantIDFromContext(c))

	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Rule not found",
		})
		return
	}

	c.JSON(http.StatusOK, rule)
}

func UpdateRule(c *gin.Context) {

	id := c.Param("id")

	var rule models.FirewallRule

	if err := c.ShouldBindJSON(&rule); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	rowsAffected, err := repositories.UpdateRule(
		id,
		rule,
		tenantIDFromContext(c),
	)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	if rowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Rule not found",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Rule Updated",
	})
}

func DeleteRule(c *gin.Context) {

	id := c.Param("id")

	rowsAffected, err := repositories.DeleteRule(id, tenantIDFromContext(c))

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	if rowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Rule not found",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Rule Deleted",
	})
}

func Health(c *gin.Context) {

	c.JSON(http.StatusOK, gin.H{
		"status":  "healthy",
		"service": "xcloak-ngfw",
	})
}
