package api

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"xcloak-ngfw/models"
	"xcloak-ngfw/services"
)

// ── Hunt Templates ─────────────────────────────────────────────────────────

func ListHuntTemplates(c *gin.Context) {
	templates, err := services.GetHuntTemplates(tenantIDFromContext(c))
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	if templates == nil {
		templates = []models.HuntTemplate{}
	}
	c.JSON(http.StatusOK, templates)
}

func CreateHuntTemplate(c *gin.Context) {
	tenantID := tenantIDFromContext(c)
	var t models.HuntTemplate
	if err := c.ShouldBindJSON(&t); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	t.TenantID = tenantID
	t.CreatedBy = usernameFromContext(c)
	created, err := services.CreateHuntTemplate(t)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, created)
}

func DeleteHuntTemplate(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	if err := services.DeleteHuntTemplate(id, tenantIDFromContext(c)); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "deleted"})
}

// ── Hunt Runs ──────────────────────────────────────────────────────────────

func ListHuntRuns(c *gin.Context) {
	runs, err := services.GetHuntRuns(tenantIDFromContext(c))
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	if runs == nil {
		runs = []models.HuntRun{}
	}
	c.JSON(http.StatusOK, runs)
}

func GetHuntRunDetail(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	run, err := services.GetHuntRun(id, tenantIDFromContext(c))
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, run)
}

func ExecuteHunt(c *gin.Context) {
	tenantID := tenantIDFromContext(c)
	analyst := usernameFromContext(c)
	var body struct {
		TemplateID *int   `json:"template_id"`
		Name       string `json:"name"`
		KQLQuery   string `json:"kql_query"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	if body.KQLQuery == "" {
		c.JSON(400, gin.H{"error": "kql_query is required"})
		return
	}
	if body.Name == "" {
		body.Name = "Ad-hoc Hunt"
	}
	run, err := services.ExecuteHunt(tenantID, body.TemplateID, body.Name, body.KQLQuery, analyst)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusAccepted, run)
}

func UpdateHuntRunNotes(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var body struct {
		Notes    string `json:"notes"`
		Severity string `json:"severity"`
	}
	c.ShouldBindJSON(&body)
	if err := services.UpdateHuntRunNotes(id, tenantIDFromContext(c), body.Notes, body.Severity); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "updated"})
}
