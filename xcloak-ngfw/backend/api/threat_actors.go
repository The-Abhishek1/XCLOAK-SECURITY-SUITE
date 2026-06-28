package api

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"xcloak-ngfw/models"
	"xcloak-ngfw/services"
)

func ListThreatActors(c *gin.Context) {
	actors, err := services.GetThreatActors(tenantIDFromContext(c))
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	if actors == nil {
		actors = []models.ThreatActor{}
	}
	c.JSON(http.StatusOK, actors)
}

func CreateThreatActor(c *gin.Context) {
	var a models.ThreatActor
	if err := c.ShouldBindJSON(&a); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	a.TenantID = tenantIDFromContext(c)
	created, err := services.CreateThreatActor(a)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, created)
}

func DeleteThreatActor(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	if err := services.DeleteThreatActor(id, tenantIDFromContext(c)); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "deleted"})
}

func GetActorAlerts(c *gin.Context) {
	actorID, _ := strconv.Atoi(c.Param("id"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	alerts, err := services.GetRecentActorAlerts(actorID, tenantIDFromContext(c), limit)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	if alerts == nil {
		alerts = []map[string]any{}
	}
	c.JSON(http.StatusOK, alerts)
}

func GetAlertActorTags(c *gin.Context) {
	alertID, _ := strconv.Atoi(c.Param("id"))
	tags, err := services.GetActorTagsForAlert(alertID, tenantIDFromContext(c))
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	if tags == nil {
		tags = []models.ActorAlertTag{}
	}
	c.JSON(http.StatusOK, tags)
}

// ── Playbook Recommender ───────────────────────────────────────────────────

func GetPlaybookRecommendations(c *gin.Context) {
	alertID, _ := strconv.Atoi(c.Param("id"))
	tenantID := tenantIDFromContext(c)
	// Try cached first
	recs, err := services.GetPlaybookRecommendations(alertID, tenantID)
	if err != nil || len(recs) == 0 {
		// Compute fresh
		recs, err = services.RecommendPlaybooks(alertID, tenantID)
		if err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
	}
	if recs == nil {
		recs = []models.PlaybookRecommendation{}
	}
	c.JSON(http.StatusOK, recs)
}

func ExecuteRecommendedPlaybook(c *gin.Context) {
	alertID, _ := strconv.Atoi(c.Param("id"))
	var body struct {
		RecommendationID int `json:"recommendation_id"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	err := services.ExecuteRecommendedPlaybook(body.RecommendationID, alertID, tenantIDFromContext(c), usernameFromContext(c))
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "playbook dispatched"})
}

// ── Network Behavior Analytics ─────────────────────────────────────────────

func GetNetworkAnomalies(c *gin.Context) {
	tenantID := tenantIDFromContext(c)
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "100"))
	anomalies, err := services.GetNetworkAnomalies(tenantID, limit)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	if anomalies == nil {
		anomalies = []models.NetworkAnomaly{}
	}
	c.JSON(http.StatusOK, anomalies)
}

func AcknowledgeNetworkAnomaly(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	if err := services.AcknowledgeNetworkAnomaly(id, tenantIDFromContext(c)); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "acknowledged"})
}

func GetNetworkBaselineStats(c *gin.Context) {
	agentID, _ := strconv.Atoi(c.Param("agent_id"))
	stats, err := services.GetNetworkBaselineStats(agentID, tenantIDFromContext(c))
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, stats)
}

func TriggerNBAAnalysis(c *gin.Context) {
	tenantID := tenantIDFromContext(c)
	go services.RunNBAForTenant(tenantID)
	c.JSON(http.StatusOK, gin.H{"message": "NBA analysis started"})
}
