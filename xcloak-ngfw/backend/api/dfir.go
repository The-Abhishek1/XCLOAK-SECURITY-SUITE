package api

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"xcloak-ngfw/models"
	"xcloak-ngfw/services"
)

func ListForensicCollections(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	cols, err := services.ListForensicCollections(tenantIDFromContext(c), limit)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	if cols == nil {
		cols = []models.ForensicCollection{}
	}
	c.JSON(http.StatusOK, cols)
}

func TriggerForensicCollection(c *gin.Context) {
	var body struct {
		AgentID       int      `json:"agent_id"`
		IncidentID    *int     `json:"incident_id"`
		Label         string   `json:"label"`
		ArtifactTypes []string `json:"artifact_types"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	if body.AgentID == 0 {
		c.JSON(400, gin.H{"error": "agent_id required"})
		return
	}
	if body.Label == "" {
		body.Label = "Forensic Collection"
	}
	id, err := services.TriggerForensicCollection(
		body.AgentID, tenantIDFromContext(c), body.IncidentID,
		body.Label, usernameFromContext(c), body.ArtifactTypes,
	)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"collection_id": id})
}

func GetCollectionArtifacts(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	artifacts, err := services.GetCollectionArtifacts(id, tenantIDFromContext(c))
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	if artifacts == nil {
		artifacts = []models.ForensicArtifact{}
	}
	c.JSON(http.StatusOK, artifacts)
}

func GetForensicTimeline(c *gin.Context) {
	incidentID, _ := strconv.Atoi(c.Param("incident_id"))
	events, err := services.BuildForensicTimeline(incidentID, tenantIDFromContext(c))
	if err != nil {
		c.JSON(404, gin.H{"error": err.Error()})
		return
	}
	if events == nil {
		events = []models.ForensicTimelineEvent{}
	}
	c.JSON(http.StatusOK, events)
}

// ── Alert Clustering ───────────────────────────────────────────────────────

func ListAlertClusters(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "100"))
	clusters, err := services.GetAlertClusters(tenantIDFromContext(c), limit)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	if clusters == nil {
		clusters = []models.AlertCluster{}
	}
	c.JSON(http.StatusOK, clusters)
}

func GetClusterAlerts(c *gin.Context) {
	clusterID, _ := strconv.Atoi(c.Param("id"))
	alerts, err := services.GetClusterAlerts(clusterID, tenantIDFromContext(c))
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	if alerts == nil {
		alerts = []map[string]any{}
	}
	c.JSON(http.StatusOK, alerts)
}

func SuppressCluster(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	if err := services.SuppressCluster(id, tenantIDFromContext(c)); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "suppressed"})
}

func TriggerClustering(c *gin.Context) {
	go services.ClusterAlerts(tenantIDFromContext(c))
	c.JSON(http.StatusOK, gin.H{"message": "clustering started"})
}

// ── Framework Compliance ───────────────────────────────────────────────────

func GetFrameworkAssessment(c *gin.Context) {
	framework := c.Param("framework")
	tenantID := tenantIDFromContext(c)
	result, err := services.AssessFramework(framework, tenantID)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, result)
}

func GetAllFrameworkAssessments(c *gin.Context) {
	results := services.AssessAllFrameworks(tenantIDFromContext(c))
	c.JSON(http.StatusOK, results)
}
