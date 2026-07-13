package api

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"xcloak-platform/models"
	"xcloak-platform/repositories"
	"xcloak-platform/services"
)

// ReceiveFIMScan — POST /api/agents/fim
func ReceiveFIMScan(c *gin.Context) {

	var payload models.FIMScanPayload

	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	payload.AgentID = agentIDFromContext(c)

	if err := services.ProcessFIMScan(payload); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "FIM scan processed"})
}

// GetFIMBaseline — GET /api/agents/:id/fim/baseline
func GetFIMBaseline(c *gin.Context) {

	agentID, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid agent id"})
		return
	}
	if !agentOwnedBy404(c, c.Param("id")) {
		return
	}

	baseline, err := repositories.GetFIMBaseline(agentID)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	if baseline == nil {
		baseline = []models.FIMBaseline{}
	}

	c.JSON(200, baseline)
}

// AcceptFIMBaseline — POST /api/agents/:id/fim/baseline/accept
// Explicitly re-baselines one file to its most recently detected hash.
// Replaces the previous behavior of doing this automatically on every
// "modified" event, which meant a tampered file silently became the new
// "good" baseline with no analyst review.
func AcceptFIMBaseline(c *gin.Context) {

	agentID, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid agent id"})
		return
	}
	if !agentOwnedBy404(c, c.Param("id")) {
		return
	}

	var body struct {
		FilePath string `json:"file_path"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.FilePath == "" {
		c.JSON(400, gin.H{"error": "file_path is required"})
		return
	}

	if err := services.AcceptFIMBaseline(agentID, body.FilePath); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	username, _ := c.Get("username")
	services.LogEvent("FIM_BASELINE_ACCEPTED", fmt.Sprintf("Accepted FIM change for %s on agent %d", body.FilePath, agentID), fmt.Sprintf("%v", username))

	c.JSON(200, gin.H{"message": "baseline updated"})
}

// GetFIMAlerts — GET /api/agents/:id/fim/alerts
func GetFIMAlerts(c *gin.Context) {

	agentID := c.Param("id")
	if !agentOwnedBy404(c, agentID) {
		return
	}

	alerts, err := repositories.GetFIMAlerts(agentID)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	if alerts == nil {
		alerts = []models.FIMAlert{}
	}

	c.JSON(200, alerts)
}

// GetMITREMappings — GET /api/mitre/mappings
func GetMITREMappings(c *gin.Context) {

	mappings, err := services.GetMITREMappings()
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	if mappings == nil {
		mappings = []map[string]string{}
	}

	c.JSON(200, mappings)
}
