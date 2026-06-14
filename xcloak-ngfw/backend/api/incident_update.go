package api

import (
	"strconv"

	"github.com/gin-gonic/gin"

	"xcloak-ngfw/services"
)

// UpdateIncidentStatus — PUT /api/incidents/:id/status
// Body: { "status": "open" | "investigating" | "resolved" | "closed" }
func UpdateIncidentStatus(c *gin.Context) {

	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid incident id"})
		return
	}

	var body struct {
		Status string `json:"status"`
	}

	if err := c.ShouldBindJSON(&body); err != nil || body.Status == "" {
		c.JSON(400, gin.H{"error": "status is required"})
		return
	}

	valid := map[string]bool{"open": true, "investigating": true, "resolved": true, "closed": true}
	if !valid[body.Status] {
		c.JSON(400, gin.H{"error": "status must be: open, investigating, resolved, or closed"})
		return
	}

	if err := services.UpdateIncidentStatus(id, body.Status); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	// Record MTTR when incident is resolved or closed.
	if body.Status == "resolved" || body.Status == "closed" {
		services.RecordMTTR(id)
	}

	username, _ := c.Get("username")
	services.LogEvent("UPDATE_INCIDENT_STATUS",
		"incident "+strconv.Itoa(id)+" → "+body.Status,
		username.(string),
	)

	c.JSON(200, gin.H{"message": "Status updated", "status": body.Status})
}

// AddIncidentNote — POST /api/incidents/:id/notes
// Body: { "note": "..." }
func AddIncidentNote(c *gin.Context) {

	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid incident id"})
		return
	}

	var body struct {
		Note string `json:"note"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Note == "" {
		c.JSON(400, gin.H{"error": "note is required"})
		return
	}

	username, _ := c.Get("username")
	user := "admin"
	if username != nil {
		user = username.(string)
	}

	if err := services.AddIncidentEvent(id, "note", body.Note, user); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, gin.H{"message": "Note added"})
}
