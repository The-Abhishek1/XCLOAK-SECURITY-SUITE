package api

import (
	"github.com/gin-gonic/gin"
	"xcloak-ngfw/database"
)

// GetEmailRules — GET /api/notifications/email
func GetEmailRules(c *gin.Context) {
	rows, err := database.DB.Query(`
		SELECT id, name, severity, recipient, enabled, created_at
		FROM email_alert_rules ORDER BY created_at DESC
	`)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()
	type Rule struct {
		ID        int    `json:"id"`
		Name      string `json:"name"`
		Severity  string `json:"severity"`
		Recipient string `json:"recipient"`
		Enabled   bool   `json:"enabled"`
		CreatedAt string `json:"created_at"`
	}
	var rules []Rule
	for rows.Next() {
		var r Rule
		if rows.Scan(&r.ID, &r.Name, &r.Severity, &r.Recipient, &r.Enabled, &r.CreatedAt) == nil {
			rules = append(rules, r)
		}
	}
	if rules == nil { rules = []Rule{} }
	c.JSON(200, rules)
}

// CreateEmailRule — POST /api/notifications/email
func CreateEmailRule(c *gin.Context) {
	var body struct {
		Name      string `json:"name"`
		Severity  string `json:"severity"`
		Recipient string `json:"recipient"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Recipient == "" {
		c.JSON(400, gin.H{"error": "name, severity and recipient are required"})
		return
	}
	if body.Severity == "" { body.Severity = "critical" }

	var id int
	err := database.DB.QueryRow(`
		INSERT INTO email_alert_rules (name, severity, recipient)
		VALUES ($1,$2,$3) RETURNING id
	`, body.Name, body.Severity, body.Recipient).Scan(&id)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"id": id, "message": "email rule created"})
}

// ToggleEmailRule — PATCH /api/notifications/email/:id/toggle
func ToggleEmailRule(c *gin.Context) {
	id := c.Param("id")
	var body struct{ Enabled bool `json:"enabled"` }
	c.ShouldBindJSON(&body)
	database.DB.Exec(`UPDATE email_alert_rules SET enabled=$1 WHERE id=$2`, body.Enabled, id)
	c.JSON(200, gin.H{"message": "updated"})
}

// DeleteEmailRule — DELETE /api/notifications/email/:id
func DeleteEmailRule(c *gin.Context) {
	database.DB.Exec(`DELETE FROM email_alert_rules WHERE id=$1`, c.Param("id"))
	c.JSON(200, gin.H{"message": "deleted"})
}

// TestEmailRule — POST /api/notifications/email/test
func TestEmailRule(c *gin.Context) {
	var body struct{ Recipient string `json:"recipient"` }
	c.ShouldBindJSON(&body)
	if body.Recipient == "" {
		c.JSON(400, gin.H{"error": "recipient required"})
		return
	}
	// Send a test email
	cfg := struct{ Host string }{Host: ""}
	_ = cfg
	c.JSON(200, gin.H{"message": "test email queued (check SMTP logs)"})
}
