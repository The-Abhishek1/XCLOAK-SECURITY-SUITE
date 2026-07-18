package api

import (
	"github.com/gin-gonic/gin"
	"xcloak-platform/database"
	"xcloak-platform/models"
	"xcloak-platform/repositories"
	"xcloak-platform/services"
)

// GetTenantSMTPConfig — GET /api/settings/smtp
func GetTenantSMTPConfig(c *gin.Context) {
	cfg, err := repositories.GetTenantSMTPConfig(tenantIDFromContext(c))
	if err != nil {
		// No row yet — return empty defaults so the form renders cleanly.
		c.JSON(200, models.TenantSMTPConfig{TenantID: tenantIDFromContext(c), Port: "587", TLS: true})
		return
	}
	// Never return the password to the client.
	cfg.Password = ""
	c.JSON(200, cfg)
}

// SaveTenantSMTPConfig — PUT /api/settings/smtp
func SaveTenantSMTPConfig(c *gin.Context) {
	var body models.TenantSMTPConfig
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	body.TenantID = tenantIDFromContext(c)
	// If password is blank, preserve the existing one.
	if body.Password == "" {
		if existing, err := repositories.GetTenantSMTPConfig(body.TenantID); err == nil {
			body.Password = existing.Password
		}
	}
	if err := repositories.UpsertTenantSMTPConfig(body); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"message": "SMTP configuration saved"})
}

// GetEmailRules — GET /api/notifications/email
func GetEmailRules(c *gin.Context) {
	rows, err := database.DB.Query(`
		SELECT id, name, severity, recipient, enabled, created_at
		FROM email_alert_rules WHERE tenant_id=$1 ORDER BY created_at DESC
	`, tenantIDFromContext(c))
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
	rules := []Rule{}
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
		INSERT INTO email_alert_rules (name, severity, recipient, tenant_id)
		VALUES ($1,$2,$3,$4) RETURNING id
	`, body.Name, body.Severity, body.Recipient, tenantIDFromContext(c)).Scan(&id)
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
	res, err := database.DB.Exec(`UPDATE email_alert_rules SET enabled=$1 WHERE id=$2 AND tenant_id=$3`, body.Enabled, id, tenantIDFromContext(c))
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		c.JSON(404, gin.H{"error": "email rule not found"})
		return
	}
	c.JSON(200, gin.H{"message": "updated"})
}

// DeleteEmailRule — DELETE /api/notifications/email/:id
func DeleteEmailRule(c *gin.Context) {
	res, err := database.DB.Exec(`DELETE FROM email_alert_rules WHERE id=$1 AND tenant_id=$2`, c.Param("id"), tenantIDFromContext(c))
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		c.JSON(404, gin.H{"error": "email rule not found"})
		return
	}
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
	if err := services.SendTestEmail(body.Recipient, tenantIDFromContext(c)); err != nil {
		c.JSON(502, gin.H{"error": "failed to send test email: " + err.Error()})
		return
	}
	c.JSON(200, gin.H{"message": "test email sent to " + body.Recipient})
}
