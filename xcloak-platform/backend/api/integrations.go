package api

import (
	"crypto/rand"
	"encoding/hex"

	"github.com/gin-gonic/gin"

	"xcloak-platform/database"
	"xcloak-platform/services"
)

// GetIntegrations — GET /api/integrations
func GetIntegrations(c *gin.Context) {
	result, err := services.GetIntegrations(tenantIDFromContext(c))
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	if result == nil {
		result = []map[string]any{}
	}

	// OIDC's client_secret is more dangerous than this endpoint's other
	// already-unredacted secrets (webhook URLs, Slack URLs) — combined with
	// the issuer/client_id (also in this same response) it lets an attacker
	// impersonate the relying-party application to the IdP. Redact it here
	// rather than leave a fresh, more severe leak on top of the existing one.
	for _, row := range result {
		if row["name"] != "oidc" {
			continue
		}
		if cfg, ok := row["config"].(map[string]any); ok {
			if _, has := cfg["client_secret"]; has {
				cfg["client_secret"] = "••••••••"
			}
		}
	}

	c.JSON(200, result)
}

// SaveIntegration — PUT /api/integrations/:name
func SaveIntegration(c *gin.Context) {
	name := c.Param("name")
	var body struct {
		Enabled bool           `json:"enabled"`
		Config  map[string]any `json:"config"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	// GetIntegrations redacts oidc's client_secret, so the settings UI can
	// only ever echo back the placeholder, never the real value — if the
	// admin saves without re-entering it, keep the previously stored secret
	// instead of overwriting it with an empty/redacted string.
	if name == "oidc" {
		if secret, _ := body.Config["client_secret"].(string); secret == "" || secret == "••••••••" {
			if existing, err := services.GetIntegrations(tenantIDFromContext(c)); err == nil {
				for _, row := range existing {
					if row["name"] != "oidc" {
						continue
					}
					if cfg, ok := row["config"].(map[string]any); ok {
						body.Config["client_secret"] = cfg["client_secret"]
					}
				}
			}
		}
	}

	username, _ := c.Get("username")
	if err := services.SaveIntegration(name, body.Enabled, body.Config, username.(string), tenantIDFromContext(c)); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"message": "saved"})
}

// TestIntegration — POST /api/integrations/:name/test
func TestIntegration(c *gin.Context) {
	name := c.Param("name")
	go services.FireTestWebhook(name, tenantIDFromContext(c))
	c.JSON(200, gin.H{"message": "test event fired for " + name})
}

// GetWebhookDeliveries — GET /api/integrations/deliveries
func GetWebhookDeliveries(c *gin.Context) {
	result, err := services.GetWebhookDeliveries(tenantIDFromContext(c))
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	if result == nil {
		result = []map[string]any{}
	}
	c.JSON(200, result)
}

// GenerateInstallToken — POST /api/integrations/install-tokens
func GenerateInstallToken(c *gin.Context) {
	var body struct {
		Label string `json:"label"`
	}
	c.ShouldBindJSON(&body)

	token := randomHex(32)
	username, _ := c.Get("username")
	tenantID := tenantIDFromContext(c)

	_, err := database.DB.Exec(`
		INSERT INTO agent_install_tokens (token, label, created_by, tenant_id)
		VALUES ($1,$2,$3,$4)
	`, token, body.Label, username.(string), tenantID)

	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, gin.H{
		"token":      token,
		"expires_in": "24 hours",
		"label":      body.Label,
	})
}

// GetInstallTokens — GET /api/integrations/install-tokens
func GetInstallTokens(c *gin.Context) {
	rows, err := database.DB.Query(`
		SELECT id, label, used, created_by, expires_at, created_at
		FROM agent_install_tokens WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT 20
	`, tenantIDFromContext(c))
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	tokens := []map[string]any{}
	for rows.Next() {
		var id int
		var label, createdBy, expiresAt, createdAt string
		var used bool
		if err := rows.Scan(&id, &label, &used, &createdBy, &expiresAt, &createdAt); err == nil {
			tokens = append(tokens, map[string]any{
				"id": id, "label": label, "used": used,
				"created_by": createdBy, "expires_at": expiresAt, "created_at": createdAt,
			})
		}
	}
	if tokens == nil {
		tokens = []map[string]any{}
	}
	c.JSON(200, tokens)
}

func randomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}
