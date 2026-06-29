package api

import (
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"xcloak-ngfw/database"
)

// GetJA3Fingerprints — GET /api/ja3/fingerprints
// Returns platform-wide + tenant-specific JA3 entries.
func GetJA3Fingerprints(c *gin.Context) {
	tenantID := tenantIDFromContext(c)
	rows, err := database.DB.Query(`
		SELECT id, hash, threat_name, severity, source,
		       COALESCE(description,''), enabled,
		       tenant_id IS NULL AS is_platform, created_at
		FROM ja3_fingerprints
		WHERE tenant_id = $1 OR tenant_id IS NULL
		ORDER BY tenant_id NULLS FIRST, threat_name
	`, tenantID)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	var out []map[string]any
	for rows.Next() {
		var id int
		var hash, threatName, severity, source, description, createdAt string
		var enabled, isPlatform bool
		if err := rows.Scan(&id, &hash, &threatName, &severity, &source,
			&description, &enabled, &isPlatform, &createdAt); err == nil {
			out = append(out, map[string]any{
				"id":          id,
				"hash":        hash,
				"threat_name": threatName,
				"severity":    severity,
				"source":      source,
				"description": description,
				"enabled":     enabled,
				"is_platform": isPlatform,
				"created_at":  createdAt,
			})
		}
	}
	if out == nil {
		out = []map[string]any{}
	}
	c.JSON(200, out)
}

// CreateJA3Fingerprint — POST /api/ja3/fingerprints
func CreateJA3Fingerprint(c *gin.Context) {
	var body struct {
		Hash        string `json:"hash"        binding:"required"`
		ThreatName  string `json:"threat_name" binding:"required"`
		Severity    string `json:"severity"`
		Source      string `json:"source"`
		Description string `json:"description"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	if len(body.Hash) != 32 {
		c.JSON(400, gin.H{"error": "hash must be a 32-character MD5 hex string"})
		return
	}
	if body.Severity == "" { body.Severity = "high" }
	if body.Source == ""   { body.Source = "manual" }

	tenantID := tenantIDFromContext(c)
	var id int
	err := database.DB.QueryRow(`
		INSERT INTO ja3_fingerprints
		  (hash, threat_name, severity, source, description, tenant_id)
		VALUES ($1,$2,$3,$4,$5,$6)
		ON CONFLICT (hash, COALESCE(tenant_id, 0)) DO UPDATE SET
		  threat_name = EXCLUDED.threat_name,
		  severity    = EXCLUDED.severity,
		  source      = EXCLUDED.source,
		  description = EXCLUDED.description,
		  enabled     = TRUE
		RETURNING id
	`, body.Hash, body.ThreatName, body.Severity, body.Source, body.Description, tenantID).Scan(&id)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(201, gin.H{"id": id})
}

// DeleteJA3Fingerprint — DELETE /api/ja3/fingerprints/:id
// Only allows deleting tenant-owned rows, not platform-wide ones.
func DeleteJA3Fingerprint(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid id"})
		return
	}
	tenantID := tenantIDFromContext(c)
	res, err := database.DB.Exec(`
		DELETE FROM ja3_fingerprints WHERE id = $1 AND tenant_id = $2
	`, id, tenantID)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		c.JSON(404, gin.H{"error": "not found or platform-managed (cannot delete platform entries)"})
		return
	}
	c.JSON(200, gin.H{"message": "deleted"})
}

// GetIdentityCache — GET /api/identity
// Returns cached AD/LDAP identity records for the tenant.
func GetIdentityCache(c *gin.Context) {
	tenantID := tenantIDFromContext(c)
	rows, err := database.DB.Query(`
		SELECT username, COALESCE(display_name,''), COALESCE(email,''),
		       COALESCE(department,''), COALESCE(title,''), COALESCE(manager,''),
		       COALESCE(groups::text, '{}'), account_status, cached_at
		FROM identity_cache WHERE tenant_id = $1
		ORDER BY display_name NULLS LAST
		LIMIT 500
	`, tenantID)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	var out []map[string]any
	for rows.Next() {
		var username, displayName, email, dept, title, manager, groupsRaw, status, cachedAt string
		if err := rows.Scan(&username, &displayName, &email, &dept,
			&title, &manager, &groupsRaw, &status, &cachedAt); err == nil {
			out = append(out, map[string]any{
				"username":       username,
				"display_name":   displayName,
				"email":          email,
				"department":     dept,
				"title":          title,
				"manager":        manager,
				"groups":         parsePGArray(groupsRaw),
				"account_status": status,
				"cached_at":      cachedAt,
			})
		}
	}
	if out == nil {
		out = []map[string]any{}
	}
	c.JSON(200, out)
}

// parsePGArray converts a PostgreSQL text[] literal "{a,b,c}" to []string.
func parsePGArray(s string) []string {
	s = strings.TrimPrefix(s, "{")
	s = strings.TrimSuffix(s, "}")
	if s == "" {
		return []string{}
	}
	var parts []string
	var cur strings.Builder
	inQ := false
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case ch == '"':
			inQ = !inQ
		case ch == ',' && !inQ:
			parts = append(parts, cur.String())
			cur.Reset()
		default:
			cur.WriteByte(ch)
		}
	}
	parts = append(parts, cur.String())
	return parts
}
