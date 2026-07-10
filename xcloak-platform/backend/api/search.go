package api

import (
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"xcloak-platform/database"
)

type SearchResult struct {
	Type      string    `json:"type"`      // alert, incident, agent, ioc, sigma_rule, yara_rule
	ID        int       `json:"id"`
	Title     string    `json:"title"`
	Subtitle  string    `json:"subtitle"`
	Severity  string    `json:"severity,omitempty"`
	Href      string    `json:"href"`       // frontend navigation path
	CreatedAt time.Time `json:"created_at"`
}

// GlobalSearch — GET /api/search?q=<term>&types=alert,incident,agent
func GlobalSearch(c *gin.Context) {
	q := strings.TrimSpace(c.Query("q"))
	if len(q) < 2 {
		c.JSON(400, gin.H{"error": "query must be at least 2 characters"})
		return
	}

	typesParam := c.Query("types") // comma-separated, empty = all
	wantedTypes := map[string]bool{}
	if typesParam != "" {
		for _, t := range strings.Split(typesParam, ",") {
			wantedTypes[strings.TrimSpace(t)] = true
		}
	}

	want := func(t string) bool {
		return len(wantedTypes) == 0 || wantedTypes[t]
	}

	pattern := "%" + strings.ToLower(q) + "%"
	tenantID := tenantIDFromContext(c)
	var results []SearchResult

	// ── Agents ─────────────────────────────────────────────────
	if want("agent") {
		rows, err := database.DB.Query(`
			SELECT id, hostname, ip_address, status, last_seen
			FROM agents
			WHERE tenant_id = $2 AND (LOWER(hostname) LIKE $1 OR ip_address LIKE $1)
			LIMIT 5
		`, pattern, tenantID)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var id int
				var hostname, ip, status string
				var lastSeen time.Time
				if rows.Scan(&id, &hostname, &ip, &status, &lastSeen) == nil {
					results = append(results, SearchResult{
						Type:      "agent",
						ID:        id,
						Title:     hostname,
						Subtitle:  ip + " · " + status,
						Href:      "/agents/" + itoa(id),
						CreatedAt: lastSeen,
					})
				}
			}
		}
	}

	// ── Alerts ─────────────────────────────────────────────────
	if want("alert") {
		rows, err := database.DB.Query(`
			SELECT id, rule_name, severity, log_message, created_at
			FROM alerts
			WHERE tenant_id = $2 AND (LOWER(rule_name) LIKE $1 OR LOWER(log_message) LIKE $1
			  OR LOWER(mitre_technique) LIKE $1)
			ORDER BY created_at DESC LIMIT 8
		`, pattern, tenantID)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var id int
				var ruleName, severity, logMsg string
				var createdAt time.Time
				if rows.Scan(&id, &ruleName, &severity, &logMsg, &createdAt) == nil {
					sub := logMsg
					if len(sub) > 80 {
						sub = sub[:80] + "…"
					}
					results = append(results, SearchResult{
						Type:      "alert",
						ID:        id,
						Title:     ruleName,
						Subtitle:  sub,
						Severity:  severity,
						Href:      "/alerts",
						CreatedAt: createdAt,
					})
				}
			}
		}
	}

	// ── Incidents ──────────────────────────────────────────────
	if want("incident") {
		rows, err := database.DB.Query(`
			SELECT id, title, severity, status, created_at
			FROM incidents
			WHERE tenant_id = $2 AND (LOWER(title) LIKE $1 OR LOWER(description) LIKE $1)
			ORDER BY created_at DESC LIMIT 5
		`, pattern, tenantID)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var id int
				var title, severity, status string
				var createdAt time.Time
				if rows.Scan(&id, &title, &severity, &status, &createdAt) == nil {
					results = append(results, SearchResult{
						Type:      "incident",
						ID:        id,
						Title:     title,
						Subtitle:  "Status: " + status,
						Severity:  severity,
						Href:      "/incidents",
						CreatedAt: createdAt,
					})
				}
			}
		}
	}

	// ── IOCs ───────────────────────────────────────────────────
	if want("ioc") {
		rows, err := database.DB.Query(`
			SELECT id, indicator, type, severity, created_at
			FROM iocs
			WHERE tenant_id = $2 AND (LOWER(indicator) LIKE $1 OR LOWER(description) LIKE $1)
			ORDER BY created_at DESC LIMIT 5
		`, pattern, tenantID)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var id int
				var indicator, iocType, severity string
				var createdAt time.Time
				if rows.Scan(&id, &indicator, &iocType, &severity, &createdAt) == nil {
					results = append(results, SearchResult{
						Type:      "ioc",
						ID:        id,
						Title:     indicator,
						Subtitle:  "Type: " + iocType,
						Severity:  severity,
						Href:      "/threat-intel",
						CreatedAt: createdAt,
					})
				}
			}
		}
	}

	// ── Sigma Rules ────────────────────────────────────────────
	if want("sigma_rule") {
		rows, err := database.DB.Query(`
			SELECT id, title, severity, created_at
			FROM sigma_rules
			WHERE tenant_id = $2 AND (LOWER(title) LIKE $1 OR LOWER(mitre_technique) LIKE $1)
			ORDER BY created_at DESC LIMIT 5
		`, pattern, tenantID)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var id int
				var title, severity string
				var createdAt time.Time
				if rows.Scan(&id, &title, &severity, &createdAt) == nil {
					results = append(results, SearchResult{
						Type:      "sigma_rule",
						ID:        id,
						Title:     title,
						Subtitle:  "Sigma Detection Rule",
						Severity:  severity,
						Href:      "/sigma-rules",
						CreatedAt: createdAt,
					})
				}
			}
		}
	}

	// ── YARA Rules ─────────────────────────────────────────────
	if want("yara_rule") {
		rows, err := database.DB.Query(`
			SELECT id, name, description, created_at
			FROM yara_rules
			WHERE tenant_id = $2 AND (LOWER(name) LIKE $1 OR LOWER(description) LIKE $1)
			ORDER BY created_at DESC LIMIT 5
		`, pattern, tenantID)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var id int
				var name, desc string
				var createdAt time.Time
				if rows.Scan(&id, &name, &desc, &createdAt) == nil {
					results = append(results, SearchResult{
						Type:      "yara_rule",
						ID:        id,
						Title:     name,
						Subtitle:  desc,
						Href:      "/yara-rules",
						CreatedAt: createdAt,
					})
				}
			}
		}
	}

	// ── Packages (endpoint) ────────────────────────────────────
	if want("package") {
		rows, err := database.DB.Query(`
			SELECT ep.id, ep.package_name, ep.version, a.hostname, ep.agent_id
			FROM endpoint_packages ep
			JOIN agents a ON a.id = ep.agent_id
			WHERE ep.tenant_id = $2 AND LOWER(ep.package_name) LIKE $1
			LIMIT 5
		`, pattern, tenantID)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var id, agentID int
				var pkgName, version, hostname string
				if rows.Scan(&id, &pkgName, &version, &hostname, &agentID) == nil {
					results = append(results, SearchResult{
						Type:     "package",
						ID:       id,
						Title:    pkgName + " " + version,
						Subtitle: "on " + hostname,
						Href:     "/agents/" + itoa(agentID),
					})
				}
			}
		}
	}

	if results == nil {
		results = []SearchResult{}
	}

	c.JSON(200, gin.H{
		"query":   q,
		"count":   len(results),
		"results": results,
	})
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	buf := make([]byte, 0, 10)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		buf = append([]byte{byte('0' + n%10)}, buf...)
		n /= 10
	}
	if neg {
		buf = append([]byte{'-'}, buf...)
	}
	return string(buf)
}
