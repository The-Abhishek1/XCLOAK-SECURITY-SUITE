package api

import (
	"fmt"

	"github.com/gin-gonic/gin"

	"xcloak-platform/database"
	"xcloak-platform/services"
)

type logNameCount struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

// GetLiveLogStats returns aggregate log statistics for the tenant.
// Used by the Live Logs page stats panel.
func GetLiveLogStats(c *gin.Context) {
	tenantID := tenantIDFromContext(c)

	var out struct {
		TotalLogs    int64          `json:"total_logs"`
		LastHourLogs int64          `json:"last_hour_logs"`
		TopSources   []logNameCount `json:"top_sources"`
		TopHosts     []logNameCount `json:"top_hosts"`
		TopUsers     []logNameCount `json:"top_users"`
	}

	database.DB.QueryRow(`
		SELECT COUNT(*) FROM endpoint_logs el
		JOIN agents a ON a.id = el.agent_id WHERE a.tenant_id = $1
	`, tenantID).Scan(&out.TotalLogs)

	database.DB.QueryRow(`
		SELECT COUNT(*) FROM endpoint_logs el
		JOIN agents a ON a.id = el.agent_id
		WHERE a.tenant_id = $1 AND el.collected_at >= NOW() - INTERVAL '1 hour'
	`, tenantID).Scan(&out.LastHourLogs)

	if rows, err := database.DB.Query(`
		SELECT COALESCE(log_source,'unknown'), COUNT(*) cnt FROM endpoint_logs el
		JOIN agents a ON a.id = el.agent_id WHERE a.tenant_id = $1
		GROUP BY log_source ORDER BY cnt DESC LIMIT 10
	`, tenantID); err == nil {
		defer rows.Close()
		for rows.Next() {
			var nc logNameCount
			if rows.Scan(&nc.Name, &nc.Count) == nil {
				out.TopSources = append(out.TopSources, nc)
			}
		}
	}

	if rows, err := database.DB.Query(`
		SELECT a.hostname, COUNT(*) cnt FROM endpoint_logs el
		JOIN agents a ON a.id = el.agent_id WHERE a.tenant_id = $1
		GROUP BY a.hostname ORDER BY cnt DESC LIMIT 10
	`, tenantID); err == nil {
		defer rows.Close()
		for rows.Next() {
			var nc logNameCount
			if rows.Scan(&nc.Name, &nc.Count) == nil {
				out.TopHosts = append(out.TopHosts, nc)
			}
		}
	}

	// Best-effort parsed_fields->>'user' extraction
	if rows, err := database.DB.Query(`
		SELECT COALESCE(parsed_fields->>'user', parsed_fields->>'target_user', parsed_fields->>'subject_user', 'unknown') as usr,
		       COUNT(*) cnt
		FROM endpoint_logs el
		JOIN agents a ON a.id = el.agent_id
		WHERE a.tenant_id = $1 AND parsed_fields IS NOT NULL
		GROUP BY usr ORDER BY cnt DESC LIMIT 10
	`, tenantID); err == nil {
		defer rows.Close()
		for rows.Next() {
			var nc logNameCount
			if rows.Scan(&nc.Name, &nc.Count) == nil && nc.Name != "unknown" {
				out.TopUsers = append(out.TopUsers, nc)
			}
		}
	}

	c.JSON(200, out)
}

// ExplainLogEntry calls the LLM to explain a single log line.
// POST /api/ai/explain-log
func ExplainLogEntry(c *gin.Context) {
	var body struct {
		Message string         `json:"message"`
		Source  string         `json:"source"`
		Fields  map[string]any `json:"fields"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	prompt := fmt.Sprintf(`You are a security analyst assistant. Analyze this log entry and respond with exactly three short bullet points:
• What happened (1 sentence)
• Why it may be suspicious (1 sentence)
• Recommended action (1 sentence)

Source: %s
Raw Message: %s
Parsed Fields: %v

Be direct and concise. No intro, no header, just the three bullet points.`,
		body.Source, body.Message, body.Fields)

	explanation, err := services.CallLLM(prompt)
	if err != nil {
		c.JSON(500, gin.H{"error": "AI service unavailable"})
		return
	}
	c.JSON(200, gin.H{"explanation": explanation})
}

// SummarizeLogs summarizes the last N log entries from the stream.
// POST /api/ai/summarize-logs
func SummarizeLogs(c *gin.Context) {
	var body struct {
		Messages []string `json:"messages"` // up to 100 log messages
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	if len(body.Messages) == 0 {
		c.JSON(400, gin.H{"error": "no messages provided"})
		return
	}
	if len(body.Messages) > 200 {
		body.Messages = body.Messages[:200]
	}

	sample := ""
	for i, m := range body.Messages {
		sample += fmt.Sprintf("[%d] %s\n", i+1, m)
	}

	prompt := fmt.Sprintf(`You are a SOC analyst. Summarize these %d log entries in 3-5 bullet points. Focus on:
- Key security events (auth failures, policy violations, suspicious processes)
- Patterns or anomalies
- Hosts and users involved
- Recommended analyst actions

Logs:
%s

Reply with concise bullet points only.`, len(body.Messages), sample)

	summary, err := services.CallLLM(prompt)
	if err != nil {
		c.JSON(500, gin.H{"error": "AI service unavailable"})
		return
	}
	c.JSON(200, gin.H{"summary": summary})
}
