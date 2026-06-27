package api

import (
	"fmt"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"xcloak-ngfw/services"
)

// SearchLogs — GET /api/logs/search
// Query params:
//   q        — KQL-lite query string  (field:value, "phrase", bare word)
//   agent_id — filter by agent
//   from     — ISO-8601 start
//   to       — ISO-8601 end
//   severity — exact severity filter
//   source   — log_source ILIKE filter
//   page     — 0-based page number (default 0)
//   limit    — page size (default 200, max 1000)
func SearchLogsHandler(c *gin.Context) {
	p := buildSearchParams(c)
	result, err := services.SearchLogs(p)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, result)
}

// ExportLogs — GET /api/logs/export?format=csv|json&<same filters>
func ExportLogs(c *gin.Context) {
	p := buildSearchParams(c)
	format := c.DefaultQuery("format", "csv")

	switch format {
	case "json":
		data, err := services.ExportLogsJSON(p)
		if err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
		c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="logs-%s.json"`, time.Now().Format("20060102-150405")))
		c.Data(200, "application/json", data)

	default:
		data, err := services.ExportLogsCSV(p)
		if err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
		c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="logs-%s.csv"`, time.Now().Format("20060102-150405")))
		c.Data(200, "text/csv", data)
	}
}

// GetLogStats — GET /api/logs/stats
func GetLogStats(c *gin.Context) {
	stats, err := services.GetLogStats(tenantIDFromContext(c))
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, stats)
}

// GetSavedLogSearches — GET /api/logs/searches
func GetSavedLogSearches(c *gin.Context) {
	searches, err := services.GetSavedLogSearches(tenantIDFromContext(c))
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	if searches == nil {
		searches = []services.SavedLogSearch{}
	}
	c.JSON(200, searches)
}

// SaveLogSearch — POST /api/logs/searches
func SaveLogSearch(c *gin.Context) {
	var body services.SavedLogSearch
	if err := c.ShouldBindJSON(&body); err != nil || body.Name == "" {
		c.JSON(400, gin.H{"error": "name is required"})
		return
	}
	username, _ := c.Get("username")
	body.CreatedBy = fmt.Sprintf("%v", username)

	saved, err := services.SaveLogSearch(body, tenantIDFromContext(c))
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(201, saved)
}

// DeleteSavedLogSearch — DELETE /api/logs/searches/:id
func DeleteSavedLogSearch(c *gin.Context) {
	if err := services.DeleteSavedLogSearch(c.Param("id"), tenantIDFromContext(c)); err != nil {
		c.JSON(404, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"message": "deleted"})
}

// RunSavedLogSearch — POST /api/logs/searches/:id/run
func RunSavedLogSearch(c *gin.Context) {
	id := c.Param("id")
	tenantID := tenantIDFromContext(c)

	// Load the saved search to rebuild params.
	searches, err := services.GetSavedLogSearches(tenantID)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	var found *services.SavedLogSearch
	for _, s := range searches {
		if strconv.Itoa(s.ID) == id {
			found = &s
			break
		}
	}
	if found == nil {
		c.JSON(404, gin.H{"error": "search not found"})
		return
	}

	p := expandTimeRange(found.TimeRange, tenantID)
	p.Query = found.Query

	result, err := services.SearchLogs(p)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	services.IncrementSearchRunCount(found.ID)
	c.JSON(200, result)
}

// GetRetentionPolicy — GET /api/logs/retention
func GetRetentionPolicy(c *gin.Context) {
	days := services.GetRetentionDays(tenantIDFromContext(c))
	c.JSON(200, gin.H{"retention_days": days})
}

// SetRetentionPolicy — PUT /api/logs/retention
func SetRetentionPolicy(c *gin.Context) {
	var body struct {
		RetentionDays int `json:"retention_days"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(400, gin.H{"error": "invalid body"})
		return
	}
	if err := services.SetRetentionDays(tenantIDFromContext(c), body.RetentionDays); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"retention_days": body.RetentionDays})
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

func buildSearchParams(c *gin.Context) services.LogSearchParams {
	p := services.LogSearchParams{
		TenantID: tenantIDFromContext(c),
	}

	p.Query = c.Query("q")
	p.Severity = c.Query("severity")
	p.LogSource = c.Query("source")

	if agentID, err := strconv.Atoi(c.Query("agent_id")); err == nil {
		p.AgentID = agentID
	}
	if limit, err := strconv.Atoi(c.Query("limit")); err == nil {
		p.Limit = limit
	}
	if page, err := strconv.Atoi(c.Query("page")); err == nil {
		p.Page = page
	}

	if from := c.Query("from"); from != "" {
		if t, err := time.Parse(time.RFC3339, from); err == nil {
			p.From = t
		}
	}
	if to := c.Query("to"); to != "" {
		if t, err := time.Parse(time.RFC3339, to); err == nil {
			p.To = t
		}
	}

	// Convenience: ?range=1h|24h|7d|30d sets From automatically if from/to absent.
	if p.From.IsZero() && p.To.IsZero() {
		if r := c.Query("range"); r != "" {
			p = expandTimeRange(r, p.TenantID)
			// Re-apply overrides from other params.
			p.Query = c.Query("q")
			p.Severity = c.Query("severity")
			p.LogSource = c.Query("source")
			if agentID, err := strconv.Atoi(c.Query("agent_id")); err == nil {
				p.AgentID = agentID
			}
		}
	}

	return p
}

func expandTimeRange(r string, tenantID int) services.LogSearchParams {
	p := services.LogSearchParams{TenantID: tenantID}
	now := time.Now()
	switch r {
	case "1h":
		p.From = now.Add(-time.Hour)
	case "6h":
		p.From = now.Add(-6 * time.Hour)
	case "24h":
		p.From = now.Add(-24 * time.Hour)
	case "7d":
		p.From = now.Add(-7 * 24 * time.Hour)
	case "30d":
		p.From = now.Add(-30 * 24 * time.Hour)
	}
	p.To = now
	return p
}
