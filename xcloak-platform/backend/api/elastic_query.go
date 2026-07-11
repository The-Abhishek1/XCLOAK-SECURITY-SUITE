package api

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	"xcloak-platform/services"
)

// ElasticQueryHandler — POST /api/elastic/query
// Body: { "index": "xcloak-logs-1", "dsl": { ...ES Query DSL... } }
// Injects a tenant_id filter before forwarding to ES.
func ElasticQueryHandler(c *gin.Context) {
	if !services.ElasticsearchEnabled() {
		c.JSON(503, gin.H{"error": "Elasticsearch is not configured on this server (set ELASTICSEARCH_URL)"})
		return
	}

	var body struct {
		Index string          `json:"index"`
		DSL   json.RawMessage `json:"dsl"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || len(body.DSL) == 0 {
		c.JSON(400, gin.H{"error": "body must contain 'index' (string) and 'dsl' (ES Query DSL object)"})
		return
	}
	if body.Index == "" {
		body.Index = indexForTenant(tenantIDFromContext(c))
	}

	// Reject admin or system indices that have no tenant data.
	if strings.HasPrefix(body.Index, ".") || body.Index == "_all" {
		c.JSON(400, gin.H{"error": "index name not allowed"})
		return
	}

	result, err := services.ExecuteRawQuery(tenantIDFromContext(c), body.Index, body.DSL)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, result)
}

// ElasticIndicesHandler — GET /api/elastic/indices
// Returns all visible ES indices with doc count, size, health.
func ElasticIndicesHandler(c *gin.Context) {
	if !services.ElasticsearchEnabled() {
		c.JSON(503, gin.H{"error": "Elasticsearch not configured"})
		return
	}
	meta, err := services.ListESIndexMeta()
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"indices": meta})
}

// ElasticMappingsHandler — GET /api/elastic/mappings/:index
// Returns the Elasticsearch field mappings for the given index.
func ElasticMappingsHandler(c *gin.Context) {
	if !services.ElasticsearchEnabled() {
		c.JSON(503, gin.H{"error": "Elasticsearch not configured"})
		return
	}
	index, _ := url.PathUnescape(c.Param("index"))
	if index == "" {
		c.JSON(400, gin.H{"error": "index name required"})
		return
	}
	mappings, err := services.GetESMappings(index)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.Data(200, "application/json", mappings)
}

// ElasticHealthHandler — GET /api/elastic/health
// Returns ES cluster health status.
func ElasticHealthHandler(c *gin.Context) {
	if !services.ElasticsearchEnabled() {
		c.JSON(200, gin.H{"status": "not_configured", "enabled": false})
		return
	}
	health, err := services.ESClusterHealth()
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.Data(200, "application/json", health)
}

func indexForTenant(tenantID int) string {
	if tenantID <= 0 {
		return "xcloak-logs-*"
	}
	return fmt.Sprintf("xcloak-logs-%d", tenantID)
}
