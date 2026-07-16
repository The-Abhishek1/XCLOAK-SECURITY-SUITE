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

// ElasticExplainHandler — POST /api/elastic/explain
// Body: { "index": "...", "dsl": { ...ES Query DSL... } }
// Returns a structured analysis of the DSL: parsed_query, execution_plan,
// scoring, analyzer, optimizations[], cost_estimate.
func ElasticExplainHandler(c *gin.Context) {
	var body struct {
		Index string          `json:"index"`
		DSL   json.RawMessage `json:"dsl"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || len(body.DSL) == 0 {
		c.JSON(400, gin.H{"error": "body must contain 'dsl' (ES Query DSL object)"})
		return
	}

	var dslObj map[string]interface{}
	if err := json.Unmarshal(body.DSL, &dslObj); err != nil {
		c.JSON(400, gin.H{"error": "dsl must be a valid JSON object"})
		return
	}

	prompt := fmt.Sprintf(`You are an Elasticsearch expert. Analyze this ES Query DSL and return a JSON object with exactly these keys:

{
  "parsed_query":    <echo back the query clause as an object, or null>,
  "execution_plan":  <string: how ES would execute this — which phases, filters before scorers, etc.>,
  "scoring":         <string: how documents are scored — BM25, constant_score, etc.>,
  "analyzer":        <string: which analyzer applies to text fields, if any>,
  "optimizations":   <array of strings: 2-4 concrete optimizations the analyst could apply>,
  "cost_estimate":   { "docs_scanned": <string>, "shards_queried": <string>, "estimated_ms": <string> }
}

DSL: %s

Return ONLY the raw JSON object. No markdown, no explanation text outside the JSON.`, string(body.DSL))

	raw, err := services.CallLLM(prompt)
	if err != nil {
		// Static fallback
		c.JSON(200, gin.H{
			"parsed_query":    dslObj["query"],
			"execution_plan":  "Elasticsearch will evaluate the query clause first, then apply any aggregations. Filter context clauses skip scoring and use the bitset cache.",
			"scoring":         "BM25 (default). Use constant_score with filter for non-relevance queries to skip scoring overhead.",
			"analyzer":        "standard (default). Text fields use standard analyzer unless the mapping specifies otherwise.",
			"optimizations":   []string{"Wrap non-scoring clauses in filter context", "Add date range filter to limit scanned docs", "Use keyword fields for exact match instead of text", "Reduce size if aggregations are the goal"},
			"cost_estimate":   gin.H{"docs_scanned": "unknown", "shards_queried": "1+", "estimated_ms": "unknown"},
		})
		return
	}

	// Strip markdown fences if LLM wrapped the JSON
	raw = strings.TrimSpace(raw)
	raw = strings.TrimPrefix(raw, "```json")
	raw = strings.TrimPrefix(raw, "```")
	raw = strings.TrimSuffix(raw, "```")
	raw = strings.TrimSpace(raw)

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		// LLM returned non-JSON — wrap the text into execution_plan
		c.JSON(200, gin.H{
			"parsed_query":   dslObj["query"],
			"execution_plan": raw,
			"scoring":        "",
			"analyzer":       "",
			"optimizations":  []string{},
			"cost_estimate":  nil,
		})
		return
	}
	c.JSON(200, result)
}

// ElasticAIQueryHandler — POST /api/ai/es-query
// Body: { "prompt": "natural language description" }
// Returns: { "dsl": {...ES DSL...}, "explanation": "..." }
func ElasticAIQueryHandler(c *gin.Context) {
	var body struct {
		Prompt string `json:"prompt"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || strings.TrimSpace(body.Prompt) == "" {
		c.JSON(400, gin.H{"error": "prompt required"})
		return
	}

	genPrompt := fmt.Sprintf(`You are an Elasticsearch DSL expert for a SIEM platform. Convert the following natural language request into a valid Elasticsearch Query DSL JSON object.

XCloak log index fields:
- log_message (text): raw log line
- log_source (keyword): e.g. "ssh", "nginx", "syslog", "winlogbeat"
- collected_at (date): ingest timestamp
- agent_id (long): numeric agent ID
- parsed_fields (object with keyword sub-fields): user, target_user, src_ip, dst_ip, src_port, dst_port, hostname, process, pid, event_id, auth_result, bytes, method, url, domain, logon_type

Request: %s

Return a JSON object with two top-level keys:
{
  "dsl": { ...Elasticsearch Query DSL... },
  "explanation": "one sentence describing what this query finds"
}

The dsl should be a complete, runnable ES DSL body (query, aggs, sort, size as needed).
Return ONLY the raw JSON. No markdown fences. No text outside the JSON.`, body.Prompt)

	raw, err := services.CallLLM(genPrompt)
	if err != nil {
		c.JSON(500, gin.H{"error": "AI service unavailable"})
		return
	}

	raw = strings.TrimSpace(raw)
	raw = strings.TrimPrefix(raw, "```json")
	raw = strings.TrimPrefix(raw, "```")
	raw = strings.TrimSuffix(raw, "```")
	raw = strings.TrimSpace(raw)

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		// LLM returned a plain DSL without the wrapper — treat the whole thing as DSL
		var dslOnly interface{}
		if json.Unmarshal([]byte(raw), &dslOnly) == nil {
			c.JSON(200, gin.H{"dsl": dslOnly, "explanation": ""})
			return
		}
		c.JSON(500, gin.H{"error": "AI returned invalid JSON"})
		return
	}
	c.JSON(200, result)
}
