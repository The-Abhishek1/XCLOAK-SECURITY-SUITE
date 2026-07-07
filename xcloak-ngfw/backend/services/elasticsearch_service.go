package services

// Elasticsearch / OpenSearch integration for log search.
//
// When ELASTICSEARCH_URL is set in the environment, SearchLogs routes queries
// to ES instead of Postgres. The Postgres path remains the default so the
// feature degrades gracefully when ES is unavailable.
//
// Index layout: one index per tenant — "xcloak-logs-<tenantID>". This keeps
// tenant isolation at the index level (ILM policies, shard routing) rather
// than relying solely on a tenant_id field filter. Index template is
// registered on first use (idempotent PUT /_index_template/xcloak-logs).
//
// Log ingest: SaveLogs() calls IndexLogsToES() in a non-blocking goroutine;
// Postgres remains the source of truth. ES is read-side only.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
)

var esClient *elasticsearchClient

type elasticsearchClient struct {
	baseURL  string
	username string
	password string
	http     *http.Client
}

// InitElasticsearch initialises the ES client from environment variables.
// Call once from main.go after env is loaded. No-ops when ELASTICSEARCH_URL
// is unset.
func InitElasticsearch() {
	url := os.Getenv("ELASTICSEARCH_URL")
	if url == "" {
		return
	}
	esClient = &elasticsearchClient{
		baseURL:  strings.TrimRight(url, "/"),
		username: os.Getenv("ELASTICSEARCH_USERNAME"),
		password: os.Getenv("ELASTICSEARCH_PASSWORD"),
		http:     &http.Client{Timeout: 10 * time.Second},
	}
	if err := esClient.ensureIndexTemplate(); err != nil {
		slog.Warn("elasticsearch: index template setup failed", "err", err)
	}
	slog.Info("elasticsearch: connected", "url", url)
}

// ElasticsearchEnabled reports whether the ES integration is active.
func ElasticsearchEnabled() bool { return esClient != nil }

// ── Index template ────────────────────────────────────────────────────────────

func (c *elasticsearchClient) ensureIndexTemplate() error {
	tmpl := map[string]any{
		"index_patterns": []string{"xcloak-logs-*"},
		"template": map[string]any{
			"settings": map[string]any{
				"number_of_shards":   1,
				"number_of_replicas": 1,
				"refresh_interval":   "5s",
			},
			"mappings": map[string]any{
				"properties": map[string]any{
					"agent_id":     map[string]any{"type": "integer"},
					"tenant_id":    map[string]any{"type": "integer"},
					"log_source":   map[string]any{"type": "keyword"},
					"log_message":  map[string]any{"type": "text", "analyzer": "standard"},
					"collected_at": map[string]any{"type": "date"},
					"parsed_fields": map[string]any{
						"type":    "object",
						"dynamic": true,
					},
				},
			},
		},
	}
	return c.put("/_index_template/xcloak-logs", tmpl)
}

// ── Document indexing ─────────────────────────────────────────────────────────

// IndexLogsToES bulk-indexes a slice of logs into the tenant's ES index.
// Called from repositories.SaveLogs() in a goroutine — never blocks the
// Postgres write path.
func IndexLogsToES(logs []models.Log) {
	if esClient == nil || len(logs) == 0 {
		return
	}

	// Group by tenant to send one bulk request per index.
	byTenant := make(map[int][]models.Log)
	for _, l := range logs {
		byTenant[l.TenantID] = append(byTenant[l.TenantID], l)
	}
	for tenantID, tLogs := range byTenant {
		if err := esClient.bulkIndex(tenantID, tLogs); err != nil {
			slog.Warn("elasticsearch: bulk index failed", "tenant_id", tenantID, "err", err)
		}
	}
}

func (c *elasticsearchClient) bulkIndex(tenantID int, logs []models.Log) error {
	index := fmt.Sprintf("xcloak-logs-%d", tenantID)
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)

	for _, l := range logs {
		_ = enc.Encode(map[string]any{"index": map[string]any{"_index": index}})
		_ = enc.Encode(map[string]any{
			"agent_id":     l.AgentID,
			"tenant_id":    l.TenantID,
			"log_source":   l.LogSource,
			"log_message":  l.LogMessage,
			"collected_at": l.CollectedAt.UTC().Format(time.RFC3339),
			"parsed_fields": json.RawMessage(func() []byte {
				if l.ParsedFields == "" {
					return []byte("{}")
				}
				return []byte(l.ParsedFields)
			}()),
		})
	}

	resp, err := c.doRequest("POST", "/_bulk", &buf)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("bulk index status %d: %s", resp.StatusCode, body)
	}
	return nil
}

// ── Search ────────────────────────────────────────────────────────────────────

// SearchLogsES executes a LogSearchParams query against Elasticsearch.
// Returns the same LogSearchResult shape as the Postgres path.
func SearchLogsES(p LogSearchParams) (*LogSearchResult, error) {
	if esClient == nil {
		return nil, fmt.Errorf("elasticsearch not configured")
	}

	index := fmt.Sprintf("xcloak-logs-%d", p.TenantID)

	// Build ES query from LogSearchParams.
	must := []map[string]any{}
	filter := []map[string]any{}

	if p.AgentID > 0 {
		filter = append(filter, map[string]any{"term": map[string]any{"agent_id": p.AgentID}})
	}
	if !p.From.IsZero() || !p.To.IsZero() {
		rang := map[string]any{"collected_at": map[string]any{}}
		if !p.From.IsZero() {
			rang["collected_at"].(map[string]any)["gte"] = p.From.UTC().Format(time.RFC3339)
		}
		if !p.To.IsZero() {
			rang["collected_at"].(map[string]any)["lte"] = p.To.UTC().Format(time.RFC3339)
		}
		filter = append(filter, map[string]any{"range": rang})
	}
	if p.LogSource != "" {
		filter = append(filter, map[string]any{"term": map[string]any{"log_source": p.LogSource}})
	}
	if p.Query != "" {
		must = append(must, map[string]any{
			"query_string": map[string]any{
				"query":            p.Query,
				"default_field":    "log_message",
				"analyze_wildcard": true,
			},
		})
	}

	esQuery := map[string]any{
		"query": map[string]any{
			"bool": map[string]any{"must": must, "filter": filter},
		},
		"sort":  []map[string]any{{"collected_at": map[string]any{"order": "desc"}}},
		"size":  p.Limit,
		"from":  p.Page * p.Limit,
		"track_total_hits": true,
	}

	var buf bytes.Buffer
	json.NewEncoder(&buf).Encode(esQuery)

	resp, err := esClient.doRequest("POST", "/"+index+"/_search", &buf)
	if err != nil {
		return nil, fmt.Errorf("elasticsearch search: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		// Index doesn't exist yet (no logs ingested for this tenant).
		return &LogSearchResult{Logs: []models.Log{}, Total: 0, Page: p.Page}, nil
	}

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("elasticsearch search status %d: %s", resp.StatusCode, body)
	}

	var result struct {
		Hits struct {
			Total struct{ Value int } `json:"total"`
			Hits  []struct {
				Source struct {
					AgentID     int             `json:"agent_id"`
					TenantID    int             `json:"tenant_id"`
					LogSource   string          `json:"log_source"`
					LogMessage  string          `json:"log_message"`
					CollectedAt string          `json:"collected_at"`
					ParsedFields json.RawMessage `json:"parsed_fields"`
				} `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("elasticsearch parse response: %w", err)
	}

	var logs []models.Log
	for _, hit := range result.Hits.Hits {
		ts, _ := time.Parse(time.RFC3339, hit.Source.CollectedAt)
		logs = append(logs, models.Log{
			AgentID:      hit.Source.AgentID,
			TenantID:     hit.Source.TenantID,
			LogSource:    hit.Source.LogSource,
			LogMessage:   hit.Source.LogMessage,
			ParsedFields: string(hit.Source.ParsedFields),
			CollectedAt:  ts,
		})
	}
	if logs == nil {
		logs = []models.Log{}
	}

	total := result.Hits.Total.Value
	return &LogSearchResult{
		Logs:    logs,
		Total:   total,
		Page:    p.Page,
		HasMore: p.Page*p.Limit+len(logs) < total,
	}, nil
}

// ── Raw DSL query API ─────────────────────────────────────────────────────────

// RawQueryResult is the full ES search response forwarded to the UI.
type RawQueryResult struct {
	Took     int              `json:"took"`
	TimedOut bool             `json:"timed_out"`
	Hits     json.RawMessage  `json:"hits"`
	Aggs     json.RawMessage  `json:"aggregations,omitempty"`
	Total    int              `json:"total"`
	Error    string           `json:"error,omitempty"`
}

// ExecuteRawQuery sends an arbitrary DSL body to ES for the given index.
// A tenant_id filter is always injected into the outermost bool.filter to
// prevent cross-tenant data leakage regardless of what the caller sends.
func ExecuteRawQuery(tenantID int, index string, rawDSL json.RawMessage) (*RawQueryResult, error) {
	if esClient == nil {
		return nil, fmt.Errorf("elasticsearch not configured (set ELASTICSEARCH_URL)")
	}

	// Parse the caller's DSL so we can inject the tenant filter.
	var dsl map[string]any
	if err := json.Unmarshal(rawDSL, &dsl); err != nil {
		return nil, fmt.Errorf("invalid DSL JSON: %w", err)
	}

	// Ensure query.bool.filter contains a tenant_id term.
	q, _ := dsl["query"].(map[string]any)
	if q == nil {
		q = map[string]any{}
		dsl["query"] = q
	}
	b, _ := q["bool"].(map[string]any)
	if b == nil {
		b = map[string]any{}
		q["bool"] = b
	}
	filterList, _ := b["filter"].([]any)
	tenantFilter := map[string]any{"term": map[string]any{"tenant_id": tenantID}}
	b["filter"] = append(filterList, tenantFilter)

	var buf bytes.Buffer
	json.NewEncoder(&buf).Encode(dsl)

	resp, err := esClient.doRequest("POST", "/"+index+"/_search", &buf)
	if err != nil {
		return nil, fmt.Errorf("elasticsearch execute: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	// ES error response
	if resp.StatusCode >= 300 {
		var errResp struct {
			Error struct {
				RootCause []struct {
					Reason string `json:"reason"`
				} `json:"root_cause"`
				Reason string `json:"reason"`
			} `json:"error"`
		}
		if jerr := json.Unmarshal(body, &errResp); jerr == nil && errResp.Error.Reason != "" {
			reason := errResp.Error.Reason
			if len(errResp.Error.RootCause) > 0 {
				reason = errResp.Error.RootCause[0].Reason
			}
			return &RawQueryResult{Error: reason}, nil
		}
		return &RawQueryResult{Error: fmt.Sprintf("ES status %d: %s", resp.StatusCode, body)}, nil
	}

	var raw struct {
		Took     int             `json:"took"`
		TimedOut bool            `json:"timed_out"`
		Hits     json.RawMessage `json:"hits"`
		Aggs     json.RawMessage `json:"aggregations"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("parse ES response: %w", err)
	}

	// Extract total from hits.total.value
	total := 0
	var hitsEnv struct {
		Total struct {
			Value int `json:"value"`
		} `json:"total"`
	}
	_ = json.Unmarshal(raw.Hits, &hitsEnv)
	total = hitsEnv.Total.Value

	return &RawQueryResult{
		Took:     raw.Took,
		TimedOut: raw.TimedOut,
		Hits:     raw.Hits,
		Aggs:     raw.Aggs,
		Total:    total,
	}, nil
}

// ListESIndices returns all index names visible to the client.
func ListESIndices() ([]string, error) {
	if esClient == nil {
		return nil, fmt.Errorf("elasticsearch not configured")
	}
	resp, err := esClient.doRequest("GET", "/_cat/indices?format=json&h=index,docs.count,store.size,health", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	var rows []struct {
		Index     string `json:"index"`
		DocsCount string `json:"docs.count"`
		StoreSize string `json:"store.size"`
		Health    string `json:"health"`
	}
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil, fmt.Errorf("parse indices: %w", err)
	}
	names := make([]string, 0, len(rows))
	for _, r := range rows {
		names = append(names, r.Index)
	}
	return names, nil
}

// ESIndexMeta holds metadata about a single index.
type ESIndexMeta struct {
	Index     string `json:"index"`
	DocsCount string `json:"docs_count"`
	StoreSize string `json:"store_size"`
	Health    string `json:"health"`
}

// ListESIndexMeta returns index metadata (docs count, size, health).
func ListESIndexMeta() ([]ESIndexMeta, error) {
	if esClient == nil {
		return nil, fmt.Errorf("elasticsearch not configured")
	}
	resp, err := esClient.doRequest("GET", "/_cat/indices?format=json&h=index,docs.count,store.size,health&s=index", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	var rows []struct {
		Index     string `json:"index"`
		DocsCount string `json:"docs.count"`
		StoreSize string `json:"store.size"`
		Health    string `json:"health"`
	}
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil, fmt.Errorf("parse indices: %w", err)
	}
	result := make([]ESIndexMeta, 0, len(rows))
	for _, r := range rows {
		result = append(result, ESIndexMeta{
			Index:     r.Index,
			DocsCount: r.DocsCount,
			StoreSize: r.StoreSize,
			Health:    r.Health,
		})
	}
	return result, nil
}

// GetESMappings returns the field mappings for the given index (raw JSON).
func GetESMappings(index string) (json.RawMessage, error) {
	if esClient == nil {
		return nil, fmt.Errorf("elasticsearch not configured")
	}
	resp, err := esClient.doRequest("GET", "/"+index+"/_mapping", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("GET /%s/_mapping: status %d", index, resp.StatusCode)
	}
	return json.RawMessage(body), nil
}

// ESClusterHealth returns raw cluster health JSON from ES.
func ESClusterHealth() (json.RawMessage, error) {
	if esClient == nil {
		return nil, fmt.Errorf("elasticsearch not configured")
	}
	resp, err := esClient.doRequest("GET", "/_cluster/health", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("cluster health: status %d", resp.StatusCode)
	}
	return json.RawMessage(body), nil
}

// IndexAlertToES indexes a single alert into the tenant-scoped alert index.
// The alert index is separate from xcloak-logs-* so alerts can have their
// own ILM policy, retention, and field mappings without polluting the log index.
// Called from alert_consumer.go — never blocks the create-alert path.
func IndexAlertToES(alert models.Alert) {
	if esClient == nil {
		return
	}
	tenantID := alert.TenantID
	if tenantID == 0 {
		database.DB.QueryRow(`SELECT tenant_id FROM agents WHERE id=$1`, alert.AgentID).Scan(&tenantID)
	}
	if tenantID == 0 {
		return
	}
	index := fmt.Sprintf("xcloak-alerts-%d", tenantID)
	doc := map[string]any{
		"id":              alert.ID,
		"agent_id":        alert.AgentID,
		"tenant_id":       tenantID,
		"severity":        alert.Severity,
		"rule_name":       alert.RuleName,
		"log_message":     alert.LogMessage,
		"mitre_tactic":    alert.MitreTactic,
		"mitre_technique": alert.MitreTechnique,
		"mitre_name":      alert.MitreName,
		"fingerprint":     alert.Fingerprint,
		"created_at":      alert.CreatedAt.UTC().Format(time.RFC3339),
	}
	var buf bytes.Buffer
	json.NewEncoder(&buf).Encode(doc)
	path := fmt.Sprintf("/%s/_doc/%d", index, alert.ID)
	resp, err := esClient.doRequest("PUT", path, &buf)
	if err != nil {
		slog.Warn("elasticsearch: alert index failed", "alert_id", alert.ID, "err", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		slog.Warn("elasticsearch: alert index bad status", "status", resp.StatusCode, "body", string(body))
	}
}

// ── HTTP helpers ─────────────────────────────────────────────────────────────

func (c *elasticsearchClient) put(path string, body any) error {
	var buf bytes.Buffer
	json.NewEncoder(&buf).Encode(body)
	resp, err := c.doRequest("PUT", path, &buf)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("PUT %s: status %d: %s", path, resp.StatusCode, b)
	}
	return nil
}

func (c *elasticsearchClient) doRequest(method, path string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(context.Background(), method, c.baseURL+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.username != "" {
		req.SetBasicAuth(c.username, c.password)
	}
	return c.http.Do(req)
}
