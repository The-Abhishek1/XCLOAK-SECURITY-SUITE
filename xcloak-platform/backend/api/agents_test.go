//go:build integration

package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"xcloak-platform/database"
)

// insertTestAgent creates a minimal agent row scoped to tenant 1 and registers
// a cleanup that removes it (and its cascaded rows) after the test.
func insertTestAgent(t *testing.T) int {
	t.Helper()
	unique := fmt.Sprintf("hb-test-%d", time.Now().UnixNano())
	var id int
	err := database.DB.QueryRow(`
		INSERT INTO agents (hostname, os, status, machine_id, token, tenant_id)
		VALUES ($1, 'linux', 'online', $2, $3, 1)
		RETURNING id
	`, unique, unique, unique).Scan(&id)
	if err != nil {
		t.Fatalf("insertTestAgent: %v", err)
	}
	t.Cleanup(func() {
		database.DB.Exec(`DELETE FROM agents WHERE id = $1`, id)
	})
	return id
}

// TestHeartbeat_ValidPayload verifies that a full heartbeat (including all
// platform-specific metrics) is accepted and persisted by the handler.
func TestHeartbeat_ValidPayload(t *testing.T) {
	setupIntegration(t)
	agentID := insertTestAgent(t)

	payload := map[string]any{
		"agent_id":        agentID,
		"version":         "1.2.3",
		"uptime_seconds":  3600,
		"mem_alloc_mb":    42,
		"goroutines":      18,
		"load_avg_1m":     0.75,
		"load_avg_5m":     1.10,
		"load_avg_15m":    0.95,
		"logged_in_users": 2,
		"open_fds":        512,
	}
	body, _ := json.Marshal(payload)

	r := gin.New()
	r.Use(injectClaims(1, 1, "admin"))
	r.POST("/api/agents/heartbeat", Heartbeat)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/agents/heartbeat", bytes.NewBuffer(body)))

	if w.Code != http.StatusOK {
		t.Fatalf("Heartbeat: status = %d, want 200; body: %s", w.Code, w.Body.String())
	}

	// Verify the metrics landed in the DB.
	var version string
	var uptimeSecs int64
	var loadAvg1m, loadAvg5m, loadAvg15m *float64
	var loggedInUsers, openFDs *int

	err := database.DB.QueryRow(`
		SELECT version, uptime_seconds, load_avg_1m, load_avg_5m, load_avg_15m,
		       logged_in_users, open_fds
		FROM agents WHERE id = $1
	`, agentID).Scan(&version, &uptimeSecs, &loadAvg1m, &loadAvg5m, &loadAvg15m, &loggedInUsers, &openFDs)
	if err != nil {
		t.Fatalf("querying stored metrics: %v", err)
	}

	if version != "1.2.3" {
		t.Errorf("version = %q, want 1.2.3", version)
	}
	if uptimeSecs != 3600 {
		t.Errorf("uptime_seconds = %d, want 3600", uptimeSecs)
	}
	if loadAvg1m == nil || *loadAvg1m != 0.75 {
		t.Errorf("load_avg_1m = %v, want 0.75", loadAvg1m)
	}
	if loadAvg5m == nil || *loadAvg5m != 1.10 {
		t.Errorf("load_avg_5m = %v, want 1.10", loadAvg5m)
	}
	if loggedInUsers == nil || *loggedInUsers != 2 {
		t.Errorf("logged_in_users = %v, want 2", loggedInUsers)
	}
	if openFDs == nil || *openFDs != 512 {
		t.Errorf("open_fds = %v, want 512", openFDs)
	}
}

// TestHeartbeat_MobilePayload verifies that Android-specific fields are stored.
func TestHeartbeat_MobilePayload(t *testing.T) {
	setupIntegration(t)
	agentID := insertTestAgent(t)

	payload := map[string]any{
		"agent_id":         agentID,
		"version":          "1.0.0",
		"platform":         "android",
		"battery_level":    78,
		"battery_charging": true,
		"network_type":     "wifi",
		"is_rooted":        false,
		"developer_mode":   false,
		"storage_free_gb":  12.5,
		"storage_total_gb": 64.0,
		"vpn_active":       true,
		"security_patch":   "2025-06-01",
	}
	body, _ := json.Marshal(payload)

	r := gin.New()
	r.Use(injectClaims(1, 1, "admin"))
	r.POST("/api/agents/heartbeat", Heartbeat)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/agents/heartbeat", bytes.NewBuffer(body)))

	if w.Code != http.StatusOK {
		t.Fatalf("Heartbeat mobile: status = %d; body: %s", w.Code, w.Body.String())
	}

	var batteryLevel *int
	var batteryCharging, vpnActive *bool
	var networkType, securityPatch *string
	var storageFreeGB, storageTotalGB *float64

	err := database.DB.QueryRow(`
		SELECT battery_level, battery_charging, network_type, storage_free_gb,
		       storage_total_gb, vpn_active, security_patch
		FROM agents WHERE id = $1
	`, agentID).Scan(&batteryLevel, &batteryCharging, &networkType, &storageFreeGB, &storageTotalGB, &vpnActive, &securityPatch)
	if err != nil {
		t.Fatalf("querying stored mobile metrics: %v", err)
	}

	if batteryLevel == nil || *batteryLevel != 78 {
		t.Errorf("battery_level = %v, want 78", batteryLevel)
	}
	if batteryCharging == nil || !*batteryCharging {
		t.Errorf("battery_charging = %v, want true", batteryCharging)
	}
	if networkType == nil || *networkType != "wifi" {
		t.Errorf("network_type = %v, want wifi", networkType)
	}
	if storageFreeGB == nil || *storageFreeGB != 12.5 {
		t.Errorf("storage_free_gb = %v, want 12.5", storageFreeGB)
	}
	if vpnActive == nil || !*vpnActive {
		t.Errorf("vpn_active = %v, want true", vpnActive)
	}
	if securityPatch == nil || *securityPatch != "2025-06-01" {
		t.Errorf("security_patch = %v, want 2025-06-01", securityPatch)
	}
}

// TestHeartbeat_BadJSON verifies that malformed JSON returns 400.
func TestHeartbeat_BadJSON(t *testing.T) {
	setupIntegration(t)

	r := gin.New()
	r.Use(injectClaims(1, 1, "admin"))
	r.POST("/api/agents/heartbeat", Heartbeat)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/agents/heartbeat",
		bytes.NewBufferString(`not-json`)))

	if w.Code != http.StatusBadRequest {
		t.Errorf("bad JSON: status = %d, want 400", w.Code)
	}
}

// TestGetAgents_Returns200 verifies the agent list endpoint returns 200 and
// includes the inserted agent.
func TestGetAgents_Returns200(t *testing.T) {
	setupIntegration(t)
	insertTestAgent(t)

	r := gin.New()
	r.Use(injectClaims(1, 1, "analyst"))
	r.GET("/api/agents", GetAgents)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/agents", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("GetAgents: status = %d; body: %s", w.Code, w.Body.String())
	}

	var agents []map[string]any
	if err := json.NewDecoder(w.Body).Decode(&agents); err != nil {
		t.Fatalf("decode agents: %v", err)
	}
	if len(agents) == 0 {
		t.Error("GetAgents: got empty list, want at least 1 agent")
	}
}

// TestGetAgents_IncludesOpenAlertCount verifies that the list endpoint returns
// a snooze-aware open_alert_count per agent. Snoozed alerts must NOT count.
func TestGetAgents_IncludesOpenAlertCount(t *testing.T) {
	setupIntegration(t)
	agentID := insertTestAgent(t)
	alertID := insertTestAlert(t, agentID)

	// Before snooze — open_alert_count should be >= 1 for this agent.
	r := gin.New()
	r.Use(injectClaims(1, 1, "analyst"))
	r.GET("/api/agents", GetAgents)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/agents", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("GetAgents: %d; %s", w.Code, w.Body.String())
	}

	var agents []map[string]any
	json.NewDecoder(w.Body).Decode(&agents)

	var countBefore float64
	for _, a := range agents {
		if int(a["id"].(float64)) == agentID {
			countBefore, _ = a["open_alert_count"].(float64)
			break
		}
	}
	if countBefore < 1 {
		t.Errorf("open_alert_count before snooze = %.0f, want >= 1", countBefore)
	}

	// Snooze the alert — open_alert_count should drop to 0 for this agent.
	database.DB.Exec(`
		UPDATE alerts SET suppressed_until = NOW() + INTERVAL '1 hour' WHERE id = $1`, alertID)

	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, httptest.NewRequest(http.MethodGet, "/api/agents", nil))

	var agents2 []map[string]any
	json.NewDecoder(w2.Body).Decode(&agents2)

	for _, a := range agents2 {
		if int(a["id"].(float64)) == agentID {
			cnt, _ := a["open_alert_count"].(float64)
			if cnt != 0 {
				t.Errorf("open_alert_count after snooze = %.0f, want 0", cnt)
			}
			break
		}
	}
}

// TestGetAgents_TenantIsolation verifies that a tenant cannot see another
// tenant's agents in the list response.
func TestGetAgents_TenantIsolation(t *testing.T) {
	setupIntegration(t)

	// Insert an agent for tenant 2 directly.
	unique := fmt.Sprintf("iso-agent-%d", time.Now().UnixNano())
	var tenant2AgentID int
	err := database.DB.QueryRow(`
		INSERT INTO agents (hostname, os, status, machine_id, token, tenant_id)
		VALUES ($1, 'windows', 'online', $2, $3, 2)
		RETURNING id
	`, unique, unique, unique).Scan(&tenant2AgentID)
	if err != nil {
		t.Fatalf("insert tenant-2 agent: %v", err)
	}
	t.Cleanup(func() { database.DB.Exec(`DELETE FROM agents WHERE id = $1`, tenant2AgentID) })

	// Query as tenant 1 — must not see the tenant-2 agent.
	r := gin.New()
	r.Use(injectClaims(1, 1, "analyst"))
	r.GET("/api/agents", GetAgents)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/agents", nil))

	var agents []map[string]any
	json.NewDecoder(w.Body).Decode(&agents)

	for _, a := range agents {
		if int(a["id"].(float64)) == tenant2AgentID {
			t.Errorf("tenant 1 can see tenant-2 agent ID %d — isolation breach", tenant2AgentID)
		}
	}
}
