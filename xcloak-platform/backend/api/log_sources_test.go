//go:build integration

package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func logSourceRouter(tenantID int) *gin.Engine {
	r := gin.New()
	r.Use(injectClaims(tenantID, 1, "admin"))
	r.GET("/api/log-sources", GetLogSources)
	r.POST("/api/log-sources", CreateLogSource)
	r.PUT("/api/log-sources/:id", UpdateLogSource)
	r.DELETE("/api/log-sources/:id", DeleteLogSource)
	return r
}

// TestGetLogSources_EmptyList verifies that a tenant with no log sources gets
// an empty array (not null) — the frontend does Array.isArray() on the response.
func TestGetLogSources_EmptyList(t *testing.T) {
	setupIntegration(t)

	r := logSourceRouter(999) // tenant with no sources
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/log-sources", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("GetLogSources empty: status = %d; body: %s", w.Code, w.Body.String())
	}

	var resp []any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp == nil {
		t.Error("response must be an array, got null")
	}
}

// TestCreateLogSource_HTTP creates an HTTP log source and verifies the response
// includes api_key (one-time plaintext), id, and api_key_hint.
func TestCreateLogSource_HTTP(t *testing.T) {
	setupIntegration(t)

	body, _ := json.Marshal(map[string]any{
		"name":        "Test-HTTP-Source",
		"source_type": "http",
		"format":      "json",
		"device_type": "cloud",
	})
	r := logSourceRouter(1)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/log-sources", bytes.NewBuffer(body)))

	if w.Code != http.StatusCreated {
		t.Fatalf("CreateLogSource HTTP: status = %d; body: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)

	if resp["api_key"] == nil || resp["api_key"] == "" {
		t.Error("HTTP log source must return plaintext api_key on creation")
	}
	if resp["id"] == nil {
		t.Error("response must include id")
	}
	if resp["api_key_hint"] == nil {
		t.Error("response must include api_key_hint")
	}
	// api_key and api_key_hint must differ (hint is truncated, key is full)
	if resp["api_key"] == resp["api_key_hint"] {
		t.Error("api_key_hint must differ from full api_key")
	}
}

// TestCreateLogSource_SyslogWildcard verifies that a syslog source with no IP
// can be created (wildcard — matches any sender). Backend previously rejected this.
func TestCreateLogSource_SyslogWildcard(t *testing.T) {
	setupIntegration(t)

	body, _ := json.Marshal(map[string]any{
		"name":        "Wildcard-Syslog",
		"source_type": "syslog",
		"format":      "auto",
		"device_type": "firewall",
		// ip_address intentionally omitted
	})
	r := logSourceRouter(1)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/log-sources", bytes.NewBuffer(body)))

	if w.Code != http.StatusCreated {
		t.Fatalf("CreateLogSource syslog wildcard: status = %d; body: %s", w.Code, w.Body.String())
	}
}

// TestUpdateLogSource_RequiresEnabled verifies that PUT without "enabled"
// returns 400. Previously it defaulted to true, silently enabling paused sources.
func TestUpdateLogSource_RequiresEnabled(t *testing.T) {
	setupIntegration(t)

	// Create a source to update
	createBody, _ := json.Marshal(map[string]any{
		"name": "Update-Test-Source", "source_type": "http",
	})
	r := logSourceRouter(1)
	wc := httptest.NewRecorder()
	r.ServeHTTP(wc, httptest.NewRequest(http.MethodPost, "/api/log-sources", bytes.NewBuffer(createBody)))
	if wc.Code != http.StatusCreated {
		t.Skipf("setup: create failed %d", wc.Code)
	}

	var created map[string]any
	json.NewDecoder(wc.Body).Decode(&created)
	id := int(created["id"].(float64))

	// PUT without enabled field
	updateBody, _ := json.Marshal(map[string]any{"name": "Renamed"})
	wu := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/log-sources/%d", id), bytes.NewBuffer(updateBody))
	r.ServeHTTP(wu, req)

	if wu.Code != http.StatusBadRequest {
		t.Errorf("UpdateLogSource without enabled: status = %d, want 400", wu.Code)
	}
}

// TestUpdateLogSource_TenantIsolation verifies that updating a log source from
// another tenant returns 404, not 200.
func TestUpdateLogSource_TenantIsolation(t *testing.T) {
	setupIntegration(t)

	// Create source under tenant 1
	createBody, _ := json.Marshal(map[string]any{
		"name": "Tenant1-Source", "source_type": "http",
	})
	r1 := logSourceRouter(1)
	wc := httptest.NewRecorder()
	r1.ServeHTTP(wc, httptest.NewRequest(http.MethodPost, "/api/log-sources", bytes.NewBuffer(createBody)))
	if wc.Code != http.StatusCreated {
		t.Skipf("setup: create failed %d", wc.Code)
	}

	var created map[string]any
	json.NewDecoder(wc.Body).Decode(&created)
	id := int(created["id"].(float64))

	// Attempt update from tenant 2
	updateBody, _ := json.Marshal(map[string]any{"name": "Hacked", "enabled": true})
	r2 := logSourceRouter(2)
	wu := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/log-sources/%d", id), bytes.NewBuffer(updateBody))
	r2.ServeHTTP(wu, req)

	if wu.Code != http.StatusNotFound {
		t.Errorf("cross-tenant update: status = %d, want 404", wu.Code)
	}
}
