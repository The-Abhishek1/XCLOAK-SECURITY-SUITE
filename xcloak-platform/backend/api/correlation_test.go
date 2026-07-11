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

	"xcloak-platform/database"
)

func correlationRouter(tenantID int) *gin.Engine {
	r := gin.New()
	r.Use(injectClaims(tenantID, 1, "admin"))
	r.GET("/api/correlation/rules", GetCorrelationRules)
	r.POST("/api/correlation/rules", CreateCorrelationRule)
	r.PUT("/api/correlation/rules/:id", UpdateCorrelationRule)
	r.PATCH("/api/correlation/rules/:id/toggle", ToggleCorrelationRule)
	r.DELETE("/api/correlation/rules/:id", DeleteCorrelationRule)
	r.GET("/api/correlation/matches", GetCorrelationMatches)
	return r
}

func insertTestCorrelationRule(t *testing.T, tenantID int) int {
	t.Helper()
	var id int
	err := database.DB.QueryRow(`
		INSERT INTO correlation_rules
		  (name, description, severity, rule_name, action, enabled,
		   created_by, tenant_id, correlation_type, window_minutes, threshold,
		   source_type, condition_value)
		VALUES ('Test Rule', '', 'medium', 'test_rule', 'notify', true,
		        'test', $1, 'simple', 5, 2, 'alert', '')
		RETURNING id
	`, tenantID).Scan(&id)
	if err != nil {
		t.Fatalf("insertTestCorrelationRule: %v", err)
	}
	t.Cleanup(func() {
		database.DB.Exec(`DELETE FROM correlation_rules WHERE id = $1`, id)
	})
	return id
}

// TestGetCorrelationRules_ReturnsArray verifies the endpoint returns an array
// even when no rules exist.
func TestGetCorrelationRules_ReturnsArray(t *testing.T) {
	setupIntegration(t)

	r := correlationRouter(999)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/correlation/rules", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("GetCorrelationRules: status = %d; body: %s", w.Code, w.Body.String())
	}
	var resp []any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp == nil {
		t.Error("response must be an array, not null")
	}
}

// TestCreateCorrelationRule_Valid verifies that a valid rule can be created.
func TestCreateCorrelationRule_Valid(t *testing.T) {
	setupIntegration(t)

	body, _ := json.Marshal(map[string]any{
		"name":             "Test Correlation Rule",
		"severity":         "high",
		"rule_name":        "test_corr",
		"action":           "notify",
		"correlation_type": "simple",
		"source_type":      "alert",
	})
	r := correlationRouter(1)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/correlation/rules",
		bytes.NewReader(body)))

	if w.Code != http.StatusOK {
		t.Fatalf("CreateCorrelationRule: status = %d; body: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["id"] == nil {
		t.Error("response must include id")
	}
	// Cleanup
	if id, ok := resp["id"].(float64); ok {
		database.DB.Exec(`DELETE FROM correlation_rules WHERE id = $1`, int(id))
	}
}

// TestUpdateCorrelationRule_CrossTenant verifies tenant isolation on update.
func TestUpdateCorrelationRule_CrossTenant(t *testing.T) {
	setupIntegration(t)

	ruleID := insertTestCorrelationRule(t, 1)
	body, _ := json.Marshal(map[string]any{
		"name":             "Hijacked",
		"severity":         "critical",
		"rule_name":        "hijacked",
		"action":           "notify",
		"correlation_type": "simple",
		"source_type":      "alert",
	})

	r2 := correlationRouter(2)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut,
		fmt.Sprintf("/api/correlation/rules/%d", ruleID), bytes.NewReader(body))
	r2.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("cross-tenant update: status = %d, want 404", w.Code)
	}
}

// TestGetCorrelationMatches_ReturnsArray verifies the matches endpoint returns
// an array (not null) even when no matches exist.
func TestGetCorrelationMatches_ReturnsArray(t *testing.T) {
	setupIntegration(t)

	r := correlationRouter(999)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/correlation/matches", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("GetCorrelationMatches: status = %d; body: %s", w.Code, w.Body.String())
	}
	var resp []any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp == nil {
		t.Error("matches response must be an array, not null")
	}
}

// TestDeleteCorrelationRule_CrossTenant verifies that deleting another
// tenant's rule silently does nothing (no 500).
func TestDeleteCorrelationRule_CrossTenant(t *testing.T) {
	setupIntegration(t)

	ruleID := insertTestCorrelationRule(t, 1)

	r2 := correlationRouter(2)
	w := httptest.NewRecorder()
	r2.ServeHTTP(w, httptest.NewRequest(http.MethodDelete,
		fmt.Sprintf("/api/correlation/rules/%d", ruleID), nil))

	// DELETE is idempotent — 200 with no rows affected is acceptable,
	// but the rule must still exist under tenant 1.
	if w.Code != http.StatusOK {
		t.Errorf("cross-tenant delete: status = %d, want 200 (idempotent)", w.Code)
	}
	var count int
	database.DB.QueryRow(`SELECT COUNT(*) FROM correlation_rules WHERE id=$1 AND tenant_id=1`, ruleID).Scan(&count)
	if count != 1 {
		t.Error("cross-tenant delete must not remove the original rule")
	}
}

