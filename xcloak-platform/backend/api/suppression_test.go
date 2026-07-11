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

func suppressionRouter(tenantID int) *gin.Engine {
	r := gin.New()
	r.Use(injectClaims(tenantID, 1, "admin"))
	r.GET("/api/suppression/rules", GetSuppressionRules)
	r.POST("/api/suppression/rules", CreateSuppressionRule)
	r.DELETE("/api/suppression/rules/:id", DeleteSuppressionRule)
	r.PATCH("/api/suppression/rules/:id/toggle", ToggleSuppressionRule)
	return r
}

func insertTestSuppressionRule(t *testing.T, tenantID int) int {
	t.Helper()
	var id int
	err := database.DB.QueryRow(`
		INSERT INTO suppression_rules
		  (name, rule_name, window_minutes, enabled, created_by, tenant_id)
		VALUES ('Test Rule', 'test_rule', 60, true, 'test', $1)
		RETURNING id
	`, tenantID).Scan(&id)
	if err != nil {
		t.Fatalf("insertTestSuppressionRule: %v", err)
	}
	t.Cleanup(func() {
		database.DB.Exec(`DELETE FROM suppression_rules WHERE id = $1`, id)
	})
	return id
}

// TestGetSuppressionRules_ReturnsObject verifies the endpoint returns a rules
// array (wrapped in an object).
func TestGetSuppressionRules_ReturnsObject(t *testing.T) {
	setupIntegration(t)

	r := suppressionRouter(999)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/suppression/rules", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("GetSuppressionRules: status = %d; body: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["rules"] == nil {
		t.Error("response must include 'rules' key")
	}
}

// TestCreateSuppressionRule_Valid verifies a rule can be created.
func TestCreateSuppressionRule_Valid(t *testing.T) {
	setupIntegration(t)

	body, _ := json.Marshal(map[string]any{
		"name":           "Block Nmap",
		"rule_name":      "nmap_scan",
		"window_minutes": 30,
	})
	r := suppressionRouter(1)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/suppression/rules",
		bytes.NewReader(body)))

	if w.Code != http.StatusOK && w.Code != http.StatusCreated {
		t.Fatalf("CreateSuppressionRule: status = %d; body: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["id"] == nil {
		t.Error("response must include id")
	}
	if id, ok := resp["id"].(float64); ok {
		database.DB.Exec(`DELETE FROM suppression_rules WHERE id = $1`, int(id))
	}
}

// TestDeleteSuppressionRule_CrossTenant verifies that a tenant cannot delete
// another tenant's rule; the original must survive.
func TestDeleteSuppressionRule_CrossTenant(t *testing.T) {
	setupIntegration(t)

	ruleID := insertTestSuppressionRule(t, 1)

	r2 := suppressionRouter(2)
	w := httptest.NewRecorder()
	r2.ServeHTTP(w, httptest.NewRequest(http.MethodDelete,
		fmt.Sprintf("/api/suppression/rules/%d", ruleID), nil))

	var count int
	database.DB.QueryRow(`SELECT COUNT(*) FROM suppression_rules WHERE id=$1 AND tenant_id=1`, ruleID).Scan(&count)
	if count != 1 {
		t.Error("cross-tenant delete must not remove another tenant's suppression rule")
	}
}

// TestToggleSuppressionRule_CrossTenant verifies that toggling another
// tenant's rule does not change its state.
func TestToggleSuppressionRule_CrossTenant(t *testing.T) {
	setupIntegration(t)

	ruleID := insertTestSuppressionRule(t, 1)

	body, _ := json.Marshal(map[string]any{"enabled": false})
	r2 := suppressionRouter(2)
	w := httptest.NewRecorder()
	r2.ServeHTTP(w, httptest.NewRequest(http.MethodPatch,
		fmt.Sprintf("/api/suppression/rules/%d/toggle", ruleID),
		bytes.NewReader(body)))

	var enabled bool
	database.DB.QueryRow(`SELECT enabled FROM suppression_rules WHERE id=$1`, ruleID).Scan(&enabled)
	if !enabled {
		t.Error("cross-tenant toggle must not change the original rule's enabled state")
	}
}
