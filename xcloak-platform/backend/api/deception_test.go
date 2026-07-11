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

func deceptionRouter(tenantID int) *gin.Engine {
	r := gin.New()
	r.Use(injectClaims(tenantID, 1, "admin"))
	r.GET("/api/canary/tokens", ListCanaryTokens)
	r.POST("/api/canary/tokens", CreateCanaryToken)
	r.DELETE("/api/canary/tokens/:id", DeleteCanaryToken)
	r.PATCH("/api/canary/tokens/:id/toggle", ToggleCanaryToken)
	r.GET("/api/canary/trips", GetCanaryTrips)
	r.GET("/api/honeyports", ListHoneyports)
	r.POST("/api/honeyports", CreateHoneyport)
	r.DELETE("/api/honeyports/:id", DeleteHoneyport)
	return r
}

func insertTestCanaryToken(t *testing.T, tenantID int) int {
	t.Helper()
	var id int
	err := database.DB.QueryRow(`
		INSERT INTO canary_tokens
		  (tenant_id, token_type, name, token_value, created_by)
		VALUES ($1, 'url', 'Test Token', $2, 'test')
		RETURNING id
	`, tenantID, fmt.Sprintf("test-token-%d-%d", tenantID, tenantID*1000)).Scan(&id)
	if err != nil {
		t.Fatalf("insertTestCanaryToken: %v", err)
	}
	t.Cleanup(func() {
		database.DB.Exec(`DELETE FROM canary_tokens WHERE id = $1`, id)
	})
	return id
}

// TestListCanaryTokens_ReturnsArray verifies the endpoint returns an array.
func TestListCanaryTokens_ReturnsArray(t *testing.T) {
	setupIntegration(t)

	r := deceptionRouter(999)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/canary/tokens", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("ListCanaryTokens: status = %d; body: %s", w.Code, w.Body.String())
	}
	var resp []any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp == nil {
		t.Error("response must be an array, not null")
	}
}

// TestCreateCanaryToken_Valid verifies a canary token can be created.
func TestCreateCanaryToken_Valid(t *testing.T) {
	setupIntegration(t)

	body, _ := json.Marshal(map[string]any{
		"token_type": "url",
		"name":       "Test API Key Canary",
		"description": "created by integration test",
	})
	r := deceptionRouter(1)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/canary/tokens",
		bytes.NewReader(body)))

	if w.Code != http.StatusOK && w.Code != http.StatusCreated {
		t.Fatalf("CreateCanaryToken: status = %d; body: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["id"] == nil {
		t.Error("response must include id")
	}
	if id, ok := resp["id"].(float64); ok {
		database.DB.Exec(`DELETE FROM canary_tokens WHERE id = $1`, int(id))
	}
}

// TestDeleteCanaryToken_CrossTenant verifies tenant isolation on delete.
func TestDeleteCanaryToken_CrossTenant(t *testing.T) {
	setupIntegration(t)

	tokenID := insertTestCanaryToken(t, 1)

	r2 := deceptionRouter(2)
	w := httptest.NewRecorder()
	r2.ServeHTTP(w, httptest.NewRequest(http.MethodDelete,
		fmt.Sprintf("/api/canary/tokens/%d", tokenID), nil))

	var count int
	database.DB.QueryRow(`SELECT COUNT(*) FROM canary_tokens WHERE id=$1 AND tenant_id=1`, tokenID).Scan(&count)
	if count != 1 {
		t.Error("cross-tenant delete must not remove another tenant's canary token")
	}
}

// TestGetCanaryTrips_ReturnsArray verifies trips endpoint returns an array.
func TestGetCanaryTrips_ReturnsArray(t *testing.T) {
	setupIntegration(t)

	r := deceptionRouter(999)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/canary/trips", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("GetCanaryTrips: status = %d; body: %s", w.Code, w.Body.String())
	}
	var resp []any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp == nil {
		t.Error("trips response must be an array, not null")
	}
}
