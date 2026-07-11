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

func ja3Router(tenantID int) *gin.Engine {
	r := gin.New()
	r.Use(injectClaims(tenantID, 1, "analyst"))
	r.GET("/api/ja3/fingerprints", GetJA3Fingerprints)
	r.POST("/api/ja3/fingerprints", CreateJA3Fingerprint)
	r.DELETE("/api/ja3/fingerprints/:id", DeleteJA3Fingerprint)
	return r
}

// TestGetJA3Fingerprints_ReturnsArray verifies the endpoint returns an array.
func TestGetJA3Fingerprints_ReturnsArray(t *testing.T) {
	setupIntegration(t)

	r := ja3Router(999)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/ja3/fingerprints", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("GetJA3Fingerprints: status = %d; body: %s", w.Code, w.Body.String())
	}
	var resp []any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp == nil {
		t.Error("response must be an array, not null")
	}
}

// TestCreateJA3Fingerprint_Valid verifies that a valid fingerprint can be
// created with a 32-char MD5 hash.
func TestCreateJA3Fingerprint_Valid(t *testing.T) {
	setupIntegration(t)

	body, _ := json.Marshal(map[string]any{
		"hash":        "aabbccddeeff00112233445566778899",
		"threat_name": "Test TLS Fingerprint",
		"severity":    "high",
		"source":      "test",
	})
	r := ja3Router(1)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/ja3/fingerprints",
		bytes.NewReader(body)))

	if w.Code != http.StatusCreated {
		t.Fatalf("CreateJA3Fingerprint: status = %d; body: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["id"] == nil {
		t.Error("response must include id")
	}
	// Cleanup
	if id, ok := resp["id"].(float64); ok {
		database.DB.Exec(`DELETE FROM ja3_fingerprints WHERE id = $1`, int(id))
	}
}

// TestCreateJA3Fingerprint_InvalidHash verifies that a non-32-char hash is
// rejected with 400.
func TestCreateJA3Fingerprint_InvalidHash(t *testing.T) {
	setupIntegration(t)

	body, _ := json.Marshal(map[string]any{
		"hash":        "tooshort",
		"threat_name": "Bad Hash",
	})
	r := ja3Router(1)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/ja3/fingerprints",
		bytes.NewReader(body)))

	if w.Code != http.StatusBadRequest {
		t.Errorf("invalid hash: status = %d, want 400", w.Code)
	}
}

// TestDeleteJA3Fingerprint_CrossTenant verifies that a tenant cannot delete
// another tenant's fingerprint.
func TestDeleteJA3Fingerprint_CrossTenant(t *testing.T) {
	setupIntegration(t)

	// Create a fingerprint under tenant 1
	body, _ := json.Marshal(map[string]any{
		"hash":        "00112233445566778899aabbccddeeff",
		"threat_name": "Cross-tenant FP",
		"severity":    "medium",
		"source":      "test",
	})
	r1 := ja3Router(1)
	w1 := httptest.NewRecorder()
	r1.ServeHTTP(w1, httptest.NewRequest(http.MethodPost, "/api/ja3/fingerprints",
		bytes.NewReader(body)))

	var created map[string]any
	json.NewDecoder(w1.Body).Decode(&created)
	fpID, ok := created["id"].(float64)
	if !ok {
		t.Skip("could not create fingerprint for cross-tenant test")
	}
	defer database.DB.Exec(`DELETE FROM ja3_fingerprints WHERE id = $1`, int(fpID))

	// Try to delete from tenant 2
	r2 := ja3Router(2)
	w2 := httptest.NewRecorder()
	r2.ServeHTTP(w2, httptest.NewRequest(http.MethodDelete,
		fmt.Sprintf("/api/ja3/fingerprints/%d", int(fpID)), nil))

	if w2.Code != http.StatusNotFound {
		t.Errorf("cross-tenant delete: status = %d, want 404", w2.Code)
	}
}
