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

func threatActorsRouter(tenantID int) *gin.Engine {
	r := gin.New()
	r.Use(injectClaims(tenantID, 1, "analyst"))
	r.GET("/api/threat-actors", ListThreatActors)
	r.POST("/api/threat-actors", CreateThreatActor)
	r.DELETE("/api/threat-actors/:id", DeleteThreatActor)
	r.GET("/api/threat-actors/:id/alerts", GetActorAlerts)
	return r
}

func insertTestThreatActor(t *testing.T, tenantID int) int {
	t.Helper()
	var id int
	err := database.DB.QueryRow(`
		INSERT INTO threat_actors
		  (tenant_id, name, sophistication, motivation)
		VALUES ($1, 'Test Actor', 'medium', 'financial')
		RETURNING id
	`, tenantID).Scan(&id)
	if err != nil {
		t.Fatalf("insertTestThreatActor: %v", err)
	}
	t.Cleanup(func() {
		database.DB.Exec(`DELETE FROM threat_actors WHERE id = $1`, id)
	})
	return id
}

// TestListThreatActors_ReturnsArray verifies the endpoint returns an array.
func TestListThreatActors_ReturnsArray(t *testing.T) {
	setupIntegration(t)

	r := threatActorsRouter(999)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/threat-actors", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("ListThreatActors: status = %d; body: %s", w.Code, w.Body.String())
	}
	var resp []any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp == nil {
		t.Error("response must be an array, not null")
	}
}

// TestCreateThreatActor_Valid verifies a threat actor can be created.
func TestCreateThreatActor_Valid(t *testing.T) {
	setupIntegration(t)

	body, _ := json.Marshal(map[string]any{
		"name":          "APT-Test",
		"sophistication": "high",
		"motivation":    "espionage",
	})
	r := threatActorsRouter(1)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/threat-actors",
		bytes.NewReader(body)))

	if w.Code != http.StatusOK && w.Code != http.StatusCreated {
		t.Fatalf("CreateThreatActor: status = %d; body: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["id"] == nil {
		t.Error("response must include id")
	}
	if id, ok := resp["id"].(float64); ok {
		database.DB.Exec(`DELETE FROM threat_actors WHERE id = $1`, int(id))
	}
}

// TestDeleteThreatActor_CrossTenant verifies tenant isolation on delete.
func TestDeleteThreatActor_CrossTenant(t *testing.T) {
	setupIntegration(t)

	actorID := insertTestThreatActor(t, 1)

	r2 := threatActorsRouter(2)
	w := httptest.NewRecorder()
	r2.ServeHTTP(w, httptest.NewRequest(http.MethodDelete,
		fmt.Sprintf("/api/threat-actors/%d", actorID), nil))

	var count int
	database.DB.QueryRow(`SELECT COUNT(*) FROM threat_actors WHERE id=$1 AND tenant_id=1`, actorID).Scan(&count)
	if count != 1 {
		t.Error("cross-tenant delete must not remove another tenant's threat actor")
	}
}

// TestGetActorAlerts_Valid verifies alerts for an actor can be fetched.
func TestGetActorAlerts_Valid(t *testing.T) {
	setupIntegration(t)

	actorID := insertTestThreatActor(t, 1)
	r := threatActorsRouter(1)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet,
		fmt.Sprintf("/api/threat-actors/%d/alerts", actorID), nil))

	if w.Code != http.StatusOK {
		t.Fatalf("GetActorAlerts: status = %d; body: %s", w.Code, w.Body.String())
	}
}
