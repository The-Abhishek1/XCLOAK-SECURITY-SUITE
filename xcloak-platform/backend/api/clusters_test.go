//go:build integration

package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"xcloak-platform/database"
)

func clustersRouter(tenantID int) *gin.Engine {
	r := gin.New()
	r.Use(injectClaims(tenantID, 1, "analyst"))
	r.GET("/api/clusters", ListAlertClusters)
	r.GET("/api/clusters/:id/alerts", GetClusterAlerts)
	r.POST("/api/clusters/:id/suppress", SuppressCluster)
	r.POST("/api/clusters/analyze", TriggerClustering)
	return r
}

func insertTestCluster(t *testing.T, tenantID int) int {
	t.Helper()
	var id int
	err := database.DB.QueryRow(`
		INSERT INTO alert_clusters
		  (tenant_id, cluster_key, rule_name, mitre_technique, alert_count, status)
		VALUES ($1, 'test_key', 'test_rule', 'T1566', 1, 'open')
		RETURNING id
	`, tenantID).Scan(&id)
	if err != nil {
		t.Fatalf("insertTestCluster: %v", err)
	}
	t.Cleanup(func() {
		database.DB.Exec(`DELETE FROM alert_clusters WHERE id = $1`, id)
	})
	return id
}

// TestListAlertClusters_ReturnsArray verifies the endpoint returns an array
// even when no clusters exist for the tenant.
func TestListAlertClusters_ReturnsArray(t *testing.T) {
	setupIntegration(t)

	r := clustersRouter(999)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/clusters", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("ListAlertClusters: status = %d; body: %s", w.Code, w.Body.String())
	}
	var resp []any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp == nil {
		t.Error("response must be an array, not null")
	}
}

// TestGetClusterAlerts_Valid verifies that cluster alerts can be fetched
// without error (empty array is fine — cluster may have no alerts yet).
func TestGetClusterAlerts_Valid(t *testing.T) {
	setupIntegration(t)

	clusterID := insertTestCluster(t, 1)
	r := clustersRouter(1)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet,
		fmt.Sprintf("/api/clusters/%d/alerts", clusterID), nil))

	if w.Code != http.StatusOK {
		t.Fatalf("GetClusterAlerts: status = %d; body: %s", w.Code, w.Body.String())
	}
}

// TestSuppressCluster_CrossTenant verifies that suppressing another tenant's
// cluster does not affect the original record.
func TestSuppressCluster_CrossTenant(t *testing.T) {
	setupIntegration(t)

	clusterID := insertTestCluster(t, 1)

	r2 := clustersRouter(2)
	w := httptest.NewRecorder()
	r2.ServeHTTP(w, httptest.NewRequest(http.MethodPost,
		fmt.Sprintf("/api/clusters/%d/suppress", clusterID), nil))

	// The cluster should still be in 'open' state under tenant 1
	var status string
	database.DB.QueryRow(`SELECT status FROM alert_clusters WHERE id = $1`, clusterID).Scan(&status)
	if status != "open" {
		t.Errorf("cross-tenant suppress changed cluster status to %q", status)
	}
}

// TestTriggerClustering_ReturnsOK verifies the async clustering trigger
// returns 200 immediately.
func TestTriggerClustering_ReturnsOK(t *testing.T) {
	setupIntegration(t)

	r := clustersRouter(1)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/clusters/analyze", nil))

	if w.Code != http.StatusOK {
		t.Errorf("TriggerClustering: status = %d, want 200", w.Code)
	}
}
