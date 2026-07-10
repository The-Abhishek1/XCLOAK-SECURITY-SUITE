//go:build integration

package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"xcloak-platform/database"
	"xcloak-platform/testenv"
)

// setupIntegration connects the global database.DB to the test database,
// skipping the test when the DB isn't reachable.
func setupIntegration(t *testing.T) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	db := testenv.SetupDB(t)
	database.DB = db
	t.Cleanup(func() { db.Close(); database.DB = nil })
}

// injectClaims injects standard user claims into a gin context for handlers
// that call tenantIDFromContext / userIDFromContext.
func injectClaims(tenantID, userID int, role string) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set("tenant_id", float64(tenantID))
		c.Set("user_id", float64(userID))
		c.Set("role", role)
		c.Set("username", "integration-test")
		c.Set("is_platform_admin", false)
		c.Next()
	}
}

func newRouter(handlers ...gin.HandlerFunc) *gin.Engine {
	r := gin.New()
	r.Use(injectClaims(1, 1, "admin"))
	for _, h := range handlers {
		r.GET("/test", h)
	}
	return r
}

func newPostRouter(handler gin.HandlerFunc) *gin.Engine {
	r := gin.New()
	r.Use(injectClaims(1, 1, "admin"))
	r.POST("/test", handler)
	return r
}

// ── Health ────────────────────────────────────────────────────────────────────

func TestHealth(t *testing.T) {
	setupIntegration(t)
	r := gin.New()
	r.GET("/api/health", Health)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/health", nil))
	if w.Code != http.StatusOK {
		t.Errorf("Health: status = %d, want 200", w.Code)
	}
}

func TestDeepHealth(t *testing.T) {
	setupIntegration(t)
	r := gin.New()
	r.GET("/api/health/deep", DeepHealth)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/health/deep", nil))
	if w.Code != http.StatusOK {
		t.Errorf("DeepHealth: status = %d, want 200", w.Code)
	}
}

// ── Alerts ────────────────────────────────────────────────────────────────────

func TestGetAlerts(t *testing.T) {
	setupIntegration(t)
	testenv.LoadFixtures(t, database.DB)
	w := doGet(t, GetAlerts)
	if w.Code != http.StatusOK {
		t.Errorf("GetAlerts: status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
}

// ── Firewall rules ────────────────────────────────────────────────────────────

func TestGetRules(t *testing.T) {
	setupIntegration(t)
	testenv.LoadFixtures(t, database.DB)
	w := doGet(t, GetRules)
	if w.Code != http.StatusOK {
		t.Errorf("GetRules: status = %d, want 200", w.Code)
	}
}

func TestCreateRule_BadRequest(t *testing.T) {
	setupIntegration(t)
	// Send invalid JSON → 400
	r := gin.New()
	r.Use(injectClaims(1, 1, "admin"))
	r.POST("/test", CreateRule)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewBufferString(`{invalid`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	if w.Code == http.StatusOK {
		t.Errorf("CreateRule bad JSON: expected non-200, got 200")
	}
}

func TestCreateRule_Valid(t *testing.T) {
	setupIntegration(t)
	testenv.LoadFixtures(t, database.DB)
	body := map[string]interface{}{
		"name": "integration-fw-rule", "action": "allow",
		"direction": "in", "proto": "tcp", "priority": 10,
	}
	w := doPost(t, CreateRule, body)
	if w.Code != http.StatusCreated && w.Code != http.StatusOK {
		t.Errorf("CreateRule: status = %d; body: %s", w.Code, w.Body.String())
	}
}

// ── Agents ────────────────────────────────────────────────────────────────────

func TestGetAgents(t *testing.T) {
	setupIntegration(t)
	testenv.LoadFixtures(t, database.DB)
	w := doGet(t, GetAgents)
	if w.Code != http.StatusOK {
		t.Errorf("GetAgents: status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
}

// ── Dashboard ─────────────────────────────────────────────────────────────────

func TestGetDashboard(t *testing.T) {
	setupIntegration(t)
	testenv.LoadFixtures(t, database.DB)
	w := doGet(t, GetDashboard)
	if w.Code != http.StatusOK {
		t.Errorf("GetDashboard: status = %d; body: %s", w.Code, w.Body.String())
	}
}

// ── Cases ─────────────────────────────────────────────────────────────────────

func TestGetCases(t *testing.T) {
	setupIntegration(t)
	testenv.LoadFixtures(t, database.DB)
	w := doGet(t, GetCases)
	if w.Code != http.StatusOK {
		t.Errorf("GetCases: status = %d; body: %s", w.Code, w.Body.String())
	}
}

// ── Audit logs ────────────────────────────────────────────────────────────────

func TestGetAuditLogs(t *testing.T) {
	setupIntegration(t)
	testenv.LoadFixtures(t, database.DB)
	w := doGet(t, GetAuditLogs)
	if w.Code != http.StatusOK {
		t.Errorf("GetAuditLogs: status = %d; body: %s", w.Code, w.Body.String())
	}
}

// ── Vulnerabilities ───────────────────────────────────────────────────────────

func TestGetVulnerabilities(t *testing.T) {
	setupIntegration(t)
	testenv.LoadFixtures(t, database.DB)
	w := doGet(t, GetVulnerabilities)
	if w.Code != http.StatusOK {
		t.Errorf("GetVulnerabilities: status = %d; body: %s", w.Code, w.Body.String())
	}
}

// ── Custom roles ──────────────────────────────────────────────────────────────

func TestGetCustomRoles(t *testing.T) {
	setupIntegration(t)
	testenv.LoadFixtures(t, database.DB)
	w := doGet(t, GetCustomRoles)
	if w.Code != http.StatusOK {
		t.Errorf("GetCustomRoles: status = %d; body: %s", w.Code, w.Body.String())
	}
}

// ── Log sources ───────────────────────────────────────────────────────────────

func TestGetLogSources(t *testing.T) {
	setupIntegration(t)
	testenv.LoadFixtures(t, database.DB)
	w := doGet(t, GetLogSources)
	if w.Code != http.StatusOK {
		t.Errorf("GetLogSources: status = %d; body: %s", w.Code, w.Body.String())
	}
}

// ── Assets ────────────────────────────────────────────────────────────────────

func TestGetAssets(t *testing.T) {
	setupIntegration(t)
	testenv.LoadFixtures(t, database.DB)
	w := doGet(t, GetAssets)
	if w.Code != http.StatusOK {
		t.Errorf("GetAssets: status = %d; body: %s", w.Code, w.Body.String())
	}
}

// ── IOCs ──────────────────────────────────────────────────────────────────────

func TestGetIOCs(t *testing.T) {
	setupIntegration(t)
	testenv.LoadFixtures(t, database.DB)
	w := doGet(t, GetIOCs)
	if w.Code != http.StatusOK {
		t.Errorf("GetIOCs: status = %d; body: %s", w.Code, w.Body.String())
	}
}

// ── Users ─────────────────────────────────────────────────────────────────────

func TestGetUsers(t *testing.T) {
	setupIntegration(t)
	testenv.LoadFixtures(t, database.DB)
	w := doGet(t, GetUsers)
	if w.Code != http.StatusOK {
		t.Errorf("GetUsers: status = %d; body: %s", w.Code, w.Body.String())
	}
}

// ── Sigma rules ───────────────────────────────────────────────────────────────

func TestGetSigmaRules(t *testing.T) {
	setupIntegration(t)
	testenv.LoadFixtures(t, database.DB)
	w := doGet(t, GetSigmaRules)
	if w.Code != http.StatusOK {
		t.Errorf("GetSigmaRules: status = %d; body: %s", w.Code, w.Body.String())
	}
}

// ── Playbooks ─────────────────────────────────────────────────────────────────

func TestGetPlaybooks(t *testing.T) {
	setupIntegration(t)
	testenv.LoadFixtures(t, database.DB)
	w := doGet(t, GetPlaybooks)
	if w.Code != http.StatusOK {
		t.Errorf("GetPlaybooks: status = %d; body: %s", w.Code, w.Body.String())
	}
}

// ── Register / Login (400 paths without body) ─────────────────────────────────

func TestRegister_MissingBody(t *testing.T) {
	setupIntegration(t)
	r := gin.New()
	r.POST("/api/auth/register", Register)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/auth/register", nil))
	if w.Code == http.StatusOK {
		t.Errorf("Register with no body: expected non-200, got 200")
	}
}

func TestLogin_InvalidCredentials(t *testing.T) {
	setupIntegration(t)
	testenv.LoadFixtures(t, database.DB)
	body := map[string]string{"username": "nonexistent", "password": "wrongpass"}
	r := gin.New()
	r.POST("/api/auth/login", Login)
	b, _ := json.Marshal(body)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	if w.Code == http.StatusOK {
		t.Errorf("Login with wrong creds: expected non-200, got 200")
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

func doGet(t *testing.T, handler gin.HandlerFunc) *httptest.ResponseRecorder {
	t.Helper()
	r := gin.New()
	r.Use(injectClaims(1, 1, "admin"))
	r.GET("/test", handler)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/test", nil))
	return w
}

func doPost(t *testing.T, handler gin.HandlerFunc, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	r := gin.New()
	r.Use(injectClaims(1, 1, "admin"))
	r.POST("/test", handler)
	b, _ := json.Marshal(body)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	return w
}
