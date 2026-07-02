package middleware

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gin-gonic/gin"
)

// ── RequirePlatformAdmin ──────────────────────────────────────────────────────

func runPlatformAdmin(isPlatformAdmin any, setIt bool) *httptest.ResponseRecorder {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/", func(c *gin.Context) {
		if setIt {
			c.Set("is_platform_admin", isPlatformAdmin)
		}
		c.Next()
	}, RequirePlatformAdmin(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	return w
}

func TestRequirePlatformAdmin_Allows(t *testing.T) {
	if w := runPlatformAdmin(true, true); w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

func TestRequirePlatformAdmin_BlocksFalse(t *testing.T) {
	if w := runPlatformAdmin(false, true); w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
}

func TestRequirePlatformAdmin_BlocksMissing(t *testing.T) {
	if w := runPlatformAdmin(nil, false); w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
}

func TestRequirePlatformAdmin_BlocksNonBool(t *testing.T) {
	if w := runPlatformAdmin("yes", true); w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
}

// ── DBCircuit ─────────────────────────────────────────────────────────────────

func runDBCircuit(path string) *httptest.ResponseRecorder {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(DBCircuit())
	r.GET(path, func(c *gin.Context) { c.Status(http.StatusOK) })
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
	return w
}

func TestDBCircuit_HealthPassThrough(t *testing.T) {
	// DB is nil (not connected in tests) — IsPrimaryDown() returns false when
	// primaryState == stateClosed (zero value), so health endpoints pass through.
	for _, path := range []string{"/api/health", "/api/health/deep"} {
		if w := runDBCircuit(path); w.Code != http.StatusOK {
			t.Errorf("%s: status = %d, want 200", path, w.Code)
		}
	}
}

func TestDBCircuit_NormalRequestPassesWhenClosed(t *testing.T) {
	// primaryState is 0 (stateClosed) by default — requests should pass.
	if w := runDBCircuit("/api/alerts"); w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

// ── RequireMetricsAuth ────────────────────────────────────────────────────────

func runMetricsAuth(header, token string) *httptest.ResponseRecorder {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/metrics", RequireMetricsAuth(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	if header != "" {
		req.Header.Set("Authorization", header)
	}
	r.ServeHTTP(w, req)
	return w
}

func TestRequireMetricsAuth_NoEnvVar(t *testing.T) {
	os.Unsetenv("METRICS_TOKEN")
	if w := runMetricsAuth("Bearer secret", ""); w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503 when METRICS_TOKEN unset", w.Code)
	}
}

func TestRequireMetricsAuth_ValidToken(t *testing.T) {
	os.Setenv("METRICS_TOKEN", "supersecret")
	defer os.Unsetenv("METRICS_TOKEN")
	if w := runMetricsAuth("Bearer supersecret", "supersecret"); w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

func TestRequireMetricsAuth_WrongToken(t *testing.T) {
	os.Setenv("METRICS_TOKEN", "supersecret")
	defer os.Unsetenv("METRICS_TOKEN")
	if w := runMetricsAuth("Bearer wrongtoken", "supersecret"); w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestRequireMetricsAuth_MissingHeader(t *testing.T) {
	os.Setenv("METRICS_TOKEN", "supersecret")
	defer os.Unsetenv("METRICS_TOKEN")
	if w := runMetricsAuth("", "supersecret"); w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

// ── RequestLogger ─────────────────────────────────────────────────────────────

func TestRequestLogger_DoesNotPanic(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(RequestLogger())
	r.GET("/ping", func(c *gin.Context) { c.Status(http.StatusOK) })
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/ping", nil))
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

// ── RequestID ─────────────────────────────────────────────────────────────────

func TestRequestID_SetsHeader(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(RequestID())
	r.GET("/ping", func(c *gin.Context) { c.Status(http.StatusOK) })
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/ping", nil))
	if w.Header().Get("X-Request-ID") == "" {
		t.Error("X-Request-ID header not set")
	}
}

func TestRequestID_UniquePerRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(RequestID())
	r.GET("/ping", func(c *gin.Context) { c.Status(http.StatusOK) })

	ids := make(map[string]bool)
	for i := 0; i < 5; i++ {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/ping", nil))
		id := w.Header().Get("X-Request-ID")
		if id == "" {
			t.Error("empty X-Request-ID")
		}
		if ids[id] {
			t.Errorf("duplicate request ID: %s", id)
		}
		ids[id] = true
	}
}

// ── RequirePermission ─────────────────────────────────────────────────────────
// RequirePermission calls services.HasPermission which queries the DB for
// custom roles. The built-in admin role returns immediately without a DB query.

func TestRequirePermission_AdminPassesThroughWhenDBDown(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/", func(c *gin.Context) {
		c.Set("role", "admin")
		c.Set("tenant_id", float64(1))
		c.Next()
	}, RequirePermission("manage_firewall"), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	// admin always has permission without a DB round-trip.
	if w.Code != http.StatusOK {
		t.Errorf("admin role: status = %d, want 200", w.Code)
	}
}

func TestRequirePermission_ForbiddenWhenRoleMissing(t *testing.T) {
	// HasPermission queries the DB for non-admin roles; skip when DB absent.
	defer func() {
		if r := recover(); r != nil {
			t.Skip("DB not available — skipping non-admin permission test")
		}
	}()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/", RequirePermission("manage_firewall"), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
}

// ── RateLimit (fail-open when Redis absent) ────────────────────────────────────

func TestRateLimitAPI_FailOpen(t *testing.T) {
	// services.RDB is nil / not connected in unit tests — isAllowed fails
	// open, so requests should pass through.
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(RateLimitAPI())
	r.GET("/ping", func(c *gin.Context) { c.Status(http.StatusOK) })
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/ping", nil))
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (fail-open)", w.Code)
	}
}

func TestRateLimitAuth_FailOpen(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(RateLimitAuth())
	r.POST("/login", func(c *gin.Context) { c.Status(http.StatusOK) })
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/login", nil))
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (fail-open)", w.Code)
	}
}

// ── AgentFromContext ──────────────────────────────────────────────────────────

func TestAgentFromContextPanicsOnMissingKey(t *testing.T) {
	gin.SetMode(gin.TestMode)
	// AgentFromContext does a type assertion on the stored value.
	// A panic here is expected when no agent is set — document the behaviour.
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic when AgentKey not set, got none")
		}
	}()
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	AgentFromContext(c) // should panic: type assertion on nil interface
}
