package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"xcloak-ngfw/auth"
	"xcloak-ngfw/services"
)

func TestMain(m *testing.M) {
	// RequireAuth calls services.IsRevoked, which dereferences services.RDB —
	// it must be initialized even if Redis isn't reachable in this test run
	// (IsRevoked fails open on a connection error, so tests still pass).
	services.InitRedis()
	m.Run()
}

func runRequireAuth(authHeader string) *httptest.ResponseRecorder {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/protected", RequireAuth(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	router.ServeHTTP(w, req)
	return w
}

func TestRequireAuth_RejectsMissingToken(t *testing.T) {
	w := runRequireAuth("")
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestRequireAuth_RejectsGarbageToken(t *testing.T) {
	w := runRequireAuth("Bearer not-a-real-jwt")
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestRequireAuth_RejectsRefreshTokenAsAccessToken(t *testing.T) {
	tokenStr, err := auth.GenerateRefreshToken(1, "alice", "admin", 1)
	if err != nil {
		t.Fatalf("GenerateRefreshToken: %v", err)
	}

	w := runRequireAuth("Bearer " + tokenStr)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestRequireAuth_AcceptsValidAccessToken(t *testing.T) {
	tokenStr, err := auth.GenerateJWT(1, "alice", "admin", 1)
	if err != nil {
		t.Fatalf("GenerateJWT: %v", err)
	}

	w := runRequireAuth("Bearer " + tokenStr)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}
