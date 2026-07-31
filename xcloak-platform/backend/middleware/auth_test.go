package middleware

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"xcloak-platform/auth"
	"xcloak-platform/repositories"
	"xcloak-platform/services"
)

func TestMain(m *testing.M) {
	// JwtSecret() panics if unset (intentional — see auth/jwt.go), so tests
	// must set one, same as production. Resolved once via sync.Once for this
	// whole test binary, so this must run before the first test.
	os.Setenv("JWT_SECRET", "test-jwt-secret-at-least-32-characters-long")

	// RequireAuth calls services.IsRevoked, which dereferences services.RDB —
	// it must be initialized even if Redis isn't reachable in this test run
	// (IsRevoked fails open on a connection error, so tests still pass).
	services.InitRedis()
	os.Exit(m.Run())
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
	tokenStr, err := auth.GenerateJWT(1, "alice", "admin", 1, false)
	if err != nil {
		t.Fatalf("GenerateJWT: %v", err)
	}

	w := runRequireAuth("Bearer " + tokenStr)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

// ── httpOnly cookie auth path ─────────────────────────────────────────────────

func runRequireAuthWithCookie(cookieValue string) *httptest.ResponseRecorder {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/protected", RequireAuth(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	if cookieValue != "" {
		req.AddCookie(&http.Cookie{Name: "token", Value: cookieValue})
	}
	router.ServeHTTP(w, req)
	return w
}

func TestRequireAuth_AcceptsValidTokenCookie(t *testing.T) {
	tokenStr, err := auth.GenerateJWT(2, "bob", "analyst", 1, false)
	if err != nil {
		t.Fatalf("GenerateJWT: %v", err)
	}

	w := runRequireAuthWithCookie(tokenStr)
	if w.Code != http.StatusOK {
		t.Errorf("cookie auth: status = %d, want 200", w.Code)
	}
}

func TestRequireAuth_RejectsInvalidTokenCookie(t *testing.T) {
	w := runRequireAuthWithCookie("not-a-real-jwt")
	if w.Code != http.StatusUnauthorized {
		t.Errorf("invalid cookie token: status = %d, want 401", w.Code)
	}
}

func TestRequireAuth_RejectsQueryParamToken(t *testing.T) {
	// ?token= query param must no longer be accepted — callers must use
	// Authorization header or httpOnly cookie.
	validToken, err := auth.GenerateJWT(5, "eve", "analyst", 1, false)
	if err != nil {
		t.Fatalf("GenerateJWT: %v", err)
	}

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/protected", RequireAuth(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/protected?token="+validToken, nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("?token= query param should be rejected, got %d (want 401)", w.Code)
	}
}

// TestRequireAuth_RejectsHashRevokedSession exercises the admin-initiated
// revocation path (Settings' "Revoke Session", force_logout,
// concurrent-session-limit enforcement) — these never have the raw JWT on
// hand, only its sha256 hash (sessions.token_hash), so they blacklist by
// hash via services.RevokeTokenHash rather than the raw-token path
// services.RevokeToken (self-logout) uses. A valid token must be accepted
// before revocation and rejected immediately after — without needing the
// token to expire naturally.
func TestRequireAuth_RejectsHashRevokedSession(t *testing.T) {
	tokenStr, err := auth.GenerateJWT(4, "dana", "analyst", 1, false)
	if err != nil {
		t.Fatalf("GenerateJWT: %v", err)
	}

	if w := runRequireAuth("Bearer " + tokenStr); w.Code != http.StatusOK {
		t.Fatalf("before revocation: status = %d, want 200", w.Code)
	}

	hash := repositories.HashToken(tokenStr)
	services.RevokeTokenHash(hash, time.Now().Add(time.Hour))

	w := runRequireAuth("Bearer " + tokenStr)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("after revocation: status = %d, want 401", w.Code)
	}
}

func TestRequireAuth_AuthHeaderWinsCookieLoses(t *testing.T) {
	// Authorization header is checked before the cookie — a valid header token
	// plus an invalid cookie must still succeed (header wins, cookie never tried).
	validToken, err := auth.GenerateJWT(3, "charlie", "admin", 1, false)
	if err != nil {
		t.Fatalf("GenerateJWT: %v", err)
	}

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/protected", RequireAuth(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+validToken)
	req.AddCookie(&http.Cookie{Name: "token", Value: "invalid-garbage"})
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("header+bad-cookie: status = %d, want 200 (header should win)", w.Code)
	}
}
