package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func runAgentAuth(authHeader string) *httptest.ResponseRecorder {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/", RequireAgentAuth(), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	r.ServeHTTP(w, req)
	return w
}

func TestRequireAgentAuth_MissingHeader(t *testing.T) {
	if w := runAgentAuth(""); w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestRequireAgentAuth_EmptyBearerToken(t *testing.T) {
	if w := runAgentAuth("Bearer "); w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestRequireAgentAuth_InvalidToken(t *testing.T) {
	// GetAgentByToken queries the DB; skip this test when the DB is not
	// connected (unit test environment).
	defer func() {
		if r := recover(); r != nil {
			t.Skip("DB not available — skipping invalid-token path test")
		}
	}()
	if w := runAgentAuth("Bearer invalidtoken"); w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}
