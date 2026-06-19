package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func runRequireRole(requiredRole string, setRole any, roleIsSet bool) *httptest.ResponseRecorder {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/protected", func(c *gin.Context) {
		if roleIsSet {
			c.Set("role", setRole)
		}
		c.Next()
	}, RequireRole(requiredRole), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	router.ServeHTTP(w, req)
	return w
}

func TestRequireRole_AllowsMatchingRole(t *testing.T) {
	w := runRequireRole("admin", "admin", true)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

func TestRequireRole_BlocksMismatchedRole(t *testing.T) {
	w := runRequireRole("admin", "analyst", true)
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
}

func TestRequireRole_BlocksMissingRole(t *testing.T) {
	w := runRequireRole("admin", nil, false)
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
}
