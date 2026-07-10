package routes

import (
	"testing"

	"github.com/gin-gonic/gin"
)

func TestSetupRoutes_RegistersRoutes(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	// SetupRoutes registers all API endpoints; verify it doesn't panic and
	// the router has routes registered after the call.
	SetupRoutes(r)
	if len(r.Routes()) == 0 {
		t.Error("SetupRoutes: no routes registered")
	}
}
