package api

import (
	"fmt"

	"github.com/gin-gonic/gin"

	"xcloak-ngfw/database"
)

// tenantIDFromContext reads the tenant_id set by RequireAuth/RequireAgentAuth.
// JWT numeric claims decode as float64, so RequireAuth's c.Set("tenant_id",
// claims["tenant_id"]) stores a float64; RequireAgentAuth's c.Set("tenant_id",
// agent.TenantID) stores a plain int. Handle both. Defaults to tenant 1 if
// missing (shouldn't happen behind RequireAuth/RequireAgentAuth, but fails
// safe to the default tenant rather than panicking).
func userIDFromContext(c *gin.Context) int {
	v, _ := c.Get("user_id")
	switch t := v.(type) {
	case int:
		return t
	case float64:
		return int(t)
	default:
		return 0
	}
}

func usernameFromContext(c *gin.Context) string {
	v, _ := c.Get("username")
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprintf("user-%d", userIDFromContext(c))
}

// agentBelongsToTenant confirms that agentID is owned by tenantID. Used by
// EDR response endpoints to prevent cross-tenant task dispatch.
func agentBelongsToTenant(agentID, tenantID int) bool {
	var count int
	database.DB.QueryRow(
		`SELECT COUNT(*) FROM agents WHERE id=$1 AND tenant_id=$2`, agentID, tenantID,
	).Scan(&count)
	return count > 0
}

func tenantIDFromContext(c *gin.Context) int {
	v, exists := c.Get("tenant_id")
	if !exists {
		return 1
	}
	switch t := v.(type) {
	case int:
		return t
	case float64:
		return int(t)
	default:
		return 1
	}
}
