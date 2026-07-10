package api

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"xcloak-platform/services"
)

// IssueWSTicket — POST /api/ws/ticket
// Issues a 30-second single-use ticket for WebSocket connections. The browser
// uses the returned UUID as ?ticket= on the WS URL instead of ?token=, keeping
// the session JWT out of URL query strings and server access logs.
func IssueWSTicket(c *gin.Context) {
	userID   := int(c.MustGet("user_id").(float64))
	username := c.MustGet("username").(string)
	role     := c.MustGet("role").(string)
	tenantID := int(c.MustGet("tenant_id").(float64))

	ticket := uuid.New().String()

	if err := services.StoreWSTicket(ticket, services.WSTicketClaims{
		UserID:   userID,
		Username: username,
		Role:     role,
		TenantID: tenantID,
	}); err != nil {
		c.JSON(500, gin.H{"error": "failed to issue ticket"})
		return
	}

	c.JSON(200, gin.H{"ticket": ticket})
}
