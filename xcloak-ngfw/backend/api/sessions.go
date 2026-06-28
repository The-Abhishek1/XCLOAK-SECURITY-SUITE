package api

import (
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"xcloak-ngfw/auth"
	"xcloak-ngfw/models"
	"xcloak-ngfw/repositories"
)

// GetMySessions — GET /api/auth/sessions
func GetMySessions(c *gin.Context) {
	tenantID := tenantIDFromContext(c)
	userID := userIDFromContext(c)
	sessions, err := repositories.GetActiveSessions(tenantID, userID)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"sessions": sessions})
}

// GetAllSessions — GET /api/sessions (admin: all tenant sessions)
func GetAllSessions(c *gin.Context) {
	tenantID := tenantIDFromContext(c)
	sessions, err := repositories.GetAllActiveSessions(tenantID)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"sessions": sessions})
}

// RevokeSession — DELETE /api/sessions/:id
func RevokeSession(c *gin.Context) {
	tenantID := tenantIDFromContext(c)
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid id"})
		return
	}
	if err := repositories.RevokeSessionByID(id, tenantID); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "session revoked"})
}

// GetSecurityPolicy — GET /api/security-policy
func GetSecurityPolicy(c *gin.Context) {
	tenantID := tenantIDFromContext(c)
	p, err := repositories.GetSecurityPolicy(tenantID)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, p)
}

// UpdateSecurityPolicy — PUT /api/security-policy (admin only)
func UpdateSecurityPolicy(c *gin.Context) {
	tenantID := tenantIDFromContext(c)
	var body models.TenantSecurityPolicy
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	body.TenantID = tenantID
	if body.SessionTimeoutMins < 5 {
		body.SessionTimeoutMins = 5
	}
	if body.MaxConcurrentSessions < 1 {
		body.MaxConcurrentSessions = 1
	}
	if err := repositories.UpsertSecurityPolicy(body); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "security policy updated"})
}

// GetFeedSyncLog — GET /api/threat-feeds/:id/sync-log
func GetFeedSyncLog(c *gin.Context) {
	tenantID := tenantIDFromContext(c)
	feedID, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid id"})
		return
	}
	logs, err := repositories.GetFeedSyncLog(feedID, tenantID, 20)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"logs": logs})
}

// CreateSessionOnLogin persists a session record after successful login.
func CreateSessionOnLogin(tokenStr, username, ip, ua string, userID, tenantID int) {
	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		return auth.JwtSecret(), nil
	})
	var expiresAt time.Time
	if err == nil && token.Valid {
		claims := token.Claims.(jwt.MapClaims)
		if exp, ok := claims["exp"].(float64); ok {
			expiresAt = time.Unix(int64(exp), 0)
		}
	}
	if expiresAt.IsZero() {
		expiresAt = time.Now().Add(8 * time.Hour)
	}

	uid := userID
	repositories.CreateSession(models.Session{
		TenantID:  tenantID,
		UserID:    &uid,
		Username:  username,
		IPAddress: ip,
		UserAgent: ua,
		TokenHash: tokenStr,
		ExpiresAt: expiresAt,
	})
}

// StartSessionPurger removes expired sessions once per day.
func StartSessionPurger() {
	go func() {
		for {
			now := time.Now()
			next := time.Date(now.Year(), now.Month(), now.Day()+1, 1, 0, 0, 0, now.Location())
			time.Sleep(time.Until(next))
			repositories.PurgeExpiredSessions()
		}
	}()
	log.Println("[Sessions] daily purge scheduled (01:00)")
}
