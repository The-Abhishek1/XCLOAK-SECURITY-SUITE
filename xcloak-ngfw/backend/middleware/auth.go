package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"xcloak-ngfw/auth"
	"xcloak-ngfw/services"
)

func RequireAuth() gin.HandlerFunc {

	return func(c *gin.Context) {

		// 1. Try Authorization header (API keys, programmatic clients).
		tokenString := strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")

		// 2. Try the httpOnly session cookie (browser sessions).
		if tokenString == "" {
			if cookie, err := c.Request.Cookie("token"); err == nil {
				tokenString = cookie.Value
			}
		}

		// 3. Fall back to ?token= query param — kept for backward compatibility
		//    with non-browser clients that can't set headers or cookies.
		if tokenString == "" {
			tokenString = c.Query("token")
		}

		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "missing token"})
			c.Abort()
			return
		}

		// API keys (xck_...) are a separate, non-JWT auth path — direct DB
		// lookup by hash, not a token to parse. JWTs never collide with this
		// prefix (they're always two dot-separated base64 segments), so
		// there's no ambiguity. Every existing RequireRole/tenant-scoped
		// route downstream works unchanged: same context keys get set.
		if strings.HasPrefix(tokenString, "xck_") {
			key, err := services.ValidateAPIKey(tokenString)
			if err != nil {
				c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
				c.Abort()
				return
			}

			c.Set("user_id", 0)
			c.Set("username", "api-key:"+key.Label)
			c.Set("role", key.Role)
			c.Set("tenant_id", key.TenantID)
			c.Set("is_platform_admin", false)
			c.Next()
			return
		}

		// 3. Check blacklist (revoked on logout).
		if services.IsRevoked(tokenString) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "token has been revoked — please log in again"})
			c.Abort()
			return
		}

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return auth.JwtSecret(), nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			c.Abort()
			return
		}

		claims := token.Claims.(jwt.MapClaims)

		// Reject refresh tokens used as access tokens.
		if claims["type"] == "refresh" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "refresh tokens cannot be used for API access"})
			c.Abort()
			return
		}

		// Reject tokens with no tenant_id claim — e.g. a token issued before
		// multi-tenancy shipped. Without this, tenantIDFromContext's fail-safe
		// default would silently resolve every request from that token to
		// tenant 1 instead of forcing re-authentication, for the token's
		// entire remaining lifetime (up to 8h).
		if _, ok := claims["tenant_id"].(float64); !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "session invalid — please log in again"})
			c.Abort()
			return
		}

		// is_platform_admin only grants extra capability (tenant provisioning),
		// it doesn't gate tenant isolation like tenant_id does — so a
		// missing/wrong-type claim defaults safely to false rather than
		// rejecting the request.
		isPlatformAdmin, _ := claims["is_platform_admin"].(bool)

		c.Set("user_id",      claims["user_id"])
		c.Set("username",     claims["username"])
		c.Set("role",         claims["role"])
		c.Set("tenant_id",    claims["tenant_id"])
		c.Set("is_platform_admin", isPlatformAdmin)
		c.Set("token_string", tokenString) // stored for logout

		c.Next()
	}
}
