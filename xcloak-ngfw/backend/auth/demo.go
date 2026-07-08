package auth

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const DemoTenantID = 9999
const DemoUserID = 0

// GenerateDemoJWT issues a short-lived, read-only demo token.
// The "demo" claim is checked by middleware.DemoReadOnly() to block mutations.
func GenerateDemoJWT() (string, error) {
	claims := jwt.MapClaims{
		"user_id":           DemoUserID,
		"username":          "demo-viewer",
		"role":              "viewer",
		"tenant_id":         float64(DemoTenantID),
		"is_platform_admin": false,
		"demo":              true,
		"iat":               time.Now().Unix(),
		"exp":               time.Now().Add(2 * time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(JwtSecret())
}
