package auth

import (
	"fmt"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"xcloak-ngfw/secrets"
)

// JwtSecret returns the JWT signing key — Vault KV at
// secret/data/xcloak/backend#jwt_secret when Vault is configured, else the
// JWT_SECRET env var. Panics if neither yields at least 32 chars: a
// predictable signing key is worse than refusing to start.
//
// Resolved lazily (sync.Once) rather than at package-var-init time: package
// vars initialize before main() runs godotenv.Load()/secrets.Init(), so an
// eager init here would always miss a .env-file-only JWT_SECRET and silently
// fall back to a hardcoded dev secret — which is exactly the bug this
// lazy-and-cached form fixes (the previous package-var-IIFE had this name
// and intent but ran too early to ever see the resolved value).
var (
	jwtSecretOnce  sync.Once
	jwtSecretValue []byte
)

func JwtSecret() []byte {
	jwtSecretOnce.Do(func() {
		s := secrets.Resolve("JWT_SECRET", "xcloak/backend", "jwt_secret")
		if len(s) < 32 {
			panic(fmt.Sprintf(
				"JWT secret missing or too short (%d chars, need >=32) — set JWT_SECRET "+
					"or a Vault secret/data/xcloak/backend#jwt_secret. Generate one with: openssl rand -hex 32",
				len(s)))
		}
		jwtSecretValue = []byte(s)
	})
	return jwtSecretValue
}

func GenerateJWT(userID int, username, role string, tenantID int, isPlatformAdmin bool) (string, error) {
	claims := jwt.MapClaims{
		"user_id":           userID,
		"username":          username,
		"role":              role,
		"tenant_id":         tenantID,
		"is_platform_admin": isPlatformAdmin,
		"iat":               time.Now().Unix(),
		"exp":               time.Now().Add(8 * time.Hour).Unix(), // 8h — reduced from 24h
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(JwtSecret())
}

// GenerateRefreshToken issues a longer-lived refresh token (7 days).
// Used to silently re-issue access tokens without re-login.
func GenerateRefreshToken(userID int, username, role string, tenantID int) (string, error) {
	claims := jwt.MapClaims{
		"user_id":   userID,
		"username":  username,
		"role":      role,
		"tenant_id": tenantID,
		"type":      "refresh",
		"iat":       time.Now().Unix(),
		"exp":       time.Now().Add(7 * 24 * time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(JwtSecret())
}
