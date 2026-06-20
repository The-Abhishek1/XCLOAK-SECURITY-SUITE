package auth

import (
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// jwtSecret loads the JWT signing key from JWT_SECRET env var.
// Panics on startup if not set — intentional, fail-fast is safer than running
// with a predictable secret.
func jwtSecret() []byte {
	s := os.Getenv("JWT_SECRET")
	if s == "" {
		panic("JWT_SECRET environment variable is not set — refusing to start. " +
			"Generate one with: openssl rand -hex 32")
	}
	if len(s) < 32 {
		panic(fmt.Sprintf("JWT_SECRET is too short (%d chars) — minimum 32 characters required", len(s)))
	}
	return []byte(s)
}

// JwtSecret is the package-level accessor used by middleware.
// Evaluated once at first call (after env is loaded).
var JwtSecret = func() []byte {
	// Lazy init so tests can set the env var before first use.
	s := os.Getenv("JWT_SECRET")
	if s == "" {
		// Fallback warning — development only.
		fmt.Println("[WARN] JWT_SECRET not set — using insecure default. DO NOT use in production.")
		return []byte("dev-insecure-secret-change-me-in-production-32c")
	}
	return []byte(s)
}()

func GenerateJWT(userID int, username, role string, tenantID int) (string, error) {
	claims := jwt.MapClaims{
		"user_id":   userID,
		"username":  username,
		"role":      role,
		"tenant_id": tenantID,
		"iat":       time.Now().Unix(),
		"exp":       time.Now().Add(8 * time.Hour).Unix(), // 8h — reduced from 24h
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(JwtSecret)
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
	return token.SignedString(JwtSecret)
}
