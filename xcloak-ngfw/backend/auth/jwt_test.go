package auth

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func parse(t *testing.T, tokenStr string) jwt.MapClaims {
	t.Helper()
	token, err := jwt.Parse(tokenStr, func(*jwt.Token) (interface{}, error) {
		return JwtSecret, nil
	})
	if err != nil {
		t.Fatalf("parsing token: %v", err)
	}
	if !token.Valid {
		t.Fatal("token reported invalid")
	}
	return token.Claims.(jwt.MapClaims)
}

func TestGenerateJWT(t *testing.T) {
	tokenStr, err := GenerateJWT(42, "alice", "admin")
	if err != nil {
		t.Fatalf("GenerateJWT: %v", err)
	}

	claims := parse(t, tokenStr)

	if got := claims["username"]; got != "alice" {
		t.Errorf("username = %v, want alice", got)
	}
	if got := claims["role"]; got != "admin" {
		t.Errorf("role = %v, want admin", got)
	}
	if claims["type"] != nil {
		t.Errorf("access token should not have a type claim, got %v", claims["type"])
	}

	exp := time.Unix(int64(claims["exp"].(float64)), 0)
	if time.Until(exp) > 8*time.Hour || time.Until(exp) < 7*time.Hour {
		t.Errorf("access token expiry = %v, want ~8h from now", time.Until(exp))
	}
}

func TestGenerateRefreshToken(t *testing.T) {
	tokenStr, err := GenerateRefreshToken(42, "alice", "admin")
	if err != nil {
		t.Fatalf("GenerateRefreshToken: %v", err)
	}

	claims := parse(t, tokenStr)

	if claims["type"] != "refresh" {
		t.Errorf("type = %v, want refresh", claims["type"])
	}

	exp := time.Unix(int64(claims["exp"].(float64)), 0)
	if time.Until(exp) < 6*24*time.Hour {
		t.Errorf("refresh token expiry = %v, want ~7d from now", time.Until(exp))
	}
}

func TestGenerateAgentJWT(t *testing.T) {
	tokenStr, err := GenerateAgentJWT(7)
	if err != nil {
		t.Fatalf("GenerateAgentJWT: %v", err)
	}

	claims := parse(t, tokenStr)

	if got := claims["role"]; got != "agent" {
		t.Errorf("role = %v, want agent", got)
	}
	if got := int(claims["agent_id"].(float64)); got != 7 {
		t.Errorf("agent_id = %v, want 7", got)
	}
}

func TestTempToken_RoundTrip(t *testing.T) {
	tokenStr, err := GenerateTempToken(1, "bob", "analyst")
	if err != nil {
		t.Fatalf("GenerateTempToken: %v", err)
	}

	userID, username, role, err := ValidateTempToken(tokenStr)
	if err != nil {
		t.Fatalf("ValidateTempToken: %v", err)
	}
	if userID != 1 || username != "bob" || role != "analyst" {
		t.Errorf("got (%d, %s, %s), want (1, bob, analyst)", userID, username, role)
	}
}

func TestValidateTempToken_RejectsNonTempToken(t *testing.T) {
	// A normal access token must not be usable as a temp 2FA token.
	tokenStr, _ := GenerateJWT(1, "bob", "analyst")

	if _, _, _, err := ValidateTempToken(tokenStr); err == nil {
		t.Error("expected error validating a non-temp token as temp, got nil")
	}
}

func TestValidateTempToken_RejectsGarbage(t *testing.T) {
	if _, _, _, err := ValidateTempToken("not-a-jwt"); err == nil {
		t.Error("expected error parsing garbage token, got nil")
	}
}
