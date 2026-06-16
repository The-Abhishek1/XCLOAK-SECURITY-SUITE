package auth

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// GenerateTempToken issues a 5-minute token used during 2FA login flow.
// It can't be used for API access (type="temp").
func GenerateTempToken(userID int, username string) (string, error) {
	claims := jwt.MapClaims{
		"user_id":  userID,
		"username": username,
		"type":     "temp",
		"exp":      time.Now().Add(5 * time.Minute).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(JwtSecret)
}

// ValidateTempToken parses a temp token and returns user info.
func ValidateTempToken(tokenStr string) (userID int, username, role string, err error) {
	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		return JwtSecret, nil
	})
	if err != nil || !token.Valid {
		return 0, "", "", fmt.Errorf("invalid token")
	}
	claims := token.Claims.(jwt.MapClaims)
	if claims["type"] != "temp" {
		return 0, "", "", fmt.Errorf("not a temp token")
	}
	if uid, ok := claims["user_id"].(float64); ok {
		userID = int(uid)
	}
	username, _ = claims["username"].(string)
	role, _ = claims["role"].(string)
	return userID, username, role, nil
}
