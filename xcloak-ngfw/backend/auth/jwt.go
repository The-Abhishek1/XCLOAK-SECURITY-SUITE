package auth

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var JwtSecret = []byte("xcloak-super-secret-key")

func GenerateJWT(
	userID int,
	username string,
	role string,
) (string, error) {

	claims := jwt.MapClaims{
		"user_id":  userID,
		"username": username,
		"role":     role,
		"exp": time.Now().Add(
			24 * time.Hour,
		).Unix(),
	}

	token := jwt.NewWithClaims(
		jwt.SigningMethodHS256,
		claims,
	)

	return token.SignedString(
		JwtSecret,
	)
}
