package api

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"

	"xcloak-ngfw/auth"
	"xcloak-ngfw/database"
	"xcloak-ngfw/services"
)

// Setup2FA — POST /api/auth/2fa/setup
// Generates a TOTP secret for the current user and returns QR URL.
func Setup2FA(c *gin.Context) {
	userID, _ := c.Get("user_id")
	username, _ := c.Get("username")

	secret, err := services.GenerateTOTPSecret()
	if err != nil {
		c.JSON(500, gin.H{"error": "failed to generate secret"})
		return
	}

	// Save secret (unverified until user confirms first code)
	_, err = database.DB.Exec(`
		UPDATE users SET totp_secret=$1, totp_enabled=FALSE, totp_verified=FALSE
		WHERE id=$2
	`, secret, userID)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	qrURL := services.GenerateTOTPQRURL(fmt.Sprintf("%v", username), secret)

	c.JSON(200, gin.H{
		"secret": secret,
		"qr_url": qrURL,
		"instructions": "Scan the QR code with Google Authenticator, Authy, or any TOTP app. Then verify with a code to enable 2FA.",
	})
}

// Verify2FA — POST /api/auth/2fa/verify
// Confirms the TOTP code is correct and enables 2FA on the account.
func Verify2FA(c *gin.Context) {
	userID, _ := c.Get("user_id")

	var body struct {
		Code string `json:"code"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Code == "" {
		c.JSON(400, gin.H{"error": "code is required"})
		return
	}

	// Get stored secret
	var secret string
	err := database.DB.QueryRow(
		`SELECT COALESCE(totp_secret,'') FROM users WHERE id=$1`, userID,
	).Scan(&secret)
	if err != nil || secret == "" {
		c.JSON(400, gin.H{"error": "2FA setup not initiated — call /api/auth/2fa/setup first"})
		return
	}

	if !services.ValidateTOTP(secret, body.Code) {
		c.JSON(401, gin.H{"error": "invalid TOTP code"})
		return
	}

	// Enable 2FA
	database.DB.Exec(`
		UPDATE users SET totp_enabled=TRUE, totp_verified=TRUE WHERE id=$1
	`, userID)

	username, _ := c.Get("username")
	services.LogEvent("2FA_ENABLED", "2FA enabled", fmt.Sprintf("%v", username))

	c.JSON(200, gin.H{"message": "2FA enabled successfully"})
}

// Disable2FA — DELETE /api/auth/2fa
func Disable2FA(c *gin.Context) {
	userID, _ := c.Get("user_id")

	var body struct {
		Code string `json:"code"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Code == "" {
		c.JSON(400, gin.H{"error": "current TOTP code required to disable 2FA"})
		return
	}

	var secret string
	database.DB.QueryRow(
		`SELECT COALESCE(totp_secret,'') FROM users WHERE id=$1`, userID,
	).Scan(&secret)

	if !services.ValidateTOTP(secret, body.Code) {
		c.JSON(401, gin.H{"error": "invalid TOTP code"})
		return
	}

	database.DB.Exec(`
		UPDATE users SET totp_enabled=FALSE, totp_secret=NULL, totp_verified=FALSE
		WHERE id=$1
	`, userID)

	username, _ := c.Get("username")
	services.LogEvent("2FA_DISABLED", "2FA disabled", fmt.Sprintf("%v", username))
	c.JSON(200, gin.H{"message": "2FA disabled"})
}

// Get2FAStatus — GET /api/auth/2fa/status
func Get2FAStatus(c *gin.Context) {
	userID, _ := c.Get("user_id")
	var enabled bool
	database.DB.QueryRow(
		`SELECT COALESCE(totp_enabled,FALSE) FROM users WHERE id=$1`, userID,
	).Scan(&enabled)
	c.JSON(200, gin.H{"enabled": enabled})
}

// LoginWith2FA — POST /api/auth/login
// Extended login: if 2FA enabled, returns needs_2fa=true and a temp token.
// Client then calls /api/auth/login/2fa with the TOTP code.
func LoginWith2FA(c *gin.Context) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	token, err := services.LoginUser(req.Username, req.Password)
	if err != nil {
		c.JSON(401, gin.H{"error": "invalid credentials"})
		return
	}

	// Check if user has 2FA enabled
	var userID int
	var totpEnabled bool
	database.DB.QueryRow(
		`SELECT id, COALESCE(totp_enabled,FALSE) FROM users WHERE username=$1`, req.Username,
	).Scan(&userID, &totpEnabled)

	if !totpEnabled {
		// Normal login — return token immediately
		c.JSON(http.StatusOK, gin.H{"token": token})
		return
	}

	// 2FA required — return a short-lived temp token
	// Client must call /api/auth/login/2fa to exchange for real token
	tempToken, _ := auth.GenerateTempToken(userID, req.Username)
	c.JSON(200, gin.H{
		"needs_2fa":  true,
		"temp_token": tempToken,
		"message":    "Enter your authenticator code to complete login",
	})
}

// CompleteTOTPLogin — POST /api/auth/login/2fa
// Validates the TOTP code against the temp token and returns the real JWT.
func CompleteTOTPLogin(c *gin.Context) {
	var body struct {
		TempToken string `json:"temp_token"`
		Code      string `json:"code"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	// Validate temp token
	userID, username, role, err := auth.ValidateTempToken(body.TempToken)
	if err != nil {
		c.JSON(401, gin.H{"error": "invalid or expired temp token"})
		return
	}

	// Get TOTP secret
	var secret string
	database.DB.QueryRow(
		`SELECT COALESCE(totp_secret,'') FROM users WHERE id=$1`, userID,
	).Scan(&secret)

	if !services.ValidateTOTP(secret, body.Code) {
		c.JSON(401, gin.H{"error": "invalid authenticator code"})
		return
	}

	// Issue real JWT
	token, err := auth.GenerateJWT(userID, username, role)
	if err != nil {
		c.JSON(500, gin.H{"error": "failed to generate token"})
		return
	}

	services.LogEvent("LOGIN_2FA", "2FA login completed", username)
	c.JSON(200, gin.H{"token": token})
}
