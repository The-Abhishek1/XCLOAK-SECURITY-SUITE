package api

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"xcloak-platform/auth"
	"xcloak-platform/database"
	"xcloak-platform/repositories"
	"xcloak-platform/services"
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

	storedSecret, err := services.EncryptTOTPSecret(secret)
	if err != nil {
		c.JSON(500, gin.H{"error": "failed to encrypt secret"})
		return
	}

	// Save secret (unverified until user confirms first code)
	_, err = database.DB.Exec(`
		UPDATE users SET totp_secret=$1, totp_enabled=FALSE, totp_verified=FALSE
		WHERE id=$2
	`, storedSecret, userID)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	qrURL := services.GenerateTOTPQRURL(fmt.Sprintf("%v", username), secret)

	c.JSON(200, gin.H{
		"secret":       secret,
		"qr_url":       qrURL,
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
	var storedSecret string
	err := database.DB.QueryRow(
		`SELECT COALESCE(totp_secret,'') FROM users WHERE id=$1`, userID,
	).Scan(&storedSecret)
	if err != nil || storedSecret == "" {
		c.JSON(400, gin.H{"error": "2FA setup not initiated — call /api/auth/2fa/setup first"})
		return
	}

	secret, err := services.DecryptTOTPSecret(storedSecret)
	if err != nil {
		c.JSON(500, gin.H{"error": "failed to decrypt secret"})
		return
	}

	if !services.ValidateTOTP(secret, body.Code) {
		c.JSON(401, gin.H{"error": "invalid TOTP code"})
		return
	}

	// Enable 2FA
	if _, err := database.DB.Exec(`
		UPDATE users SET totp_enabled=TRUE, totp_verified=TRUE WHERE id=$1
	`, userID); err != nil {
		c.JSON(500, gin.H{"error": "failed to enable 2FA: " + err.Error()})
		return
	}

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

	var storedSecret string
	if err := database.DB.QueryRow(
		`SELECT COALESCE(totp_secret,'') FROM users WHERE id=$1`, userID,
	).Scan(&storedSecret); err != nil {
		c.JSON(401, gin.H{"error": "invalid TOTP code"})
		return
	}

	secret, err := services.DecryptTOTPSecret(storedSecret)
	if err != nil {
		c.JSON(500, gin.H{"error": "failed to decrypt secret"})
		return
	}

	if !services.ValidateTOTP(secret, body.Code) {
		c.JSON(401, gin.H{"error": "invalid TOTP code"})
		return
	}

	if _, err := database.DB.Exec(`
		UPDATE users SET totp_enabled=FALSE, totp_secret=NULL, totp_verified=FALSE
		WHERE id=$1
	`, userID); err != nil {
		c.JSON(500, gin.H{"error": "failed to disable 2FA: " + err.Error()})
		return
	}

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
	userID, username, _, tenantID, err := auth.ValidateTempToken(body.TempToken)
	if err != nil {
		c.JSON(401, gin.H{"error": "invalid or expired temp token"})
		return
	}

	// Get TOTP secret and the authoritative role from the DB.
	var storedSecret string
	var dbRole string
	var isPlatformAdmin bool
	database.DB.QueryRow(
		`SELECT COALESCE(totp_secret,''), role, is_platform_admin FROM users WHERE id=$1`, userID,
	).Scan(&storedSecret, &dbRole, &isPlatformAdmin)

	secret, err := services.DecryptTOTPSecret(storedSecret)
	if err != nil {
		c.JSON(500, gin.H{"error": "failed to decrypt secret"})
		return
	}

	if !services.ValidateTOTP(secret, body.Code) {
		c.JSON(401, gin.H{"error": "invalid authenticator code"})
		return
	}

	// Issue real JWT with the role read from the database.
	token, err := auth.GenerateJWT(userID, username, dbRole, tenantID, isPlatformAdmin)
	if err != nil {
		c.JSON(500, gin.H{"error": "failed to generate token"})
		return
	}

	services.LogEvent("LOGIN_2FA", "2FA login completed", username)

	// Bring this in line with Login's success path — previously a
	// 2FA-completed login never created a sessions row (invisible to
	// Settings' Active Sessions / admin revocation), never got a refresh
	// token (forced re-auth every 8h instead of silently extending like a
	// non-2FA login), and never hit the audit log.
	go CreateSessionOnLogin(token, username, c.ClientIP(), c.GetHeader("User-Agent"), userID, tenantID)
	go repositories.CreateAuditLog("login_success", "ip:"+c.ClientIP()+" user_agent:"+c.GetHeader("User-Agent")+" via:2fa", username)

	setAuthCookie(c, token)
	if refreshToken, err := auth.GenerateRefreshToken(userID, username, dbRole, tenantID); err == nil {
		setRefreshCookie(c, refreshToken)
	}

	// Native mobile clients (Dart / okhttp) can't reliably read httpOnly
	// Set-Cookie headers — same special-case Login uses, previously missing
	// here, which meant a 2FA-completing mobile login had no way to obtain
	// a usable token at all even with a correct client-side 2FA UI.
	ua := c.GetHeader("User-Agent")
	if strings.Contains(ua, "Dart") || strings.Contains(ua, "okhttp") {
		c.JSON(http.StatusOK, gin.H{"ok": true, "token": token})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}
