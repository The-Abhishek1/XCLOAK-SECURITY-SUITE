package api

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"xcloak-platform/auth"
	"xcloak-platform/database"
	"xcloak-platform/repositories"
	"xcloak-platform/services"
)

// Login — POST /api/auth/login
// Accepts { username, password } or { email, password } interchangeably.
// Returns token directly, or needs_2fa+temp_token if TOTP is enabled.
func Login(c *gin.Context) {
	var req struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	// Allow login with either username or email field.
	if req.Username == "" {
		req.Username = req.Email
	}

	if services.IsUsernameLocked(req.Username) {
		c.JSON(429, gin.H{"error": "account temporarily locked due to too many failed login attempts — try again in 15 minutes"})
		return
	}

	token, needs2FA, err := services.LoginUser(req.Username, req.Password)
	if err != nil {
		services.RecordLoginFailure(req.Username)
		c.JSON(401, gin.H{"error": "invalid credentials"})
		return
	}
	services.ClearLoginFailures(req.Username)

	var userID, tenantID int
	var role string
	database.DB.QueryRow(
		`SELECT id, role, tenant_id FROM users WHERE username=$1 OR email=$1`, req.Username,
	).Scan(&userID, &role, &tenantID)

	if needs2FA {
		tempToken, _ := auth.GenerateTempToken(userID, req.Username, role, tenantID)
		c.JSON(200, gin.H{
			"needs_2fa":  true,
			"temp_token": tempToken,
		})
		return
	}

	// Persist session record (async — never delays the login response).
	go CreateSessionOnLogin(token, req.Username, c.ClientIP(), c.GetHeader("User-Agent"), userID, tenantID)

	setAuthCookie(c, token)

	// Issue a 7-day refresh token so browser sessions can silently extend
	// themselves past the 8-hour access token lifetime without re-login.
	// The refresh cookie is path-scoped to /api/auth/refresh so it is never
	// sent to other endpoints.
	if refreshToken, err := auth.GenerateRefreshToken(userID, req.Username, role, tenantID); err == nil {
		setRefreshCookie(c, refreshToken)
	}

	// Native mobile clients (Dart / okhttp) cannot reliably read httpOnly
	// Set-Cookie headers — return the raw token in the body so they can use
	// it as a Bearer token. Browser clients ignore this extra field.
	ua := c.GetHeader("User-Agent")
	if strings.Contains(ua, "Dart") || strings.Contains(ua, "okhttp") {
		c.JSON(http.StatusOK, gin.H{"ok": true, "token": token})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// RefreshToken — POST /api/auth/refresh
// Validates the httpOnly refresh_token cookie and issues a fresh access token.
// The refresh token itself is rotated on success to bound the window in which
// a stolen cookie remains usable.
func RefreshToken(c *gin.Context) {
	var refreshStr string

	// Browser sends the refresh_token cookie; mobile clients send it as Bearer.
	if cookie, err := c.Request.Cookie("refresh_token"); err == nil {
		refreshStr = cookie.Value
	}
	if refreshStr == "" {
		refreshStr = strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
	}
	if refreshStr == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "refresh token required"})
		return
	}

	if services.IsRevoked(refreshStr) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "refresh token has been revoked"})
		return
	}

	tok, err := jwt.Parse(refreshStr, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return auth.JwtSecret(), nil
	})
	if err != nil || !tok.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired refresh token"})
		return
	}

	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok || claims["type"] != "refresh" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "not a refresh token"})
		return
	}

	userID := int(claims["user_id"].(float64))
	username, _ := claims["username"].(string)
	role, _ := claims["role"].(string)
	tenantID := int(claims["tenant_id"].(float64))

	// Verify the user and tenant are still active before issuing a new token.
	var isActive bool
	var tenantActive bool
	if err := database.DB.QueryRow(
		`SELECT is_active FROM users WHERE id=$1`, userID,
	).Scan(&isActive); err != nil || !isActive {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "account no longer active"})
		return
	}
	if err := database.DB.QueryRow(
		`SELECT is_active FROM tenants WHERE id=$1`, tenantID,
	).Scan(&tenantActive); err != nil || !tenantActive {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant has been suspended"})
		return
	}

	// Revoke old refresh token and issue a fresh one (token rotation).
	expClaim, _ := claims["exp"].(float64)
	oldExpiry := time.Unix(int64(expClaim), 0)
	services.RevokeToken(refreshStr, oldExpiry)

	newToken, err := auth.GenerateJWT(userID, username, role, tenantID, false)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to issue token"})
		return
	}

	setAuthCookie(c, newToken)

	if newRefresh, err := auth.GenerateRefreshToken(userID, username, role, tenantID); err == nil {
		setRefreshCookie(c, newRefresh)
	}

	ua := c.GetHeader("User-Agent")
	if strings.Contains(ua, "Dart") || strings.Contains(ua, "okhttp") {
		c.JSON(http.StatusOK, gin.H{"ok": true, "token": newToken})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// Register — POST /api/auth/register
// First user gets admin. All subsequent users get analyst role.
func Register(c *gin.Context) {
	var user struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	if err := services.ValidatePasswordComplexity(user.Password); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	m := struct {
		Username     string
		Email        string
		Password     string
		PasswordHash string
		Role         string
		IsActive     bool
	}{
		Username: user.Username,
		Email:    user.Email,
		Password: user.Password,
		IsActive: true,
	}

	if err := services.RegisterUserFromAPI(m.Username, m.Email, m.Password); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, gin.H{"message": "account created successfully"})
}

// ForgotPassword — POST /api/auth/forgot-password
func ForgotPassword(c *gin.Context) {
	var body struct {
		Email string `json:"email"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Email == "" {
		c.JSON(400, gin.H{"error": "email is required"})
		return
	}

	// Always return success — prevents email enumeration
	services.RequestPasswordReset(body.Email)
	c.JSON(200, gin.H{
		"message": "If an account with that email exists, you will receive a reset link shortly.",
	})
}

// ResetPassword — POST /api/auth/reset-password
func ResetPassword(c *gin.Context) {
	var body struct {
		Token       string `json:"token"`
		NewPassword string `json:"new_password"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	if err := services.ResetPassword(body.Token, body.NewPassword); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, gin.H{"message": "password reset successfully — you can now log in"})
}

// ChangePassword — POST /api/auth/change-password
func ChangePassword(c *gin.Context) {
	userID := int(c.MustGet("user_id").(float64))

	var body struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	if err := services.ChangePassword(userID, body.CurrentPassword, body.NewPassword); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, gin.H{"message": "password changed successfully"})
}

// GetProfile — GET /api/auth/profile
func GetProfile(c *gin.Context) {
	userID := userIDFromContext(c)

	// API key auth: user_id is 0 and username is "api-key:<label>".
	// Return a synthetic profile from context rather than hitting the DB.
	if userID == 0 {
		role, _ := c.Get("role")
		username, _ := c.Get("username")
		tenantID := tenantIDFromContext(c)
		c.JSON(200, gin.H{
			"id":                0,
			"username":          username,
			"email":             username, // label serves as display name
			"role":              role,
			"is_active":         true,
			"is_platform_admin": false,
			"tenant_id":         tenantID,
			"totp_enabled":      false,
		})
		return
	}

	profile, err := services.GetUserProfile(userID)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, profile)
}

// SSODiscover — GET /api/auth/sso-discover?email=user@acme.com
// Unauthenticated — used by the login page to auto-detect SSO when the user
// types their email. Extracts the domain, looks it up in tenant_domains, and
// returns the slug and (optional) button label so the login page can skip the
// slug-entry step and go straight to the IdP redirect.
func SSODiscover(c *gin.Context) {
	email := c.Query("email")
	domain := ""
	for i := len(email) - 1; i >= 0; i-- {
		if email[i] == '@' {
			domain = email[i+1:]
			break
		}
	}
	if domain == "" {
		c.JSON(400, gin.H{"error": "invalid email"})
		return
	}

	tenant, err := repositories.GetTenantByDomain(domain)
	if err != nil || !tenant.IsActive {
		c.JSON(404, gin.H{"error": "no SSO mapping found for this email domain"})
		return
	}

	label, ssoEnabled := services.GetOIDCPublicConfig(tenant.ID)
	if !ssoEnabled {
		c.JSON(404, gin.H{"error": "SSO not configured for this organization"})
		return
	}

	if label == "" {
		label = "Sign in with " + tenant.Name
	}
	c.JSON(200, gin.H{
		"slug":         tenant.Slug,
		"tenant_name":  tenant.Name,
		"button_label": label,
	})
}

// UpdateProfile — PATCH /api/auth/profile
func UpdateProfile(c *gin.Context) {
	userID := int(c.MustGet("user_id").(float64))

	var body struct {
		Email string `json:"email"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	_, err := database.DB.Exec(
		`UPDATE users SET email=$1 WHERE id=$2`, body.Email, userID,
	)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	username, _ := c.Get("username")
	services.LogEvent("PROFILE_UPDATE", "Email updated", fmt.Sprintf("%v", username))
	c.JSON(200, gin.H{"message": "profile updated"})
}
