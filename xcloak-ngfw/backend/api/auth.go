package api

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"

	"xcloak-ngfw/auth"
	"xcloak-ngfw/database"
	"xcloak-ngfw/services"
)

// Login — POST /api/auth/login
// Returns token directly, or needs_2fa+temp_token if TOTP is enabled.
func Login(c *gin.Context) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	token, needs2FA, err := services.LoginUser(req.Username, req.Password)
	if err != nil {
		c.JSON(401, gin.H{"error": "invalid credentials"})
		return
	}

	if needs2FA {
		// Look up user ID for temp token
		var userID, tenantID int
		var role string
		database.DB.QueryRow(
			`SELECT id, role, tenant_id FROM users WHERE username=$1`, req.Username,
		).Scan(&userID, &role, &tenantID)

		tempToken, _ := auth.GenerateTempToken(userID, req.Username, role, tenantID)
		c.JSON(200, gin.H{
			"needs_2fa":  true,
			"temp_token": tempToken,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": token})
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

	if len(user.Password) < 8 {
		c.JSON(400, gin.H{"error": "password must be at least 8 characters"})
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
	userID := int(c.MustGet("user_id").(float64))

	profile, err := services.GetUserProfile(userID)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, profile)
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
