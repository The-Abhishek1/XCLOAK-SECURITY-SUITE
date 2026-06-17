package services

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"xcloak-ngfw/auth"
	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
	"xcloak-ngfw/repositories"
)

// RegisterUser creates a new user.
// Only the FIRST user ever registered gets admin role.
// All subsequent registrations are forced to "analyst" regardless of what the client sends.
func RegisterUser(user models.User) error {
	// Count existing users
	var count int
	database.DB.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&count)

	if count == 0 {
		// First user — allow admin
		user.Role = "admin"
	} else {
		// All subsequent users are analysts — never trust client-provided role
		user.Role = "analyst"
	}

	hash, err := auth.HashPassword(user.Password)
	if err != nil {
		return err
	}
	user.PasswordHash = hash
	return repositories.CreateUser(user)
}

// LoginUser validates credentials and returns a JWT.
// Returns needs_2fa=true signal if the user has TOTP enabled.
func LoginUser(username, password string) (string, bool, error) {
	user, err := repositories.GetUserByUsername(username)
	if err != nil {
		return "", false, errors.New("invalid credentials")
	}

	if !auth.VerifyPassword(password, user.PasswordHash) {
		return "", false, errors.New("invalid credentials")
	}

	if !user.IsActive {
		return "", false, errors.New("account is disabled")
	}

	// Check if 2FA is enabled
	var totpEnabled bool
	database.DB.QueryRow(
		`SELECT COALESCE(totp_enabled, FALSE) FROM users WHERE id=$1`, user.ID,
	).Scan(&totpEnabled)

	if totpEnabled {
		// Return empty token — caller must complete TOTP flow
		return "", true, nil
	}

	token, err := auth.GenerateJWT(user.ID, user.Username, user.Role)
	if err != nil {
		return "", false, err
	}

	database.DB.Exec(`UPDATE users SET last_login=NOW() WHERE id=$1`, user.ID)
	LogEvent("LOGIN", "User logged in", user.Username)
	return token, false, nil
}

// ChangePassword updates a user's password after verifying the current one.
func ChangePassword(userID int, currentPassword, newPassword string) error {
	var hash string
	err := database.DB.QueryRow(
		`SELECT password_hash FROM users WHERE id=$1`, userID,
	).Scan(&hash)
	if err != nil {
		return errors.New("user not found")
	}

	if !auth.VerifyPassword(currentPassword, hash) {
		return errors.New("current password is incorrect")
	}

	if len(newPassword) < 8 {
		return errors.New("new password must be at least 8 characters")
	}

	newHash, err := auth.HashPassword(newPassword)
	if err != nil {
		return err
	}

	_, err = database.DB.Exec(
		`UPDATE users SET password_hash=$1 WHERE id=$2`, newHash, userID,
	)
	LogEvent("PASSWORD_CHANGE", "User changed password", fmt.Sprintf("user_id:%d", userID))
	return err
}

// RequestPasswordReset generates a reset token and sends an email.
// Always returns success message even if email not found (prevents user enumeration).
func RequestPasswordReset(email string) error {
	var userID int
	var username string
	err := database.DB.QueryRow(
		`SELECT id, username FROM users WHERE email=$1 AND is_active=TRUE`, email,
	).Scan(&userID, &username)

	if err != nil {
		// Don't reveal if email exists
		return nil
	}

	// Generate secure random token
	b := make([]byte, 32)
	rand.Read(b)
	token := hex.EncodeToString(b)
	expiry := time.Now().Add(1 * time.Hour)

	database.DB.Exec(`
		UPDATE users
		SET password_reset_token=$1, password_reset_expiry=$2
		WHERE id=$3
	`, token, expiry, userID)

	// Send reset email
	cfg := loadSMTPConfig()
	if cfg == nil {
		return fmt.Errorf("SMTP not configured — cannot send reset email")
	}

	subject := "XCloak — Password Reset Request"
	body := fmt.Sprintf(`Hi %s,

A password reset was requested for your XCloak account.

Click the link below to reset your password (expires in 1 hour):
http://localhost:3000/reset-password?token=%s

If you didn't request this, you can safely ignore this email.

— XCloak Security Suite
`, username, token)

	return sendEmail(cfg, []string{email}, subject, body)
}

// ResetPassword validates the reset token and sets the new password.
func ResetPassword(token, newPassword string) error {
	if len(newPassword) < 8 {
		return errors.New("password must be at least 8 characters")
	}

	var userID int
	var expiry time.Time
	err := database.DB.QueryRow(`
		SELECT id, password_reset_expiry
		FROM users
		WHERE password_reset_token=$1
	`, token).Scan(&userID, &expiry)

	if err != nil {
		return errors.New("invalid or expired reset token")
	}

	if time.Now().After(expiry) {
		return errors.New("reset token has expired — please request a new one")
	}

	newHash, err := auth.HashPassword(newPassword)
	if err != nil {
		return err
	}

	database.DB.Exec(`
		UPDATE users
		SET password_hash=$1, password_reset_token=NULL, password_reset_expiry=NULL
		WHERE id=$2
	`, newHash, userID)

	LogEvent("PASSWORD_RESET", "Password reset via email token", fmt.Sprintf("user_id:%d", userID))
	return nil
}

// GetUserProfile returns profile info for the current user.
func GetUserProfile(userID int) (map[string]interface{}, error) {
	var username, email, role string
	var isActive bool
	var lastLogin *time.Time
	var createdAt *time.Time
	var totpEnabled bool

	err := database.DB.QueryRow(`
		SELECT username, COALESCE(email,''), role, is_active,
		       last_login, created_at,
		       COALESCE(totp_enabled, FALSE)
		FROM users WHERE id=$1
	`, userID).Scan(&username, &email, &role, &isActive, &lastLogin, &createdAt, &totpEnabled)

	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"id":           userID,
		"username":     username,
		"email":        email,
		"role":         role,
		"is_active":    isActive,
		"last_login":   lastLogin,
		"created_at":   createdAt,
		"totp_enabled": totpEnabled,
	}, nil
}


// RegisterUserFromAPI is called from the API handler with plain fields.
func RegisterUserFromAPI(username, email, password string) error {
	// Count existing users to determine role
	var count int
	database.DB.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&count)

	role := "analyst"
	if count == 0 {
		role = "admin"
	}

	hash, err := auth.HashPassword(password)
	if err != nil {
		return err
	}

	_, err = database.DB.Exec(`
		INSERT INTO users (username, email, password_hash, role, is_active)
		VALUES ($1, $2, $3, $4, TRUE)
	`, username, email, hash, role)
	return err
}
