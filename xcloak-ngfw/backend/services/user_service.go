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

	var tenantActive bool
	if err := database.DB.QueryRow(
		`SELECT is_active FROM tenants WHERE id=$1`, user.TenantID,
	).Scan(&tenantActive); err != nil || !tenantActive {
		return "", false, errors.New("this tenant has been suspended")
	}

	// Check if 2FA is enabled. A failed/errored query must NOT be treated as
	// "2FA disabled" — that would silently issue a real working JWT and
	// bypass the TOTP requirement on a transient DB hiccup.
	var totpEnabled bool
	if err := database.DB.QueryRow(
		`SELECT COALESCE(totp_enabled, FALSE) FROM users WHERE id=$1`, user.ID,
	).Scan(&totpEnabled); err != nil {
		return "", false, errors.New("login temporarily unavailable — please try again")
	}

	if totpEnabled {
		// Return empty token — caller must complete TOTP flow
		return "", true, nil
	}

	token, err := auth.GenerateJWT(user.ID, user.Username, user.Role, user.TenantID, user.IsPlatformAdmin)
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

// InviteUser creates a new user scoped to tenantID and emails them a
// set-password link (reuses the same password_reset_token/email plumbing as
// RequestPasswordReset — there's no functional difference between "set your
// password for the first time" and "reset your password" once a token
// exists). The account gets an unusable random password hash until the
// invitee follows the link, so it can't be logged into in the meantime.
func InviteUser(username, email, role string, tenantID int) error {
	if !IsValidRole(role, tenantID) {
		return errors.New("invalid role — must be admin, analyst, viewer, or an existing custom role")
	}

	var exists bool
	database.DB.QueryRow(
		`SELECT EXISTS(SELECT 1 FROM users WHERE username=$1 OR email=$2)`, username, email,
	).Scan(&exists)
	if exists {
		return errors.New("a user with that username or email already exists")
	}

	// Check SMTP before creating the row — an invited user with no email
	// sent and no API to retrieve their token would be a permanently
	// orphaned, unusable account.
	cfg := loadSMTPConfig()
	if cfg == nil {
		return fmt.Errorf("SMTP not configured — cannot send invite email")
	}

	placeholder := make([]byte, 32)
	rand.Read(placeholder)
	hash, err := auth.HashPassword(hex.EncodeToString(placeholder))
	if err != nil {
		return err
	}

	var userID int
	err = database.DB.QueryRow(`
		INSERT INTO users (username, email, password_hash, role, tenant_id, is_active)
		VALUES ($1, $2, $3, $4, $5, TRUE)
		RETURNING id
	`, username, email, hash, role, tenantID).Scan(&userID)
	if err != nil {
		return err
	}

	b := make([]byte, 32)
	rand.Read(b)
	token := hex.EncodeToString(b)
	expiry := time.Now().Add(24 * time.Hour)

	database.DB.Exec(`
		UPDATE users
		SET password_reset_token=$1, password_reset_expiry=$2
		WHERE id=$3
	`, token, expiry, userID)

	subject := "XCloak — You've been invited"
	body := fmt.Sprintf(`Hi %s,

You've been invited to join XCloak Security Suite as a %s.

Click the link below to set your password (expires in 24 hours):
http://localhost:3000/reset-password?token=%s

— XCloak Security Suite
`, username, role, token)

	if err := sendEmail(cfg, []string{email}, subject, body); err != nil {
		// Don't leave a password-less account stranded with no way to claim
		// it — roll back so the admin can safely retry the invite.
		database.DB.Exec(`DELETE FROM users WHERE id=$1`, userID)
		return fmt.Errorf("failed to send invite email: %w", err)
	}

	LogEvent("INVITE_USER", "Invited "+username+" ("+role+")", fmt.Sprintf("tenant_id:%d", tenantID))
	return nil
}

// InviteUserDirectly creates a user account without sending an email — used
// by OIDC JIT provisioning where the user authenticates via IdP and doesn't
// need a password-reset link to claim their account.
func InviteUserDirectly(username, email, role string, tenantID int) error {
	placeholder := make([]byte, 32)
	rand.Read(placeholder)
	hash, err := auth.HashPassword(hex.EncodeToString(placeholder))
	if err != nil {
		return err
	}
	_, err = database.DB.Exec(`
		INSERT INTO users (username, email, password_hash, role, tenant_id, is_active)
		VALUES ($1, $2, $3, $4, $5, TRUE)
		ON CONFLICT (username) DO UPDATE SET username = EXCLUDED.username || '_' || floor(random()*9000+1000)::text
	`, username, email, hash, role, tenantID)
	if err != nil {
		return err
	}
	LogEvent("JIT_PROVISION", "JIT provisioned "+email+" as "+role, fmt.Sprintf("tenant_id:%d", tenantID))
	return nil
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

// GetUserProfile returns profile info for the current user including their
// tenant name and slug — the frontend needs both to show the org context in
// the sidebar and to build the SSO test-login URL.
func GetUserProfile(userID int) (map[string]interface{}, error) {
	var username, email, role string
	var isActive, isPlatformAdmin bool
	var lastLogin *time.Time
	var createdAt *time.Time
	var totpEnabled bool
	var tenantID int
	var tenantName, tenantSlug string

	err := database.DB.QueryRow(`
		SELECT u.username, COALESCE(u.email,''), u.role, u.is_active,
		       u.last_login, u.created_at,
		       COALESCE(u.totp_enabled, FALSE), u.is_platform_admin,
		       u.tenant_id, t.name, t.slug
		FROM users u
		JOIN tenants t ON t.id = u.tenant_id
		WHERE u.id=$1
	`, userID).Scan(
		&username, &email, &role, &isActive, &lastLogin, &createdAt,
		&totpEnabled, &isPlatformAdmin, &tenantID, &tenantName, &tenantSlug,
	)

	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"id":                userID,
		"username":          username,
		"email":             email,
		"role":              role,
		"is_active":         isActive,
		"last_login":        lastLogin,
		"created_at":        createdAt,
		"totp_enabled":      totpEnabled,
		"is_platform_admin": isPlatformAdmin,
		"tenant_id":         tenantID,
		"tenant_name":       tenantName,
		"tenant_slug":       tenantSlug,
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
