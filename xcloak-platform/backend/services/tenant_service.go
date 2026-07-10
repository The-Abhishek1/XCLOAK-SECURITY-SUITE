package services

import (
	"errors"
	"fmt"
	"strings"
	"unicode"

	"xcloak-platform/auth"
	"xcloak-platform/database"
	"xcloak-platform/models"
	"xcloak-platform/repositories"
)

// CreateTenant provisions a new tenant and invites its first admin using the
// existing InviteUser flow (placeholder password hash + password-reset-token
// email, same as inviting a user into an existing tenant). If the invite
// fails — SMTP down, duplicate username/email — the just-created tenant is
// deleted rather than left behind with zero users and no way to manage it,
// mirroring InviteUser's own rollback-on-email-failure rule.
func CreateTenant(name, slug, adminUsername, adminEmail string) (*models.Tenant, error) {

	tenant, err := repositories.CreateTenant(name, slug)
	if err != nil {
		return nil, err
	}

	if err := InviteUser(adminUsername, adminEmail, "admin", tenant.ID); err != nil {
		repositories.DeleteTenant(tenant.ID)
		return nil, fmt.Errorf("tenant created but failed to invite first admin: %w", err)
	}

	LogEvent("CREATE_TENANT", fmt.Sprintf("%s (%s), first admin: %s", name, slug, adminUsername), "platform_admin")

	return tenant, nil
}

// SelfServeSignup provisions a brand-new tenant and its first admin user
// without requiring SMTP. It copies the platform's seeded Sigma rules
// (tenant_id=1) into the new tenant so it starts with a full detection library.
// On success it returns a ready-to-use JWT so the caller can set the auth
// cookie immediately — no separate login step needed.
func SelfServeSignup(orgName, slug, username, email, password string) (string, error) {
	orgName = strings.TrimSpace(orgName)
	slug = strings.TrimSpace(slug)
	username = strings.TrimSpace(username)
	email = strings.TrimSpace(email)

	if orgName == "" || slug == "" || username == "" || email == "" {
		return "", errors.New("all fields are required")
	}
	if err := ValidatePasswordComplexity(password); err != nil {
		return "", err
	}
	if !isValidSlug(slug) {
		return "", errors.New("slug must be lowercase letters, numbers, and hyphens only")
	}

	var exists bool
	database.DB.QueryRow(`SELECT EXISTS(SELECT 1 FROM users WHERE username=$1 OR email=$2)`, username, email).Scan(&exists)
	if exists {
		return "", errors.New("a user with that username or email already exists")
	}

	tenant, err := repositories.CreateTenant(orgName, slug)
	if err != nil {
		if strings.Contains(err.Error(), "unique") || strings.Contains(err.Error(), "duplicate") {
			return "", errors.New("an organization with that slug already exists")
		}
		return "", err
	}

	hash, err := auth.HashPassword(password)
	if err != nil {
		repositories.DeleteTenant(tenant.ID)
		return "", err
	}

	var userID int
	err = database.DB.QueryRow(`
		INSERT INTO users (username, email, password_hash, role, tenant_id, is_active)
		VALUES ($1, $2, $3, 'admin', $4, TRUE)
		RETURNING id
	`, username, email, hash, tenant.ID).Scan(&userID)
	if err != nil {
		repositories.DeleteTenant(tenant.ID)
		return "", err
	}

	// Copy seeded Sigma rules from tenant 1 into the new tenant.
	// Failures are non-fatal — the org still works, it just needs to configure rules manually.
	database.DB.Exec(`
		INSERT INTO sigma_rules
		  (title, description, severity, mitre_tactic, mitre_technique, mitre_name,
		   logsource_cat, logsource_prod, logsource_svc, status,
		   tags, falsepositives, references, keywords, selections, condition, enabled, tenant_id)
		SELECT
		  title, description, severity, mitre_tactic, mitre_technique, mitre_name,
		  logsource_cat, logsource_prod, logsource_svc, status,
		  tags, falsepositives, references, keywords, selections, condition, enabled, $1
		FROM sigma_rules
		WHERE tenant_id = 1
	`, tenant.ID)

	token, err := auth.GenerateJWT(userID, username, "admin", tenant.ID, false)
	if err != nil {
		return "", err
	}

	LogEvent("SELF_SERVE_SIGNUP", fmt.Sprintf("New org: %s (%s), admin: %s", orgName, slug, username), username)
	return token, nil
}

// isValidSlug allows lowercase ASCII letters, digits, and hyphens; no leading/trailing hyphens.
func isValidSlug(s string) bool {
	if len(s) == 0 || s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for _, r := range s {
		if !unicode.IsLower(r) && !unicode.IsDigit(r) && r != '-' {
			return false
		}
	}
	return true
}

func GetTenants() ([]models.Tenant, error) {
	return repositories.GetTenants()
}

func SetTenantActive(id int, active bool) error {
	return repositories.SetTenantActive(id, active)
}
