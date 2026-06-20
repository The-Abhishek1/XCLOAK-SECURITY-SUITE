package services

import (
	"fmt"

	"xcloak-ngfw/models"
	"xcloak-ngfw/repositories"
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

func GetTenants() ([]models.Tenant, error) {
	return repositories.GetTenants()
}

func SetTenantActive(id int, active bool) error {
	return repositories.SetTenantActive(id, active)
}
