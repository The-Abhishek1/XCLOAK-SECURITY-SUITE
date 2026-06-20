package repositories

import (
	"errors"

	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
)

// ErrTenantNotFound is returned when a tenant id doesn't exist.
var ErrTenantNotFound = errors.New("tenant not found")

// CreateTenant inserts a new tenant. Relies on the existing UNIQUE(slug)
// constraint for duplicate rejection.
func CreateTenant(name, slug string) (*models.Tenant, error) {

	var t models.Tenant
	t.Name = name
	t.Slug = slug

	err := database.DB.QueryRow(`
		INSERT INTO tenants (name, slug)
		VALUES ($1, $2)
		RETURNING id, is_active, created_at
	`, name, slug).Scan(&t.ID, &t.IsActive, &t.CreatedAt)

	if err != nil {
		return nil, err
	}

	return &t, nil
}

// GetTenants returns every tenant — this IS the platform-level resource, so
// unlike every other GetX(tenantID)/GetAllX() pair in this codebase, there's
// no tenant-scoped variant: only a platform admin can reach this at all.
// Includes a user_count per tenant for the admin view.
func GetTenants() ([]models.Tenant, error) {

	rows, err := database.DB.Query(`
		SELECT t.id, t.name, t.slug, t.is_active, t.created_at,
		       (SELECT COUNT(*) FROM users u WHERE u.tenant_id = t.id) AS user_count
		FROM tenants t
		ORDER BY t.created_at DESC
	`)

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tenants []models.Tenant
	for rows.Next() {
		var t models.Tenant
		if err := rows.Scan(&t.ID, &t.Name, &t.Slug, &t.IsActive, &t.CreatedAt, &t.UserCount); err == nil {
			tenants = append(tenants, t)
		}
	}

	return tenants, nil
}

// GetTenantBySlug resolves a tenant from the slug a user types into the SSO
// login form — needed before we know the tenant_id, to look up its OIDC config.
func GetTenantBySlug(slug string) (*models.Tenant, error) {

	var t models.Tenant

	err := database.DB.QueryRow(`
		SELECT id, name, slug, is_active, created_at
		FROM tenants WHERE slug = $1
	`, slug).Scan(&t.ID, &t.Name, &t.Slug, &t.IsActive, &t.CreatedAt)

	if err != nil {
		return nil, err
	}

	return &t, nil
}

// DeleteTenant removes a tenant row outright — only used to roll back a
// just-created tenant whose first-admin invite failed to send (see
// services.CreateTenant). Relies on the tenant having zero users/agents/etc.
// at this point (it was created moments ago in the same request), so there's
// nothing else referencing it yet.
func DeleteTenant(id int) error {
	_, err := database.DB.Exec(`DELETE FROM tenants WHERE id=$1`, id)
	return err
}

// SetTenantActive suspends/reactivates a tenant. Suspension is enforced at
// login (services.LoginUser) — already-issued JWTs for that tenant remain
// valid until they expire, same caveat as user deactivation.
func SetTenantActive(id int, active bool) error {
	tag, err := database.DB.Exec(`UPDATE tenants SET is_active=$1 WHERE id=$2`, active, id)
	if err != nil {
		return err
	}
	if n, _ := tag.RowsAffected(); n == 0 {
		return ErrTenantNotFound
	}
	return nil
}
