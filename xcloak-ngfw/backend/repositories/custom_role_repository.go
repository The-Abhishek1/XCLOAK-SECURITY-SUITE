package repositories

import (
	"database/sql"
	"errors"

	"github.com/lib/pq"

	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
)

var ErrCustomRoleNotFound = errors.New("custom role not found")
var ErrCustomRoleInUse = errors.New("custom role is still assigned to one or more users")

func CreateCustomRole(tenantID int, name string, permissions []string, createdBy string) (*models.CustomRole, error) {

	var r models.CustomRole
	r.TenantID = tenantID
	r.Name = name
	r.Permissions = permissions
	r.CreatedBy = createdBy

	err := database.DB.QueryRow(`
		INSERT INTO custom_roles (tenant_id, name, permissions, created_by)
		VALUES ($1, $2, $3, $4)
		RETURNING id, created_at
	`, tenantID, name, pq.Array(permissions), createdBy).Scan(&r.ID, &r.CreatedAt)

	if err != nil {
		return nil, err
	}

	return &r, nil
}

func GetCustomRolesByTenant(tenantID int) ([]models.CustomRole, error) {

	rows, err := database.DB.Query(`
		SELECT id, tenant_id, name, permissions, created_by, created_at
		FROM custom_roles WHERE tenant_id = $1 ORDER BY created_at DESC
	`, tenantID)

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var roles []models.CustomRole
	for rows.Next() {
		var r models.CustomRole
		if err := rows.Scan(&r.ID, &r.TenantID, &r.Name, pq.Array(&r.Permissions), &r.CreatedBy, &r.CreatedAt); err == nil {
			roles = append(roles, r)
		}
	}

	return roles, nil
}

// GetCustomRoleByName is the validation-path lookup — called by
// middleware.RequirePermission on every non-admin authenticated request,
// and by the role-validation helpers when inviting a user / creating an
// API key with a non-built-in role name.
func GetCustomRoleByName(tenantID int, name string) (*models.CustomRole, error) {

	var r models.CustomRole

	err := database.DB.QueryRow(`
		SELECT id, tenant_id, name, permissions, created_by, created_at
		FROM custom_roles WHERE tenant_id = $1 AND name = $2
	`, tenantID, name).Scan(&r.ID, &r.TenantID, &r.Name, pq.Array(&r.Permissions), &r.CreatedBy, &r.CreatedAt)

	if err == sql.ErrNoRows {
		return nil, ErrCustomRoleNotFound
	}
	if err != nil {
		return nil, err
	}

	return &r, nil
}

func UpdateCustomRole(id, tenantID int, permissions []string) error {
	tag, err := database.DB.Exec(`
		UPDATE custom_roles SET permissions = $1 WHERE id = $2 AND tenant_id = $3
	`, pq.Array(permissions), id, tenantID)
	if err != nil {
		return err
	}
	if n, _ := tag.RowsAffected(); n == 0 {
		return ErrCustomRoleNotFound
	}
	return nil
}

// DeleteCustomRole is IDOR-safe (id+tenant_id) and refuses to delete a role
// still assigned to any user, so nobody is silently left with an orphaned
// role string that resolves to zero permissions.
func DeleteCustomRole(id, tenantID int) error {

	var name string
	if err := database.DB.QueryRow(`SELECT name FROM custom_roles WHERE id=$1 AND tenant_id=$2`, id, tenantID).Scan(&name); err != nil {
		if err == sql.ErrNoRows {
			return ErrCustomRoleNotFound
		}
		return err
	}

	var inUse int
	database.DB.QueryRow(`SELECT count(*) FROM users WHERE tenant_id=$1 AND role=$2`, tenantID, name).Scan(&inUse)
	if inUse > 0 {
		return ErrCustomRoleInUse
	}

	_, err := database.DB.Exec(`DELETE FROM custom_roles WHERE id=$1 AND tenant_id=$2`, id, tenantID)
	return err
}
