package repositories

import (
	"errors"

	"xcloak-platform/database"
	"xcloak-platform/models"
)

// ErrUserNotFound is returned by the tenant-scoped mutations below when no
// row matches id+tenantID — covers both a nonexistent id and a real id
// belonging to another tenant, so callers can't distinguish the two.
var ErrUserNotFound = errors.New("user not found")

// GetAllUsers returns all users belonging to tenantID (passwords excluded).
func GetAllUsers(tenantID int) ([]models.User, error) {

	rows, err := database.DB.Query(`
		SELECT id, username, email, role, tenant_id,
		       COALESCE(is_active, true),
		       COALESCE(last_login, created_at),
		       COALESCE(created_at, now())
		FROM users
		WHERE tenant_id = $1
		ORDER BY id ASC
	`, tenantID)

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []models.User
	for rows.Next() {
		var u models.User
		if err := rows.Scan(&u.ID, &u.Username, &u.Email, &u.Role, &u.TenantID, &u.IsActive, &u.LastLogin, &u.CreatedAt); err != nil {
			return nil, err
		}
		users = append(users, u)
	}

	return users, rows.Err()
}

// UpdateUserRole changes a user's role, scoped to tenantID.
func UpdateUserRole(id int, role string, tenantID int) error {
	tag, err := database.DB.Exec(`UPDATE users SET role=$1 WHERE id=$2 AND tenant_id=$3`, role, id, tenantID)
	if err != nil {
		return err
	}
	if n, _ := tag.RowsAffected(); n == 0 {
		return ErrUserNotFound
	}
	return nil
}

// SetUserActive toggles a user's active status, scoped to tenantID.
func SetUserActive(id int, active bool, tenantID int) error {
	tag, err := database.DB.Exec(`UPDATE users SET is_active=$1 WHERE id=$2 AND tenant_id=$3`, active, id, tenantID)
	if err != nil {
		return err
	}
	if n, _ := tag.RowsAffected(); n == 0 {
		return ErrUserNotFound
	}
	return nil
}

// DeleteUser removes a user by ID, scoped to tenantID.
func DeleteUser(id int, tenantID int) error {
	tag, err := database.DB.Exec(`DELETE FROM users WHERE id=$1 AND tenant_id=$2`, id, tenantID)
	if err != nil {
		return err
	}
	if n, _ := tag.RowsAffected(); n == 0 {
		return ErrUserNotFound
	}
	return nil
}
