package repositories

import (
	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
)

func CreateUser(user models.User) error {

	query := `
	INSERT INTO users
	(username,email,password_hash,role)
	VALUES ($1,$2,$3,$4)
	`

	_, err := database.DB.Exec(
		query,
		user.Username,
		user.Email,
		user.PasswordHash,
		user.Role,
	)

	return err
}

func GetUserByUsername(
	username string,
) (*models.User, error) {

	var user models.User

	query := `
	SELECT
	id,
	username,
	email,
	password_hash,
	role,
	tenant_id,
	is_platform_admin,
	is_active
	FROM users
	WHERE username = $1
	`

	err := database.DB.QueryRow(
		query,
		username,
	).Scan(
		&user.ID,
		&user.Username,
		&user.Email,
		&user.PasswordHash,
		&user.Role,
		&user.TenantID,
		&user.IsPlatformAdmin,
		&user.IsActive,
	)

	if err != nil {
		return nil, err
	}

	return &user, nil
}

// GetUserByUsernameOrEmail looks up a user by username OR email (whichever matches).
// Used by Login so callers can supply either field.
func GetUserByUsernameOrEmail(usernameOrEmail string) (*models.User, error) {
	var user models.User
	err := database.DB.QueryRow(`
		SELECT id, username, email, password_hash, role, tenant_id, is_platform_admin, is_active
		FROM users
		WHERE username = $1 OR email = $1
		LIMIT 1
	`, usernameOrEmail).Scan(
		&user.ID,
		&user.Username,
		&user.Email,
		&user.PasswordHash,
		&user.Role,
		&user.TenantID,
		&user.IsPlatformAdmin,
		&user.IsActive,
	)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// GetUserByEmailAndTenant looks up a user by email scoped to a specific
// tenant — used by OIDC SSO login, where the IdP's email claim must match
// an existing account within the tenant the SSO flow was started for (no
// auto-provisioning).
func GetUserByEmailAndTenant(email string, tenantID int) (*models.User, error) {

	var user models.User

	query := `
	SELECT
	id,
	username,
	email,
	password_hash,
	role,
	tenant_id,
	is_platform_admin,
	is_active
	FROM users
	WHERE email = $1 AND tenant_id = $2
	`

	err := database.DB.QueryRow(
		query,
		email,
		tenantID,
	).Scan(
		&user.ID,
		&user.Username,
		&user.Email,
		&user.PasswordHash,
		&user.Role,
		&user.TenantID,
		&user.IsPlatformAdmin,
		&user.IsActive,
	)

	if err != nil {
		return nil, err
	}

	return &user, nil
}
