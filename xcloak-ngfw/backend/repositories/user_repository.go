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
