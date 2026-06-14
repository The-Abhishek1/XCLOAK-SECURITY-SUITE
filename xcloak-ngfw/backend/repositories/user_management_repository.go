package repositories

import (
	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
)

// GetAllUsers returns all registered users (passwords excluded).
func GetAllUsers() ([]models.User, error) {

	rows, err := database.DB.Query(`
		SELECT id, username, email, role,
		       COALESCE(is_active, true),
		       COALESCE(last_login, created_at),
		       COALESCE(created_at, now())
		FROM users
		ORDER BY id ASC
	`)

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []models.User
	for rows.Next() {
		var u models.User
		rows.Scan(&u.ID, &u.Username, &u.Email, &u.Role, &u.IsActive, &u.LastLogin, &u.CreatedAt)
		users = append(users, u)
	}

	return users, nil
}

// UpdateUserRole changes a user's role.
func UpdateUserRole(id int, role string) error {
	_, err := database.DB.Exec(`UPDATE users SET role=$1 WHERE id=$2`, role, id)
	return err
}

// SetUserActive toggles a user's active status.
func SetUserActive(id int, active bool) error {
	_, err := database.DB.Exec(`UPDATE users SET is_active=$1 WHERE id=$2`, active, id)
	return err
}

// DeleteUser removes a user by ID.
func DeleteUser(id int) error {
	_, err := database.DB.Exec(`DELETE FROM users WHERE id=$1`, id)
	return err
}
