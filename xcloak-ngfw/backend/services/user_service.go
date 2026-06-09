package services

import (
	"errors"
	"xcloak-ngfw/auth"
	"xcloak-ngfw/models"
	"xcloak-ngfw/repositories"
)

func RegisterUser(
	user models.User,
) error {

	hash, err := auth.HashPassword(
		user.Password,
	)

	if err != nil {
		return err
	}

	user.PasswordHash = hash

	return repositories.CreateUser(user)
}

func LoginUser(
	username string,
	password string,
) (string, error) {

	user, err := repositories.GetUserByUsername(
		username,
	)

	if err != nil {
		return "", err
	}

	valid := auth.VerifyPassword(
		password,
		user.PasswordHash,
	)

	if !valid {
		return "", errors.New(
			"invalid credentials",
		)
	}

	token, err := auth.GenerateJWT(
		user.ID,
		user.Username,
		user.Role,
	)

	if err != nil {
		return "", err
	}

	LogEvent(
		"LOGIN",
		"User logged in",
		user.Username,
	)

	return token, nil
}
