package services

import (
	"xcloak-ngfw/models"
	"xcloak-ngfw/repositories"
)

func CreateIOC(
	ioc models.IOC,
) error {

	return repositories.CreateIOC(ioc)
}

func GetIOCs() ([]models.IOC, error) {

	return repositories.GetIOCs()
}

func GetEnabledIOCs() ([]models.IOC, error) {

	return repositories.GetEnabledIOCs()
}

func GetIOCByID(
	id string,
) (*models.IOC, error) {

	return repositories.GetIOCByID(id)
}

func UpdateIOC(
	id string,
	ioc models.IOC,
) error {

	return repositories.UpdateIOC(
		id,
		ioc,
	)
}

func DeleteIOC(
	id string,
) error {

	return repositories.DeleteIOC(id)
}

func EnableIOC(
	id string,
) error {

	return repositories.EnableIOC(id)
}

func DisableIOC(
	id string,
) error {

	return repositories.DisableIOC(id)
}
