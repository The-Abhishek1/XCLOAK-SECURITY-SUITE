package repositories

import (
	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
)

func CreateIOC(
	ioc models.IOC,
) error {

	if IOCExists(
		ioc.Indicator,
		ioc.Type,
	) {

		return nil
	}

	_, err := database.DB.Exec(`
		INSERT INTO iocs
		(
			indicator,
			type,
			severity,
			description,
			enabled
		)
		VALUES ($1,$2,$3,$4,$5)
	`,
		ioc.Indicator,
		ioc.Type,
		ioc.Severity,
		ioc.Description,
		ioc.Enabled,
	)

	return err
}

func GetIOCs() ([]models.IOC, error) {

	rows, err := database.DB.Query(`
		SELECT
			id,
			indicator,
			type,
			severity,
			description,
			enabled,
			created_at
		FROM iocs
		ORDER BY id DESC
	`)

	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var iocs []models.IOC

	for rows.Next() {

		var ioc models.IOC

		err := rows.Scan(
			&ioc.ID,
			&ioc.Indicator,
			&ioc.Type,
			&ioc.Severity,
			&ioc.Description,
			&ioc.Enabled,
			&ioc.CreatedAt,
		)

		if err != nil {
			continue
		}

		iocs = append(iocs, ioc)
	}

	return iocs, nil
}

func GetEnabledIOCs() ([]models.IOC, error) {

	rows, err := database.DB.Query(`
		SELECT
			id,
			indicator,
			type,
			severity,
			description,
			enabled,
			created_at
		FROM iocs
		WHERE enabled = true
	`)

	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var iocs []models.IOC

	for rows.Next() {

		var ioc models.IOC

		err := rows.Scan(
			&ioc.ID,
			&ioc.Indicator,
			&ioc.Type,
			&ioc.Severity,
			&ioc.Description,
			&ioc.Enabled,
			&ioc.CreatedAt,
		)

		if err != nil {
			continue
		}

		iocs = append(iocs, ioc)
	}

	return iocs, nil
}

func GetIOCByID(
	id string,
) (*models.IOC, error) {

	var ioc models.IOC

	err := database.DB.QueryRow(`
		SELECT
			id,
			indicator,
			type,
			severity,
			description,
			enabled,
			created_at
		FROM iocs
		WHERE id = $1
	`,
		id,
	).Scan(
		&ioc.ID,
		&ioc.Indicator,
		&ioc.Type,
		&ioc.Severity,
		&ioc.Description,
		&ioc.Enabled,
		&ioc.CreatedAt,
	)

	if err != nil {
		return nil, err
	}

	return &ioc, nil
}

func UpdateIOC(
	id string,
	ioc models.IOC,
) error {

	_, err := database.DB.Exec(`
		UPDATE iocs
		SET
			indicator = $1,
			type = $2,
			severity = $3,
			description = $4,
			enabled = $5
		WHERE id = $6
	`,
		ioc.Indicator,
		ioc.Type,
		ioc.Severity,
		ioc.Description,
		ioc.Enabled,
		id,
	)

	return err
}

func DeleteIOC(
	id string,
) error {

	_, err := database.DB.Exec(`
		DELETE FROM iocs
		WHERE id = $1
	`,
		id,
	)

	return err
}

func EnableIOC(
	id string,
) error {

	_, err := database.DB.Exec(`
		UPDATE iocs
		SET enabled = true
		WHERE id = $1
	`,
		id,
	)

	return err
}

func DisableIOC(
	id string,
) error {

	_, err := database.DB.Exec(`
		UPDATE iocs
		SET enabled = false
		WHERE id = $1
	`,
		id,
	)

	return err
}

func IOCExists(
	indicator string,
	iocType string,
) bool {

	var count int

	err := database.DB.QueryRow(`
		SELECT COUNT(*)
		FROM iocs
		WHERE
			indicator = $1
			AND type = $2
	`,
		indicator,
		iocType,
	).Scan(&count)

	if err != nil {
		return false
	}

	return count > 0
}
