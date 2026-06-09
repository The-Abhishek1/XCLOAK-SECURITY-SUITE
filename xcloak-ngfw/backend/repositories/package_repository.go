package repositories

import (
	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
)

func SavePackages(
	packages []models.Package,
) error {

	if len(packages) == 0 {
		return nil
	}

	tx, err := database.DB.Begin()

	if err != nil {
		return err
	}

	defer tx.Rollback()

	agentID := packages[0].AgentID

	_, err = tx.Exec(`
		DELETE FROM endpoint_packages
		WHERE agent_id = $1
	`, agentID)

	if err != nil {
		return err
	}

	for _, pkg := range packages {

		_, err := tx.Exec(`
			INSERT INTO endpoint_packages
			(agent_id, package_name, version)
			VALUES ($1,$2,$3)
		`,
			pkg.AgentID,
			pkg.PackageName,
			pkg.Version,
		)

		if err != nil {
			return err
		}
	}

	return tx.Commit()
}
