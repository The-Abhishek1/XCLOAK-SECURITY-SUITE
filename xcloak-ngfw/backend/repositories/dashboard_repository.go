package repositories

import (
	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
)

func GetDashboardOverview() (*models.DashboardOverview, error) {

	var overview models.DashboardOverview

	database.DB.QueryRow(`
		SELECT COUNT(*)
		FROM agents
	`).Scan(&overview.Agents)

	database.DB.QueryRow(`
		SELECT COUNT(*)
		FROM agents
		WHERE status='online'
	`).Scan(&overview.OnlineAgents)

	database.DB.QueryRow(`
		SELECT COUNT(*)
		FROM agents
		WHERE status='offline'
	`).Scan(&overview.OfflineAgents)

	database.DB.QueryRow(`
		SELECT COUNT(*)
		FROM endpoint_processes
	`).Scan(&overview.Processes)

	database.DB.QueryRow(`
		SELECT COUNT(*)
		FROM endpoint_connections
	`).Scan(&overview.Connections)

	database.DB.QueryRow(`
		SELECT COUNT(*)
		FROM endpoint_services
	`).Scan(&overview.Services)

	database.DB.QueryRow(`
		SELECT COUNT(*)
		FROM endpoint_packages
	`).Scan(&overview.Packages)

	database.DB.QueryRow(`
		SELECT COUNT(*)
		FROM endpoint_users
	`).Scan(&overview.Users)

	database.DB.QueryRow(
		`SELECT COUNT(*) FROM alerts`,
	).Scan(&overview.Alerts)

	database.DB.QueryRow(
		`SELECT COUNT(*) FROM alerts WHERE severity='critical'`,
	).Scan(&overview.CriticalAlerts)

	database.DB.QueryRow(
		`SELECT COUNT(*) FROM incidents`,
	).Scan(&overview.Incidents)

	database.DB.QueryRow(
		`SELECT COUNT(*) FROM incidents WHERE severity='critical'`,
	).Scan(&overview.CriticalIncidents)

	return &overview, nil
}
