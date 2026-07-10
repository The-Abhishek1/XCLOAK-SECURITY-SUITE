package repositories

import (
	"xcloak-platform/database"
	"xcloak-platform/models"
)

func GetDashboardOverview(tenantID int) (*models.DashboardOverview, error) {

	var overview models.DashboardOverview

	database.DB.QueryRow(`
		SELECT COUNT(*)
		FROM agents
		WHERE tenant_id=$1
	`, tenantID).Scan(&overview.Agents)

	database.DB.QueryRow(`
		SELECT COUNT(*)
		FROM agents
		WHERE status='online' AND tenant_id=$1
	`, tenantID).Scan(&overview.OnlineAgents)

	database.DB.QueryRow(`
		SELECT COUNT(*)
		FROM agents
		WHERE status='offline' AND tenant_id=$1
	`, tenantID).Scan(&overview.OfflineAgents)

	database.DB.QueryRow(`
		SELECT COUNT(*)
		FROM endpoint_processes ep
		JOIN agents a ON a.id = ep.agent_id
		WHERE a.tenant_id=$1
	`, tenantID).Scan(&overview.Processes)

	database.DB.QueryRow(`
		SELECT COUNT(*)
		FROM endpoint_connections ec
		JOIN agents a ON a.id = ec.agent_id
		WHERE a.tenant_id=$1
	`, tenantID).Scan(&overview.Connections)

	database.DB.QueryRow(`
		SELECT COUNT(*)
		FROM endpoint_services es
		JOIN agents a ON a.id = es.agent_id
		WHERE a.tenant_id=$1
	`, tenantID).Scan(&overview.Services)

	database.DB.QueryRow(`
		SELECT COUNT(*)
		FROM endpoint_packages ep
		JOIN agents a ON a.id = ep.agent_id
		WHERE a.tenant_id=$1
	`, tenantID).Scan(&overview.Packages)

	database.DB.QueryRow(`
		SELECT COUNT(*)
		FROM endpoint_users eu
		JOIN agents a ON a.id = eu.agent_id
		WHERE a.tenant_id=$1
	`, tenantID).Scan(&overview.Users)

	database.DB.QueryRow(
		`SELECT COUNT(*) FROM alerts WHERE tenant_id=$1`, tenantID,
	).Scan(&overview.Alerts)

	database.DB.QueryRow(
		`SELECT COUNT(*) FROM alerts WHERE severity='critical' AND tenant_id=$1`, tenantID,
	).Scan(&overview.CriticalAlerts)

	database.DB.QueryRow(
		`SELECT COUNT(*) FROM incidents WHERE tenant_id=$1`, tenantID,
	).Scan(&overview.Incidents)

	database.DB.QueryRow(
		`SELECT COUNT(*) FROM incidents WHERE severity='critical' AND tenant_id=$1`, tenantID,
	).Scan(&overview.CriticalIncidents)

	return &overview, nil
}
