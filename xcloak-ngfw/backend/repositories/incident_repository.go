package repositories

import (
	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
)

// CreateIncident inserts a new incident. tenant_id is resolved from the
// owning agent rather than incident.TenantID — CreateIncident is called from
// the correlation engine, which only carries agent_id, and the agent is the
// single source of truth for which tenant an incident belongs to (matches
// CreateAlert's pattern).
func CreateIncident(
	incident models.Incident,
) (int, error) {

	if IncidentExists(
		incident.Fingerprint,
	) {
		return 0, nil
	}

	var incidentID int

	err := database.DB.QueryRow(`
		INSERT INTO incidents
		(
			agent_id,
			title,
			severity,
			description,
			fingerprint,
			tenant_id
		)
		VALUES ($1,$2,$3,$4,$5, (SELECT tenant_id FROM agents WHERE id = $1))
		RETURNING id
	`,
		incident.AgentID,
		incident.Title,
		incident.Severity,
		incident.Description,
		incident.Fingerprint,
	).Scan(&incidentID)

	if err != nil {
		return 0, err
	}

	return incidentID, nil
}

// GetIncidents returns incidents belonging to tenantID only. Use this from
// user-facing API paths that have a real tenant context from the request.
func GetIncidents(tenantID int) ([]models.Incident, error) {
	return queryIncidents(`
		SELECT id, agent_id, title, severity, status, description, created_at, tenant_id
		FROM incidents
		WHERE tenant_id = $1
		ORDER BY created_at DESC
	`, tenantID)
}

// GetAllIncidents returns every incident across every tenant. For internal
// background jobs (AI chat/compliance/risk scoring) that operate fleet-wide
// with no per-request tenant context — not for user-facing API responses,
// which must use GetIncidents(tenantID) instead.
func GetAllIncidents() ([]models.Incident, error) {
	return queryIncidents(`
		SELECT id, agent_id, title, severity, status, description, created_at, tenant_id
		FROM incidents
		ORDER BY created_at DESC
	`)
}

func queryIncidents(query string, args ...interface{}) ([]models.Incident, error) {

	rows, err := database.DB.Query(query, args...)

	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var incidents []models.Incident

	for rows.Next() {

		var incident models.Incident

		err := rows.Scan(
			&incident.ID,
			&incident.AgentID,
			&incident.Title,
			&incident.Severity,
			&incident.Status,
			&incident.Description,
			&incident.CreatedAt,
			&incident.TenantID,
		)

		if err != nil {
			continue
		}

		incidents = append(
			incidents,
			incident,
		)
	}

	return incidents, nil
}

func IncidentExists(
	fingerprint string,
) bool {

	var count int

	err := database.DB.QueryRow(`
		SELECT COUNT(*)
		FROM incidents
		WHERE
			fingerprint = $1
			AND created_at >
			NOW() - INTERVAL '1 hour'
	`,
		fingerprint,
	).Scan(&count)

	if err != nil {
		return false
	}

	return count > 0
}
