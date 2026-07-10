package repositories

import (
	"errors"

	"xcloak-platform/database"
	"xcloak-platform/models"
)

// errIncidentAlreadyExists signals CreateIncident's dedup hit (fingerprint
// fired within the last hour) — every existing caller already treats a
// non-nil error here as "go look up the existing incident," so this reuses
// that path instead of needing callers to special-case it.
var errIncidentAlreadyExists = errors.New("incident already exists for fingerprint")

// CreateIncident inserts a new incident, or returns the existing one's ID
// if the fingerprint already fired within the dedup window (IncidentExists).
// Every caller distinguishes "new" vs "existing" by checking err != nil —
// returning (0, nil) for the existing case used to break that contract:
// callers took the "new incident" branch on a nil error regardless, firing
// incident_created playbooks again and logging a timeline event against a
// nonexistent incident #0 on every repeat. Resolving the real ID here means
// callers can't get this wrong even if they assume err!=nil means "exists".
func CreateIncident(
	incident models.Incident,
) (int, error) {

	if IncidentExists(
		incident.Fingerprint,
	) {
		existingID, err := GetIncidentIDByFingerprint(incident.Fingerprint)
		if err != nil {
			return 0, err
		}
		return existingID, errIncidentAlreadyExists
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
