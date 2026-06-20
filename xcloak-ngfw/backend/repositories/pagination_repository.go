package repositories

import (
	"fmt"

	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
)

// PaginatedResult wraps a page of results with metadata for the frontend.
type PaginatedAlerts struct {
	Data       []models.Alert `json:"data"`
	Total      int            `json:"total"`
	Page       int            `json:"page"`
	PerPage    int            `json:"per_page"`
	TotalPages int            `json:"total_pages"`
}

type PaginatedIncidents struct {
	Data       []models.Incident `json:"data"`
	Total      int               `json:"total"`
	Page       int               `json:"page"`
	PerPage    int               `json:"per_page"`
	TotalPages int               `json:"total_pages"`
}

type PaginatedAuditLogs struct {
	Data       []models.AuditLog `json:"data"`
	Total      int               `json:"total"`
	Page       int               `json:"page"`
	PerPage    int               `json:"per_page"`
	TotalPages int               `json:"total_pages"`
}

// GetAlertsPaginated returns one page of alerts for tenantID, optionally
// filtered by severity and/or agent_id. Newest first.
func GetAlertsPaginated(tenantID int, page, perPage int, severity, agentID string) (*PaginatedAlerts, error) {

	if page < 1 {
		page = 1
	}
	if perPage < 1 || perPage > 200 {
		perPage = 50
	}

	offset := (page - 1) * perPage

	where := "WHERE tenant_id = $1"
	args := []interface{}{tenantID}
	idx := 2

	if severity != "" && severity != "all" {
		where += fmt.Sprintf(" AND severity = $%d", idx)
		args = append(args, severity)
		idx++
	}
	if agentID != "" {
		where += fmt.Sprintf(" AND agent_id = $%d", idx)
		args = append(args, agentID)
		idx++
	}

	var total int
	countQuery := "SELECT COUNT(*) FROM alerts " + where
	if err := database.DB.QueryRow(countQuery, args...).Scan(&total); err != nil {
		return nil, err
	}

	dataArgs := append(args, perPage, offset)
	rows, err := database.DB.Query(fmt.Sprintf(`
		SELECT id, agent_id, severity, rule_name, fingerprint,
		       mitre_tactic, mitre_technique, mitre_name, log_message, created_at
		FROM alerts %s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d
	`, where, idx, idx+1), dataArgs...)

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var alerts []models.Alert
	for rows.Next() {
		var a models.Alert
		if err := rows.Scan(&a.ID, &a.AgentID, &a.Severity, &a.RuleName, &a.Fingerprint,
			&a.MitreTactic, &a.MitreTechnique, &a.MitreName, &a.LogMessage, &a.CreatedAt); err == nil {
			alerts = append(alerts, a)
		}
	}

	if alerts == nil {
		alerts = []models.Alert{}
	}

	totalPages := (total + perPage - 1) / perPage

	return &PaginatedAlerts{
		Data:       alerts,
		Total:      total,
		Page:       page,
		PerPage:    perPage,
		TotalPages: totalPages,
	}, nil
}

// GetIncidentsPaginated returns one page of incidents, optionally filtered
// by status. Newest first.
func GetIncidentsPaginated(tenantID int, page, perPage int, status string) (*PaginatedIncidents, error) {

	if page < 1 {
		page = 1
	}
	if perPage < 1 || perPage > 100 {
		perPage = 25
	}

	offset := (page - 1) * perPage

	where := "WHERE tenant_id = $1"
	args := []interface{}{tenantID}
	idx := 2

	if status != "" && status != "all" {
		where += fmt.Sprintf(" AND status = $%d", idx)
		args = append(args, status)
		idx++
	}

	var total int
	if err := database.DB.QueryRow("SELECT COUNT(*) FROM incidents "+where, args...).Scan(&total); err != nil {
		return nil, err
	}

	dataArgs := append(args, perPage, offset)
	rows, err := database.DB.Query(fmt.Sprintf(`
		SELECT id, agent_id, title, severity, status, description, created_at
		FROM incidents %s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d
	`, where, idx, idx+1), dataArgs...)

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var incidents []models.Incident
	for rows.Next() {
		var i models.Incident
		if err := rows.Scan(&i.ID, &i.AgentID, &i.Title, &i.Severity,
			&i.Status, &i.Description, &i.CreatedAt); err == nil {
			incidents = append(incidents, i)
		}
	}

	if incidents == nil {
		incidents = []models.Incident{}
	}

	totalPages := (total + perPage - 1) / perPage

	return &PaginatedIncidents{
		Data:       incidents,
		Total:      total,
		Page:       page,
		PerPage:    perPage,
		TotalPages: totalPages,
	}, nil
}

// GetAuditLogsPaginated returns one page of audit logs.
func GetAuditLogsPaginated(page, perPage int, action string) (*PaginatedAuditLogs, error) {

	if page < 1 {
		page = 1
	}
	if perPage < 1 || perPage > 200 {
		perPage = 50
	}

	offset := (page - 1) * perPage

	where := "WHERE 1=1"
	args := []interface{}{}
	idx := 1

	if action != "" {
		where += fmt.Sprintf(" AND action ILIKE $%d", idx)
		args = append(args, "%"+action+"%")
		idx++
	}

	var total int
	if err := database.DB.QueryRow("SELECT COUNT(*) FROM audit_logs "+where, args...).Scan(&total); err != nil {
		return nil, err
	}

	dataArgs := append(args, perPage, offset)
	rows, err := database.DB.Query(fmt.Sprintf(`
		SELECT id, action, details, username, created_at
		FROM audit_logs %s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d
	`, where, idx, idx+1), dataArgs...)

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []models.AuditLog
	for rows.Next() {
		var l models.AuditLog
		if err := rows.Scan(&l.ID, &l.Action, &l.Details, &l.Username, &l.CreatedAt); err == nil {
			logs = append(logs, l)
		}
	}

	if logs == nil {
		logs = []models.AuditLog{}
	}

	totalPages := (total + perPage - 1) / perPage

	return &PaginatedAuditLogs{
		Data:       logs,
		Total:      total,
		Page:       page,
		PerPage:    perPage,
		TotalPages: totalPages,
	}, nil
}
