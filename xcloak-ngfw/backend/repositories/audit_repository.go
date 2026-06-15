package repositories

import (
	"fmt"

	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
)

func CreateAuditLog(action, details, username string) error {
	_, err := database.DB.Exec(
		`INSERT INTO audit_logs (action, details, username) VALUES ($1,$2,$3)`,
		action, details, username,
	)
	return err
}

func GetAuditLogs() ([]models.AuditLog, error) {
	rows, err := database.DB.Query(`
		SELECT id, action, details, username, created_at
		FROM audit_logs ORDER BY created_at DESC LIMIT 200
	`)
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
	return logs, nil
}

type AuditPage struct {
	Logs    []models.AuditLog `json:"logs"`
	Total   int               `json:"total"`
	Page    int               `json:"page"`
	PerPage int               `json:"per_page"`
	Pages   int               `json:"pages"`
}

// GetAuditLogsFiltered — search + date range filter with pagination.
func GetAuditLogsFiltered(page, perPage int, q, from, to string) (*AuditPage, error) {
	if page < 1    { page = 1 }
	if perPage < 1 { perPage = 50 }
	if perPage > 200 { perPage = 200 }

	where := "WHERE 1=1"
	args  := []interface{}{}
	idx   := 1

	if q != "" {
		where += fmt.Sprintf(
			" AND (action ILIKE $%d OR details ILIKE $%d OR username ILIKE $%d)",
			idx, idx, idx,
		)
		args = append(args, "%"+q+"%")
		idx++
	}

	if from != "" {
		where += fmt.Sprintf(" AND created_at >= $%d::timestamptz", idx)
		args = append(args, from)
		idx++
	}

	if to != "" {
		where += fmt.Sprintf(" AND created_at <= $%d::timestamptz", idx)
		args = append(args, to)
		idx++
	}

	var total int
	if err := database.DB.QueryRow(
		"SELECT COUNT(*) FROM audit_logs "+where, args...,
	).Scan(&total); err != nil {
		return nil, err
	}

	offset   := (page - 1) * perPage
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

	pages := total / perPage
	if total%perPage != 0 {
		pages++
	}

	return &AuditPage{
		Logs: logs, Total: total,
		Page: page, PerPage: perPage, Pages: pages,
	}, nil
}
