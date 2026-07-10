package repositories

import (
	"github.com/lib/pq"

	"xcloak-platform/database"
	"xcloak-platform/models"
)

func CreateScheduledReport(r models.ScheduledReport) (models.ScheduledReport, error) {
	err := database.DB.QueryRow(`
		INSERT INTO scheduled_reports (tenant_id, name, report_type, schedule, recipients, enabled, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
		RETURNING id, created_at
	`, r.TenantID, r.Name, r.ReportType, r.Schedule, pq.Array(r.Recipients), r.Enabled, r.CreatedBy,
	).Scan(&r.ID, &r.CreatedAt)
	return r, err
}

func GetScheduledReports(tenantID int) ([]models.ScheduledReport, error) {
	rows, err := database.DB.Query(`
		SELECT id, tenant_id, name, report_type, schedule, recipients, enabled, last_sent_at, created_by, created_at
		FROM scheduled_reports WHERE tenant_id=$1 ORDER BY created_at DESC
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanReports(rows)
}

func GetAllEnabledScheduledReports() ([]models.ScheduledReport, error) {
	rows, err := database.DB.Query(`
		SELECT id, tenant_id, name, report_type, schedule, recipients, enabled, last_sent_at, created_by, created_at
		FROM scheduled_reports WHERE enabled=true
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanReports(rows)
}

func UpdateScheduledReport(r models.ScheduledReport) error {
	_, err := database.DB.Exec(`
		UPDATE scheduled_reports SET
		  name=$1, report_type=$2, schedule=$3, recipients=$4, enabled=$5
		WHERE id=$6 AND tenant_id=$7
	`, r.Name, r.ReportType, r.Schedule, pq.Array(r.Recipients), r.Enabled, r.ID, r.TenantID)
	return err
}

func MarkReportSent(id int) error {
	_, err := database.DB.Exec(`UPDATE scheduled_reports SET last_sent_at=NOW() WHERE id=$1`, id)
	return err
}

func DeleteScheduledReport(id, tenantID int) error {
	_, err := database.DB.Exec(`DELETE FROM scheduled_reports WHERE id=$1 AND tenant_id=$2`, id, tenantID)
	return err
}

func scanReports(rows interface {
	Next() bool
	Scan(...any) error
	Close() error
}) ([]models.ScheduledReport, error) {
	defer rows.Close()
	var out []models.ScheduledReport
	for rows.Next() {
		var r models.ScheduledReport
		if err := rows.Scan(
			&r.ID, &r.TenantID, &r.Name, &r.ReportType, &r.Schedule,
			pq.Array(&r.Recipients), &r.Enabled, &r.LastSentAt, &r.CreatedBy, &r.CreatedAt,
		); err == nil {
			out = append(out, r)
		}
	}
	return out, nil
}
