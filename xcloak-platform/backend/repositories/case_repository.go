package repositories

import (
	"fmt"
	"strings"
	"time"

	"xcloak-platform/database"
	"xcloak-platform/models"
)

func CreateCase(c models.Case) (models.Case, error) {
	err := database.DB.QueryRow(`
		INSERT INTO cases
		  (tenant_id, title, description, severity, status, phase,
		   assigned_to, assigned_to_name, sla_hours, sla_breach_at,
		   mitre_tactic, mitre_technique)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		RETURNING id, created_at, updated_at
	`, c.TenantID, c.Title, c.Description, c.Severity, c.Status, c.Phase,
		c.AssignedTo, c.AssignedToName, c.SLAHours, c.SLABreachAt,
		c.MITRETactic, c.MITRETechnique,
	).Scan(&c.ID, &c.CreatedAt, &c.UpdatedAt)
	return c, err
}

func GetCases(tenantID, page, limit int, status, severity string) ([]models.Case, int, error) {
	args := []any{tenantID}
	where := []string{"c.tenant_id = $1"}

	if status != "" {
		args = append(args, status)
		where = append(where, fmt.Sprintf("c.status = $%d", len(args)))
	}
	if severity != "" {
		args = append(args, severity)
		where = append(where, fmt.Sprintf("c.severity = $%d", len(args)))
	}

	whereClause := strings.Join(where, " AND ")

	var total int
	database.DB.QueryRow(`SELECT COUNT(*) FROM cases c WHERE `+whereClause, args...).Scan(&total)

	offset := page * limit
	args = append(args, limit, offset)
	rows, err := database.DB.Query(`
		SELECT c.id, c.tenant_id, c.title, c.description, c.severity, c.status,
		       c.phase, c.assigned_to, c.assigned_to_name, c.sla_hours,
		       c.sla_breach_at, c.sla_breached, c.mitre_tactic, c.mitre_technique,
		       c.rca, c.closed_at, c.created_at, c.updated_at,
		       (SELECT COUNT(*) FROM case_alerts WHERE case_id = c.id) AS alert_count,
		       (SELECT COUNT(*) FROM case_comments WHERE case_id = c.id) AS comment_count
		FROM cases c
		WHERE `+whereClause+`
		ORDER BY c.created_at DESC
		LIMIT $`+fmt.Sprintf("%d", len(args)-1)+` OFFSET $`+fmt.Sprintf("%d", len(args)),
		args...,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	out := []models.Case{}
	for rows.Next() {
		var c models.Case
		if err := rows.Scan(
			&c.ID, &c.TenantID, &c.Title, &c.Description, &c.Severity, &c.Status,
			&c.Phase, &c.AssignedTo, &c.AssignedToName, &c.SLAHours,
			&c.SLABreachAt, &c.SLABreached, &c.MITRETactic, &c.MITRETechnique,
			&c.RCA, &c.ClosedAt, &c.CreatedAt, &c.UpdatedAt,
			&c.AlertCount, &c.CommentCount,
		); err == nil {
			out = append(out, c)
		}
	}
	return out, total, nil
}

func GetCaseByID(id, tenantID int) (models.Case, error) {
	var c models.Case
	err := database.DB.QueryRow(`
		SELECT c.id, c.tenant_id, c.title, c.description, c.severity, c.status,
		       c.phase, c.assigned_to, c.assigned_to_name, c.sla_hours,
		       c.sla_breach_at, c.sla_breached, c.mitre_tactic, c.mitre_technique,
		       c.rca, c.closed_at, c.created_at, c.updated_at,
		       (SELECT COUNT(*) FROM case_alerts WHERE case_id = c.id),
		       (SELECT COUNT(*) FROM case_comments WHERE case_id = c.id)
		FROM cases c
		WHERE c.id=$1 AND c.tenant_id=$2
	`, id, tenantID).Scan(
		&c.ID, &c.TenantID, &c.Title, &c.Description, &c.Severity, &c.Status,
		&c.Phase, &c.AssignedTo, &c.AssignedToName, &c.SLAHours,
		&c.SLABreachAt, &c.SLABreached, &c.MITRETactic, &c.MITRETechnique,
		&c.RCA, &c.ClosedAt, &c.CreatedAt, &c.UpdatedAt,
		&c.AlertCount, &c.CommentCount,
	)
	return c, err
}

func UpdateCase(c models.Case) error {
	_, err := database.DB.Exec(`
		UPDATE cases SET
		  title=$1, description=$2, severity=$3, status=$4, phase=$5,
		  assigned_to=$6, assigned_to_name=$7, sla_hours=$8,
		  mitre_tactic=$9, mitre_technique=$10, rca=$11,
		  closed_at=$12, updated_at=NOW()
		WHERE id=$13 AND tenant_id=$14
	`, c.Title, c.Description, c.Severity, c.Status, c.Phase,
		c.AssignedTo, c.AssignedToName, c.SLAHours,
		c.MITRETactic, c.MITRETechnique, c.RCA,
		c.ClosedAt, c.ID, c.TenantID,
	)
	return err
}

func DeleteCase(id, tenantID int) error {
	_, err := database.DB.Exec(`DELETE FROM cases WHERE id=$1 AND tenant_id=$2`, id, tenantID)
	return err
}

func LinkAlertToCase(caseID, alertID int) error {
	_, err := database.DB.Exec(
		`INSERT INTO case_alerts (case_id, alert_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`,
		caseID, alertID,
	)
	return err
}

func UnlinkAlertFromCase(caseID, alertID int) error {
	_, err := database.DB.Exec(`DELETE FROM case_alerts WHERE case_id=$1 AND alert_id=$2`, caseID, alertID)
	return err
}

func GetCaseAlerts(caseID, tenantID int) ([]models.Alert, error) {
	rows, err := database.DB.Query(`
		SELECT a.id, a.agent_id, a.severity, a.rule_name, a.log_message,
		       COALESCE(a.mitre_tactic,''), COALESCE(a.mitre_technique,''),
		       a.created_at
		FROM case_alerts ca
		JOIN alerts a ON a.id = ca.alert_id
		WHERE ca.case_id=$1 AND a.tenant_id=$2
		ORDER BY a.created_at DESC
	`, caseID, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []models.Alert{}
	for rows.Next() {
		var a models.Alert
		if err := rows.Scan(
			&a.ID, &a.AgentID, &a.Severity, &a.RuleName, &a.LogMessage,
			&a.MitreTactic, &a.MitreTechnique, &a.CreatedAt,
		); err == nil {
			out = append(out, a)
		}
	}
	return out, nil
}

func AddCaseComment(comment models.CaseComment) (models.CaseComment, error) {
	err := database.DB.QueryRow(`
		INSERT INTO case_comments (case_id, user_id, username, body, is_system)
		VALUES ($1,$2,$3,$4,$5)
		RETURNING id, created_at
	`, comment.CaseID, comment.UserID, comment.Username, comment.Body, comment.IsSystem,
	).Scan(&comment.ID, &comment.CreatedAt)
	return comment, err
}

func GetCaseComments(caseID, tenantID int) ([]models.CaseComment, error) {
	rows, err := database.DB.Query(`
		SELECT cc.id, cc.case_id, cc.user_id, cc.username, cc.body, cc.is_system, cc.created_at
		FROM case_comments cc
		JOIN cases c ON c.id = cc.case_id
		WHERE cc.case_id=$1 AND c.tenant_id=$2
		ORDER BY cc.created_at ASC
	`, caseID, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []models.CaseComment{}
	for rows.Next() {
		var c models.CaseComment
		if err := rows.Scan(&c.ID, &c.CaseID, &c.UserID, &c.Username, &c.Body, &c.IsSystem, &c.CreatedAt); err == nil {
			out = append(out, c)
		}
	}
	return out, nil
}

func AddCaseEvidence(ev models.CaseEvidence) (models.CaseEvidence, error) {
	err := database.DB.QueryRow(`
		INSERT INTO case_evidence (case_id, evidence_type, reference_id, title, description, added_by, added_by_name)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
		RETURNING id, created_at
	`, ev.CaseID, ev.EvidenceType, ev.ReferenceID, ev.Title, ev.Description, ev.AddedBy, ev.AddedByName,
	).Scan(&ev.ID, &ev.CreatedAt)
	return ev, err
}

func GetCaseEvidence(caseID, tenantID int) ([]models.CaseEvidence, error) {
	rows, err := database.DB.Query(`
		SELECT ce.id, ce.case_id, ce.evidence_type, ce.reference_id, ce.title,
		       COALESCE(ce.description,''), ce.added_by, ce.added_by_name, ce.created_at
		FROM case_evidence ce
		JOIN cases c ON c.id = ce.case_id
		WHERE ce.case_id=$1 AND c.tenant_id=$2
		ORDER BY ce.created_at DESC
	`, caseID, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []models.CaseEvidence{}
	for rows.Next() {
		var e models.CaseEvidence
		if err := rows.Scan(&e.ID, &e.CaseID, &e.EvidenceType, &e.ReferenceID, &e.Title,
			&e.Description, &e.AddedBy, &e.AddedByName, &e.CreatedAt); err == nil {
			out = append(out, e)
		}
	}
	return out, nil
}

// FindCasesBreachingSLA returns cases whose SLA deadline has passed but are not yet marked breached.
func FindCasesBreachingSLA() ([]models.Case, error) {
	rows, err := database.DB.Query(`
		SELECT id, tenant_id, title, severity, status, phase, sla_breach_at
		FROM cases
		WHERE sla_breach_at <= NOW()
		  AND sla_breached = false
		  AND status NOT IN ('closed', 'recovered')
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []models.Case{}
	for rows.Next() {
		var c models.Case
		if err := rows.Scan(&c.ID, &c.TenantID, &c.Title, &c.Severity, &c.Status, &c.Phase, &c.SLABreachAt); err == nil {
			out = append(out, c)
		}
	}
	return out, nil
}

func MarkCaseSLABreached(id int) error {
	_, err := database.DB.Exec(`UPDATE cases SET sla_breached=true, updated_at=NOW() WHERE id=$1`, id)
	return err
}

func GetCaseMetrics(tenantID int) (open, critical int, mttrHours float64, slaRate float64, err error) {
	database.DB.QueryRow(`SELECT COUNT(*) FROM cases WHERE tenant_id=$1 AND status NOT IN ('closed','recovered')`, tenantID).Scan(&open)
	database.DB.QueryRow(`SELECT COUNT(*) FROM cases WHERE tenant_id=$1 AND severity='critical' AND status NOT IN ('closed','recovered')`, tenantID).Scan(&critical)
	database.DB.QueryRow(`
		SELECT COALESCE(AVG(EXTRACT(EPOCH FROM (closed_at - created_at))/3600), 0)
		FROM cases WHERE tenant_id=$1 AND closed_at IS NOT NULL
	`, tenantID).Scan(&mttrHours)

	var total, compliant int
	database.DB.QueryRow(`SELECT COUNT(*) FROM cases WHERE tenant_id=$1 AND closed_at IS NOT NULL`, tenantID).Scan(&total)
	database.DB.QueryRow(`SELECT COUNT(*) FROM cases WHERE tenant_id=$1 AND closed_at IS NOT NULL AND sla_breached=false`, tenantID).Scan(&compliant)
	if total > 0 {
		slaRate = float64(compliant) / float64(total) * 100
	} else {
		slaRate = 100
	}
	return
}

func GetCasesGrouped(tenantID int, groupBy string) ([]models.LabelCount, error) {
	col := "severity"
	if groupBy == "phase" {
		col = "phase"
	} else if groupBy == "status" {
		col = "status"
	}
	rows, err := database.DB.Query(`
		SELECT `+col+`, COUNT(*) FROM cases
		WHERE tenant_id=$1 GROUP BY `+col+` ORDER BY COUNT(*) DESC
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []models.LabelCount{}
	for rows.Next() {
		var lc models.LabelCount
		if err := rows.Scan(&lc.Label, &lc.Count); err == nil {
			out = append(out, lc)
		}
	}
	return out, nil
}

func GetTopMITRETactics(tenantID int) ([]models.LabelCount, error) {
	rows, err := database.DB.Query(`
		SELECT mitre_tactic, COUNT(*) FROM cases
		WHERE tenant_id=$1 AND mitre_tactic != ''
		GROUP BY mitre_tactic ORDER BY COUNT(*) DESC LIMIT 8
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []models.LabelCount{}
	for rows.Next() {
		var lc models.LabelCount
		rows.Scan(&lc.Label, &lc.Count)
		out = append(out, lc)
	}
	return out, nil
}

func GetAlertVolumeLast30Days(tenantID int) ([]models.DailyCount, error) {
	rows, err := database.DB.Query(`
		SELECT TO_CHAR(created_at::date, 'YYYY-MM-DD'), COUNT(*)
		FROM alerts
		WHERE tenant_id=$1 AND created_at >= NOW() - INTERVAL '30 days'
		GROUP BY created_at::date
		ORDER BY created_at::date ASC
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []models.DailyCount{}
	for rows.Next() {
		var dc models.DailyCount
		rows.Scan(&dc.Date, &dc.Count)
		out = append(out, dc)
	}
	return out, nil
}

func GetRiskTrend(tenantID int) ([]models.DailyScore, error) {
	rows, err := database.DB.Query(`
		SELECT TO_CHAR(scored_at::date, 'YYYY-MM-DD'), AVG(score)
		FROM agent_anomaly_scores aas
		JOIN agents a ON a.id = aas.agent_id
		WHERE a.tenant_id=$1 AND aas.scored_at >= NOW() - INTERVAL '30 days'
		GROUP BY scored_at::date
		ORDER BY scored_at::date ASC
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []models.DailyScore{}
	for rows.Next() {
		var ds models.DailyScore
		rows.Scan(&ds.Date, &ds.Score)
		out = append(out, ds)
	}
	return out, nil
}

func GetMTTDHours(tenantID int) (float64, error) {
	// Proxy: avg time from alert creation to case creation for linked cases
	var h float64
	err := database.DB.QueryRow(`
		SELECT COALESCE(AVG(EXTRACT(EPOCH FROM (c.created_at - a.created_at))/3600), 0)
		FROM case_alerts ca
		JOIN cases c ON c.id = ca.case_id
		JOIN alerts a ON a.id = ca.alert_id
		WHERE c.tenant_id=$1 AND c.created_at > a.created_at
	`, tenantID).Scan(&h)
	return h, err
}

func SLAHoursForSeverity(severity string) int {
	switch severity {
	case "critical":
		return 4
	case "high":
		return 8
	case "low":
		return 72
	default: // medium
		return 24
	}
}

func SLABreachTime(severity string) time.Time {
	return time.Now().Add(time.Duration(SLAHoursForSeverity(severity)) * time.Hour)
}
