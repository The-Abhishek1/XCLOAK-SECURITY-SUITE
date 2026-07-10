package services

import (
	"encoding/json"
	"log"
	"time"

	"xcloak-platform/database"
	"xcloak-platform/models"
)

// ── Hunt Templates ─────────────────────────────────────────────────────────

func CreateHuntTemplate(t models.HuntTemplate) (models.HuntTemplate, error) {
	err := database.DB.QueryRow(`
		INSERT INTO hunt_templates
		  (tenant_id, name, description, mitre_tactic, mitre_technique, kql_query, schedule, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		RETURNING id, tenant_id, name, description, mitre_tactic, mitre_technique,
		          kql_query, schedule, is_active, created_by, created_at, updated_at`,
		t.TenantID, t.Name, t.Description, t.MitreTactic, t.MitreTechnique,
		t.KQLQuery, t.Schedule, t.CreatedBy,
	).Scan(&t.ID, &t.TenantID, &t.Name, &t.Description, &t.MitreTactic, &t.MitreTechnique,
		&t.KQLQuery, &t.Schedule, &t.IsActive, &t.CreatedBy, &t.CreatedAt, &t.UpdatedAt)
	return t, err
}

func GetHuntTemplates(tenantID int) ([]models.HuntTemplate, error) {
	rows, err := database.DB.Query(`
		SELECT id, tenant_id, name, description, mitre_tactic, mitre_technique,
		       kql_query, schedule, is_active, created_by, created_at, updated_at
		FROM hunt_templates WHERE tenant_id=$1 ORDER BY updated_at DESC`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.HuntTemplate
	for rows.Next() {
		var t models.HuntTemplate
		rows.Scan(&t.ID, &t.TenantID, &t.Name, &t.Description, &t.MitreTactic, &t.MitreTechnique,
			&t.KQLQuery, &t.Schedule, &t.IsActive, &t.CreatedBy, &t.CreatedAt, &t.UpdatedAt)
		out = append(out, t)
	}
	return out, nil
}

func DeleteHuntTemplate(id, tenantID int) error {
	_, err := database.DB.Exec(`DELETE FROM hunt_templates WHERE id=$1 AND tenant_id=$2`, id, tenantID)
	return err
}

// ── Hunt Runs ──────────────────────────────────────────────────────────────

func GetHuntRuns(tenantID int) ([]models.HuntRun, error) {
	rows, err := database.DB.Query(`
		SELECT id, template_id, tenant_id, name, kql_query, status, hit_count,
		       findings::text, analyst, severity, notes, started_at, completed_at
		FROM hunt_runs WHERE tenant_id=$1 ORDER BY started_at DESC LIMIT 100`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanHuntRuns(rows)
}

func GetHuntRun(id, tenantID int) (models.HuntRun, error) {
	row := database.DB.QueryRow(`
		SELECT id, template_id, tenant_id, name, kql_query, status, hit_count,
		       findings::text, analyst, severity, notes, started_at, completed_at
		FROM hunt_runs WHERE id=$1 AND tenant_id=$2`, id, tenantID)
	runs, err := scanHuntRuns(singleRow{row})
	if err != nil || len(runs) == 0 {
		return models.HuntRun{}, err
	}
	return runs[0], nil
}

func UpdateHuntRunNotes(id, tenantID int, notes, severity string) error {
	_, err := database.DB.Exec(`
		UPDATE hunt_runs SET notes=$1, severity=$2 WHERE id=$3 AND tenant_id=$4`,
		notes, severity, id, tenantID)
	return err
}

// ExecuteHunt runs a KQL-lite query against endpoint_logs and saves results.
func ExecuteHunt(tenantID int, templateID *int, name, kqlQuery, analyst string) (models.HuntRun, error) {
	// Create run record
	var runID int
	err := database.DB.QueryRow(`
		INSERT INTO hunt_runs (tenant_id, template_id, name, kql_query, status, analyst)
		VALUES ($1,$2,$3,$4,'running',$5) RETURNING id`,
		tenantID, templateID, name, kqlQuery, analyst,
	).Scan(&runID)
	if err != nil {
		return models.HuntRun{}, err
	}

	go func() {
		findings, hitCount := runKQLHunt(tenantID, kqlQuery)
		findingsJSON, _ := json.Marshal(findings)
		now := time.Now()
		database.DB.Exec(`
			UPDATE hunt_runs SET status='completed', hit_count=$1, findings=$2, completed_at=$3
			WHERE id=$4`, hitCount, string(findingsJSON), now, runID)
		log.Printf("[Hunt] run #%d completed: %d hits", runID, hitCount)
	}()

	return GetHuntRun(runID, tenantID)
}

// runKQLHunt executes a search against endpoint_logs using the existing KQL parser.
func runKQLHunt(tenantID int, query string) ([]models.HuntFinding, int) {
	result, err := SearchLogs(LogSearchParams{
		TenantID: tenantID,
		Query:    query,
		Limit:    200,
	})
	if err != nil {
		log.Printf("[Hunt] KQL error: %v", err)
		return nil, 0
	}

	var findings []models.HuntFinding
	for _, r := range result.Logs {
		findings = append(findings, models.HuntFinding{
			LogID:     r.ID,
			AgentID:   r.AgentID,
			Hostname:  "",
			Source:    r.LogSource,
			Message:   r.LogMessage,
			Timestamp: r.CollectedAt.Format(time.RFC3339),
		})
	}
	return findings, len(findings)
}

// ── Scheduled Hunt Runner ──────────────────────────────────────────────────

func StartHuntScheduler() {
	go func() {
		for {
			time.Sleep(10 * time.Minute)
			rows, err := database.DB.Query(`
				SELECT id, tenant_id, name, kql_query, schedule, created_by
				FROM hunt_templates
				WHERE is_active=true AND schedule!='' AND schedule IS NOT NULL`)
			if err != nil {
				continue
			}
			for rows.Next() {
				var t models.HuntTemplate
				rows.Scan(&t.ID, &t.TenantID, &t.Name, &t.KQLQuery, &t.Schedule, &t.CreatedBy)
				if shouldRunHunt(t.Schedule) {
					ExecuteHunt(t.TenantID, &t.ID, t.Name+" (scheduled)", t.KQLQuery, "scheduler")
				}
			}
			rows.Close()
		}
	}()
}

// shouldRunHunt checks a 5-part cron expression against the current hour.
func shouldRunHunt(schedule string) bool {
	now := time.Now()
	return scheduleFired(schedule, nil, now)
}

// ── Helpers ────────────────────────────────────────────────────────────────

type rowScanner interface {
	Scan(dest ...any) error
}

type singleRow struct{ r rowScanner }

func (s singleRow) Next() bool        { return true }
func (s singleRow) Scan(d ...any) error { return s.r.Scan(d...) }
func (s singleRow) Close() error       { return nil }

type rowsIface interface {
	Next() bool
	Scan(dest ...any) error
	Close() error
}

func scanHuntRuns(rows rowsIface) ([]models.HuntRun, error) {
	defer rows.Close()
	var out []models.HuntRun
	for rows.Next() {
		var r models.HuntRun
		var findingsJSON string
		rows.Scan(&r.ID, &r.TemplateID, &r.TenantID, &r.Name, &r.KQLQuery,
			&r.Status, &r.HitCount, &findingsJSON, &r.Analyst, &r.Severity,
			&r.Notes, &r.StartedAt, &r.CompletedAt)
		json.Unmarshal([]byte(findingsJSON), &r.Findings)
		if r.Findings == nil {
			r.Findings = []models.HuntFinding{}
		}
		out = append(out, r)
	}
	return out, nil
}
