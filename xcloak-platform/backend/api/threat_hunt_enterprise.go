package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"xcloak-platform/database"
	"xcloak-platform/services"
)

// createThreatHuntTables ensures all required tables exist — idempotent.
func createThreatHuntTables() {
	database.DB.Exec(`
		CREATE TABLE IF NOT EXISTS threat_hunts (
			id SERIAL PRIMARY KEY,
			tenant_id INT NOT NULL,
			name VARCHAR(255) NOT NULL,
			description TEXT NOT NULL DEFAULT '',
			category VARCHAR(50) NOT NULL DEFAULT 'custom',
			sub_category VARCHAR(100) NOT NULL DEFAULT '',
			author VARCHAR(255) NOT NULL DEFAULT '',
			priority VARCHAR(50) NOT NULL DEFAULT 'medium',
			status VARCHAR(50) NOT NULL DEFAULT 'draft',
			mitre_techniques TEXT NOT NULL DEFAULT '',
			hypothesis TEXT NOT NULL DEFAULT '',
			objective TEXT NOT NULL DEFAULT '',
			expected_findings TEXT NOT NULL DEFAULT '',
			success_criteria TEXT NOT NULL DEFAULT '',
			scope TEXT NOT NULL DEFAULT '',
			query_type VARCHAR(50) NOT NULL DEFAULT 'log',
			query_text TEXT NOT NULL DEFAULT '',
			risk_level VARCHAR(50) NOT NULL DEFAULT 'medium',
			schedule_type VARCHAR(50) NOT NULL DEFAULT 'manual',
			cron_schedule VARCHAR(100) NOT NULL DEFAULT '',
			is_continuous BOOLEAN NOT NULL DEFAULT false,
			continuous_interval VARCHAR(50) NOT NULL DEFAULT '',
			assigned_analyst VARCHAR(255) NOT NULL DEFAULT '',
			review_status VARCHAR(50) NOT NULL DEFAULT 'pending',
			hit_count INT NOT NULL DEFAULT 0,
			run_count INT NOT NULL DEFAULT 0,
			success_count INT NOT NULL DEFAULT 0,
			false_positive_count INT NOT NULL DEFAULT 0,
			last_run_at TIMESTAMPTZ,
			next_run_at TIMESTAMPTZ,
			version INT NOT NULL DEFAULT 1,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`)
	database.DB.Exec(`
		CREATE TABLE IF NOT EXISTS threat_hunt_findings (
			id SERIAL PRIMARY KEY,
			tenant_id INT NOT NULL,
			hunt_id INT NOT NULL,
			hunt_name VARCHAR(255) NOT NULL DEFAULT '',
			severity VARCHAR(50) NOT NULL DEFAULT 'medium',
			confidence VARCHAR(50) NOT NULL DEFAULT 'medium',
			risk VARCHAR(50) NOT NULL DEFAULT 'medium',
			title TEXT NOT NULL DEFAULT '',
			description TEXT NOT NULL DEFAULT '',
			mitre_technique VARCHAR(50) NOT NULL DEFAULT '',
			affected_host VARCHAR(255) NOT NULL DEFAULT '',
			affected_user VARCHAR(255) NOT NULL DEFAULT '',
			ioc_value TEXT NOT NULL DEFAULT '',
			status VARCHAR(50) NOT NULL DEFAULT 'open',
			alert_id INT,
			incident_id INT,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`)
	database.DB.Exec(`
		CREATE TABLE IF NOT EXISTS threat_hunt_comments (
			id SERIAL PRIMARY KEY,
			tenant_id INT NOT NULL,
			hunt_id INT NOT NULL,
			author VARCHAR(255) NOT NULL DEFAULT '',
			content TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`)
}

// GetThreatHuntDashboard returns KPIs and recent activity for the threat hunt dashboard.
func GetThreatHuntDashboard(c *gin.Context) {
	tid := tenantIDFromContext(c)
	createThreatHuntTables()

	var total, draft, active, completed, archived, scheduled, continuous int
	database.DB.QueryRow(`
		SELECT COUNT(*),
		       COUNT(*) FILTER (WHERE status = 'draft'),
		       COUNT(*) FILTER (WHERE status = 'active'),
		       COUNT(*) FILTER (WHERE status = 'completed'),
		       COUNT(*) FILTER (WHERE status = 'archived'),
		       COUNT(*) FILTER (WHERE schedule_type != 'manual' AND schedule_type != ''),
		       COUNT(*) FILTER (WHERE is_continuous)
		FROM threat_hunts WHERE tenant_id = $1`, tid).
		Scan(&total, &draft, &active, &completed, &archived, &scheduled, &continuous)

	var iocHunts, ttpHunts, actorHunts int
	database.DB.QueryRow(`
		SELECT COUNT(*) FILTER (WHERE category = 'ioc'),
		       COUNT(*) FILTER (WHERE category = 'ttp'),
		       COUNT(*) FILTER (WHERE category = 'actor')
		FROM threat_hunts WHERE tenant_id = $1`, tid).
		Scan(&iocHunts, &ttpHunts, &actorHunts)

	var totalRuns, successfulRuns int
	database.DB.QueryRow(`
		SELECT COALESCE(SUM(run_count),0), COALESCE(SUM(success_count),0)
		FROM threat_hunts WHERE tenant_id = $1`, tid).
		Scan(&totalRuns, &successfulRuns)
	successRate := 0.0
	if totalRuns > 0 {
		successRate = float64(successfulRuns) / float64(totalRuns) * 100
	}

	var totalFindings, critFindings, highFindings, openFindings int
	database.DB.QueryRow(`
		SELECT COUNT(*),
		       COUNT(*) FILTER (WHERE severity = 'critical'),
		       COUNT(*) FILTER (WHERE severity = 'high'),
		       COUNT(*) FILTER (WHERE status = 'open')
		FROM threat_hunt_findings WHERE tenant_id = $1`, tid).
		Scan(&totalFindings, &critFindings, &highFindings, &openFindings)

	var newFindings int
	database.DB.QueryRow(`SELECT COUNT(*) FROM threat_hunt_findings WHERE tenant_id = $1 AND created_at > NOW() - INTERVAL '24 hours'`, tid).Scan(&newFindings)

	type recentHunt struct {
		ID       int    `json:"id"`
		Name     string `json:"name"`
		Category string `json:"category"`
		Status   string `json:"status"`
		HitCount int    `json:"hit_count"`
		RunAt    string `json:"run_at"`
	}
	rows, _ := database.DB.Query(`
		SELECT id, name, category, status, hit_count, COALESCE(last_run_at::text, created_at::text)
		FROM threat_hunts WHERE tenant_id = $1 AND last_run_at IS NOT NULL
		ORDER BY last_run_at DESC LIMIT 10`, tid)
	var recent []recentHunt
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var h recentHunt
			if rows.Scan(&h.ID, &h.Name, &h.Category, &h.Status, &h.HitCount, &h.RunAt) == nil {
				recent = append(recent, h)
			}
		}
	}
	if recent == nil {
		recent = []recentHunt{}
	}

	type trendPt struct {
		Date     string `json:"date"`
		Hunts    int    `json:"hunts"`
		Findings int    `json:"findings"`
	}
	trendRows, _ := database.DB.Query(`
		SELECT DATE_TRUNC('day', created_at)::date, COUNT(*), COALESCE(SUM(hit_count),0)
		FROM threat_hunts WHERE tenant_id = $1 AND created_at > NOW() - INTERVAL '30 days'
		GROUP BY 1 ORDER BY 1`, tid)
	var trend []trendPt
	if trendRows != nil {
		defer trendRows.Close()
		for trendRows.Next() {
			var d time.Time
			var tp trendPt
			if trendRows.Scan(&d, &tp.Hunts, &tp.Findings) == nil {
				tp.Date = d.Format("2006-01-02")
				trend = append(trend, tp)
			}
		}
	}
	if trend == nil {
		trend = []trendPt{}
	}

	c.JSON(http.StatusOK, gin.H{
		"total":          total,
		"draft":          draft,
		"active":         active,
		"completed":      completed,
		"archived":       archived,
		"scheduled":      scheduled,
		"continuous":     continuous,
		"ioc_hunts":      iocHunts,
		"ttp_hunts":      ttpHunts,
		"actor_hunts":    actorHunts,
		"total_runs":     totalRuns,
		"success_rate":   successRate,
		"findings":       totalFindings,
		"new_findings":   newFindings,
		"critical_finds": critFindings,
		"high_finds":     highFindings,
		"open_findings":  openFindings,
		"recent":         recent,
		"trend":          trend,
	})
}

// GetThreatHuntLibrary returns the full list of threat hunts for the tenant.
func GetThreatHuntLibrary(c *gin.Context) {
	tid := tenantIDFromContext(c)
	createThreatHuntTables()

	category := c.Query("category")
	status := c.Query("status")

	where := "WHERE tenant_id = $1"
	args := []interface{}{tid}
	if category != "" {
		args = append(args, category)
		where += fmt.Sprintf(" AND category = $%d", len(args))
	}
	if status != "" {
		args = append(args, status)
		where += fmt.Sprintf(" AND status = $%d", len(args))
	}

	rows, _ := database.DB.Query(`
		SELECT id, name, description, category, sub_category, author, priority, status, risk_level,
		       mitre_techniques, hit_count, run_count, success_count, false_positive_count,
		       is_continuous, schedule_type, assigned_analyst, review_status, version,
		       COALESCE(last_run_at::text,''), created_at
		FROM threat_hunts `+where+` ORDER BY updated_at DESC`, args...)

	type huntRow struct {
		ID               int     `json:"id"`
		Name             string  `json:"name"`
		Description      string  `json:"description"`
		Category         string  `json:"category"`
		SubCategory      string  `json:"sub_category"`
		Author           string  `json:"author"`
		Priority         string  `json:"priority"`
		Status           string  `json:"status"`
		RiskLevel        string  `json:"risk_level"`
		MitreTechniques  string  `json:"mitre_techniques"`
		HitCount         int     `json:"hit_count"`
		RunCount         int     `json:"run_count"`
		SuccessCount     int     `json:"success_count"`
		FPCount          int     `json:"false_positive_count"`
		IsContinuous     bool    `json:"is_continuous"`
		ScheduleType     string  `json:"schedule_type"`
		AssignedAnalyst  string  `json:"assigned_analyst"`
		ReviewStatus     string  `json:"review_status"`
		Version          int     `json:"version"`
		LastRunAt        string  `json:"last_run_at"`
		SuccessRate      float64 `json:"success_rate"`
		CreatedAt        string  `json:"created_at"`
	}
	var hunts []huntRow
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var h huntRow
			var createdAt time.Time
			if rows.Scan(&h.ID, &h.Name, &h.Description, &h.Category, &h.SubCategory, &h.Author,
				&h.Priority, &h.Status, &h.RiskLevel, &h.MitreTechniques, &h.HitCount, &h.RunCount,
				&h.SuccessCount, &h.FPCount, &h.IsContinuous, &h.ScheduleType, &h.AssignedAnalyst,
				&h.ReviewStatus, &h.Version, &h.LastRunAt, &createdAt) == nil {
				if h.RunCount > 0 {
					h.SuccessRate = float64(h.SuccessCount) / float64(h.RunCount) * 100
				}
				h.CreatedAt = createdAt.Format(time.RFC3339)
				hunts = append(hunts, h)
			}
		}
	}
	if hunts == nil {
		hunts = []huntRow{}
	}
	c.JSON(http.StatusOK, hunts)
}

// PostThreatHunt creates a new threat hunt.
func PostThreatHunt(c *gin.Context) {
	tid := tenantIDFromContext(c)
	user := usernameFromContext(c)
	createThreatHuntTables()

	var body struct {
		Name              string `json:"name"`
		Description       string `json:"description"`
		Category          string `json:"category"`
		SubCategory       string `json:"sub_category"`
		Priority          string `json:"priority"`
		Status            string `json:"status"`
		RiskLevel         string `json:"risk_level"`
		MitreTechniques   string `json:"mitre_techniques"`
		Hypothesis        string `json:"hypothesis"`
		Objective         string `json:"objective"`
		ExpectedFindings  string `json:"expected_findings"`
		SuccessCriteria   string `json:"success_criteria"`
		Scope             string `json:"scope"`
		QueryType         string `json:"query_type"`
		QueryText         string `json:"query_text"`
		ScheduleType      string `json:"schedule_type"`
		CronSchedule      string `json:"cron_schedule"`
		IsContinuous      bool   `json:"is_continuous"`
		ContinuousInterval string `json:"continuous_interval"`
		AssignedAnalyst   string `json:"assigned_analyst"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if body.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
		return
	}
	if body.Category == "" {
		body.Category = "custom"
	}
	if body.Priority == "" {
		body.Priority = "medium"
	}
	if body.Status == "" {
		body.Status = "active"
	}
	if body.RiskLevel == "" {
		body.RiskLevel = "medium"
	}
	if body.QueryType == "" {
		body.QueryType = "log"
	}
	if body.ScheduleType == "" {
		body.ScheduleType = "manual"
	}
	if body.AssignedAnalyst == "" {
		body.AssignedAnalyst = user
	}

	var id int
	err := database.DB.QueryRow(`
		INSERT INTO threat_hunts (
			tenant_id, name, description, category, sub_category, author, priority, status,
			risk_level, mitre_techniques, hypothesis, objective, expected_findings,
			success_criteria, scope, query_type, query_text, schedule_type, cron_schedule,
			is_continuous, continuous_interval, assigned_analyst
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22)
		RETURNING id`,
		tid, body.Name, body.Description, body.Category, body.SubCategory, user,
		body.Priority, body.Status, body.RiskLevel, body.MitreTechniques,
		body.Hypothesis, body.Objective, body.ExpectedFindings, body.SuccessCriteria,
		body.Scope, body.QueryType, body.QueryText, body.ScheduleType, body.CronSchedule,
		body.IsContinuous, body.ContinuousInterval, body.AssignedAnalyst,
	).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"id": id})
}

// GetThreatHunt returns full detail for a single threat hunt.
func GetThreatHunt(c *gin.Context) {
	tid := tenantIDFromContext(c)
	id, _ := strconv.Atoi(c.Param("id"))

	var h struct {
		ID               int     `json:"id"`
		Name             string  `json:"name"`
		Description      string  `json:"description"`
		Category         string  `json:"category"`
		SubCategory      string  `json:"sub_category"`
		Author           string  `json:"author"`
		Priority         string  `json:"priority"`
		Status           string  `json:"status"`
		RiskLevel        string  `json:"risk_level"`
		MitreTechniques  string  `json:"mitre_techniques"`
		Hypothesis       string  `json:"hypothesis"`
		Objective        string  `json:"objective"`
		ExpectedFindings string  `json:"expected_findings"`
		SuccessCriteria  string  `json:"success_criteria"`
		Scope            string  `json:"scope"`
		QueryType        string  `json:"query_type"`
		QueryText        string  `json:"query_text"`
		ScheduleType     string  `json:"schedule_type"`
		CronSchedule     string  `json:"cron_schedule"`
		IsContinuous     bool    `json:"is_continuous"`
		ContinuousInterval string `json:"continuous_interval"`
		AssignedAnalyst  string  `json:"assigned_analyst"`
		ReviewStatus     string  `json:"review_status"`
		HitCount         int     `json:"hit_count"`
		RunCount         int     `json:"run_count"`
		SuccessCount     int     `json:"success_count"`
		FPCount          int     `json:"false_positive_count"`
		Version          int     `json:"version"`
		SuccessRate      float64 `json:"success_rate"`
		LastRunAt        string  `json:"last_run_at"`
		CreatedAt        string  `json:"created_at"`
		UpdatedAt        string  `json:"updated_at"`
	}
	var createdAt, updatedAt time.Time
	err := database.DB.QueryRow(`
		SELECT id, name, description, category, sub_category, author, priority, status, risk_level,
		       mitre_techniques, hypothesis, objective, expected_findings, success_criteria,
		       scope, query_type, query_text, schedule_type, cron_schedule, is_continuous,
		       continuous_interval, assigned_analyst, review_status, hit_count, run_count,
		       success_count, false_positive_count, version,
		       COALESCE(last_run_at::text,''), created_at, updated_at
		FROM threat_hunts WHERE id = $1 AND tenant_id = $2`, id, tid).
		Scan(&h.ID, &h.Name, &h.Description, &h.Category, &h.SubCategory, &h.Author,
			&h.Priority, &h.Status, &h.RiskLevel, &h.MitreTechniques, &h.Hypothesis,
			&h.Objective, &h.ExpectedFindings, &h.SuccessCriteria, &h.Scope,
			&h.QueryType, &h.QueryText, &h.ScheduleType, &h.CronSchedule, &h.IsContinuous,
			&h.ContinuousInterval, &h.AssignedAnalyst, &h.ReviewStatus, &h.HitCount,
			&h.RunCount, &h.SuccessCount, &h.FPCount, &h.Version, &h.LastRunAt,
			&createdAt, &updatedAt)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "hunt not found"})
		return
	}
	if h.RunCount > 0 {
		h.SuccessRate = float64(h.SuccessCount) / float64(h.RunCount) * 100
	}
	h.CreatedAt = createdAt.Format(time.RFC3339)
	h.UpdatedAt = updatedAt.Format(time.RFC3339)
	c.JSON(http.StatusOK, h)
}

// PatchThreatHunt updates a threat hunt and increments its version.
func PatchThreatHunt(c *gin.Context) {
	tid := tenantIDFromContext(c)
	id, _ := strconv.Atoi(c.Param("id"))

	var body map[string]interface{}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Whitelist of updatable fields
	allowed := map[string]bool{
		"name": true, "description": true, "category": true, "sub_category": true,
		"priority": true, "status": true, "risk_level": true, "mitre_techniques": true,
		"hypothesis": true, "objective": true, "expected_findings": true,
		"success_criteria": true, "scope": true, "query_type": true, "query_text": true,
		"schedule_type": true, "cron_schedule": true, "is_continuous": true,
		"continuous_interval": true, "assigned_analyst": true, "review_status": true,
	}
	setClauses := []string{"version = version + 1", "updated_at = NOW()"}
	args := []interface{}{}
	for k, v := range body {
		if allowed[k] {
			args = append(args, v)
			setClauses = append(setClauses, fmt.Sprintf("%s = $%d", k, len(args)))
		}
	}
	if len(args) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no valid fields to update"})
		return
	}
	args = append(args, id, tid)
	_, err := database.DB.Exec(
		fmt.Sprintf("UPDATE threat_hunts SET %s WHERE id = $%d AND tenant_id = $%d",
			strings.Join(setClauses, ", "), len(args)-1, len(args)),
		args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// DeleteThreatHunt archives a hunt (soft delete via status=archived).
func DeleteThreatHunt(c *gin.Context) {
	tid := tenantIDFromContext(c)
	id, _ := strconv.Atoi(c.Param("id"))
	database.DB.Exec(`UPDATE threat_hunts SET status = 'archived', updated_at = NOW() WHERE id = $1 AND tenant_id = $2`, id, tid)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// PostThreatHuntExecute runs a threat hunt and creates findings from results.
func PostThreatHuntExecute(c *gin.Context) {
	tid := tenantIDFromContext(c)
	id, _ := strconv.Atoi(c.Param("id"))

	var name, queryType, queryText, mitreTechnique string
	err := database.DB.QueryRow(`
		SELECT name, query_type, query_text, mitre_techniques
		FROM threat_hunts WHERE id = $1 AND tenant_id = $2`, id, tid).
		Scan(&name, &queryType, &queryText, &mitreTechnique)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "hunt not found"})
		return
	}

	// Map enterprise query types to supported RunHuntQuery types
	execType := queryType
	switch queryType {
	case "kql", "elastic":
		execType = "log"
	case "powershell", "lolbins", "injection", "persistence":
		execType = "log"
	case "beaconing", "lateral":
		execType = "connection"
	case "lsass", "credential":
		execType = "process"
	case "ip", "domain", "url":
		execType = "connection"
	case "sha256", "md5":
		execType = "file_hash"
	case "email":
		execType = "log"
	case "ja3":
		execType = "connection"
	}

	// Validate execType is supported
	validTypes := map[string]bool{"process": true, "command": true, "connection": true, "user": true, "package": true, "log": true, "alert": true, "file_hash": true}
	if !validTypes[execType] {
		execType = "log"
	}

	result, svcErr := services.RunHuntQuery(0, execType, queryText, tid)
	hits := 0
	if result != nil {
		hits = result.Hits
	}

	// Update hunt stats
	if svcErr == nil {
		database.DB.Exec(`
			UPDATE threat_hunts SET
				run_count = run_count + 1,
				hit_count = hit_count + $1,
				success_count = success_count + $2,
				last_run_at = NOW(),
				status = CASE WHEN status = 'draft' THEN 'active' ELSE status END,
				updated_at = NOW()
			WHERE id = $3 AND tenant_id = $4`,
			hits, boolToInt(hits > 0), id, tid)
	}

	// Create findings from hits
	if hits > 0 && result != nil {
		mitreFirstTech := ""
		if mitreTechnique != "" {
			parts := strings.Split(mitreTechnique, ",")
			if len(parts) > 0 {
				mitreFirstTech = strings.TrimSpace(parts[0])
			}
		}
		for i, hit := range result.Results {
			if i >= 50 { // cap findings per run
				break
			}
			var data map[string]interface{}
			_ = json.Unmarshal(hit.Result, &data)
			hostname, _ := data["hostname"].(string)
			username, _ := data["username"].(string)
			if hostname == "" {
				hostname = fmt.Sprintf("agent-%d", hit.AgentID)
			}

			sev := "medium"
			if hits >= 10 {
				sev = "high"
			} else if hits >= 20 {
				sev = "critical"
			}

			database.DB.Exec(`
				INSERT INTO threat_hunt_findings
				(tenant_id, hunt_id, hunt_name, severity, confidence, risk, title, description,
				 mitre_technique, affected_host, affected_user, ioc_value)
				VALUES ($1,$2,$3,$4,'medium',$4,$5,$6,$7,$8,$9,$10)`,
				tid, id, name, sev,
				fmt.Sprintf("%s — hit in %s", name, hostname),
				fmt.Sprintf("Hunt '%s' matched on %s (agent %d)", name, queryText, hit.AgentID),
				mitreFirstTech, hostname, username, queryText)
		}
	}

	if svcErr != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": svcErr.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"hunt_id":   id,
		"hunt_name": name,
		"hits":      hits,
		"status":    "completed",
	})
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// GetThreatHuntFindings returns all findings for the tenant, optionally filtered.
func GetThreatHuntFindings(c *gin.Context) {
	tid := tenantIDFromContext(c)
	createThreatHuntTables()

	huntID := c.Query("hunt_id")
	sev := c.Query("severity")
	status := c.Query("status")

	where := "WHERE tenant_id = $1"
	args := []interface{}{tid}
	if huntID != "" {
		args = append(args, huntID)
		where += fmt.Sprintf(" AND hunt_id = $%d", len(args))
	}
	if sev != "" {
		args = append(args, sev)
		where += fmt.Sprintf(" AND severity = $%d", len(args))
	}
	if status != "" {
		args = append(args, status)
		where += fmt.Sprintf(" AND status = $%d", len(args))
	}

	rows, _ := database.DB.Query(`
		SELECT id, hunt_id, hunt_name, severity, confidence, risk, title, description,
		       mitre_technique, affected_host, affected_user, ioc_value, status, created_at
		FROM threat_hunt_findings `+where+` ORDER BY created_at DESC LIMIT 200`, args...)

	type finding struct {
		ID             int    `json:"id"`
		HuntID         int    `json:"hunt_id"`
		HuntName       string `json:"hunt_name"`
		Severity       string `json:"severity"`
		Confidence     string `json:"confidence"`
		Risk           string `json:"risk"`
		Title          string `json:"title"`
		Description    string `json:"description"`
		MitreTechnique string `json:"mitre_technique"`
		AffectedHost   string `json:"affected_host"`
		AffectedUser   string `json:"affected_user"`
		IOCValue       string `json:"ioc_value"`
		Status         string `json:"status"`
		CreatedAt      string `json:"created_at"`
	}
	var findings []finding
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var f finding
			if rows.Scan(&f.ID, &f.HuntID, &f.HuntName, &f.Severity, &f.Confidence, &f.Risk,
				&f.Title, &f.Description, &f.MitreTechnique, &f.AffectedHost, &f.AffectedUser,
				&f.IOCValue, &f.Status, &f.CreatedAt) == nil {
				findings = append(findings, f)
			}
		}
	}
	if findings == nil {
		findings = []finding{}
	}
	c.JSON(http.StatusOK, findings)
}

// PostThreatHuntFindingAck acknowledges or updates the status of a finding.
func PostThreatHuntFindingAck(c *gin.Context) {
	tid := tenantIDFromContext(c)
	fid, _ := strconv.Atoi(c.Param("fid"))
	var body struct {
		Status string `json:"status"` // open, acknowledged, false_positive, confirmed
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Status == "" {
		body.Status = "acknowledged"
	}
	database.DB.Exec(`UPDATE threat_hunt_findings SET status = $1 WHERE id = $2 AND tenant_id = $3`,
		body.Status, fid, tid)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// PostThreatHuntAI handles AI assistance for threat hunting.
func PostThreatHuntAI(c *gin.Context) {
	var body struct {
		Action     string `json:"action"` // suggest, improve_hypothesis, generate_query, summarize, recommend, generate_sigma
		HuntID     int    `json:"hunt_id"`
		HuntName   string `json:"hunt_name"`
		Hypothesis string `json:"hypothesis"`
		Category   string `json:"category"`
		Prompt     string `json:"prompt"`
		Context    string `json:"context"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var sysPrompt, userPrompt string
	switch body.Action {
	case "suggest":
		sysPrompt = `You are a threat hunting expert. Suggest threat hunts based on the context provided. Return JSON with fields: suggestions (array of {name, category, hypothesis, query_type, query_text, mitre_techniques, priority}), rationale (string).`
		userPrompt = fmt.Sprintf("Suggest relevant threat hunts for: %s\nCategory focus: %s", body.Prompt, body.Category)
	case "improve_hypothesis":
		sysPrompt = `You are a threat hunting expert. Improve the hunt hypothesis to be more specific, testable, and actionable. Return JSON with fields: improved_hypothesis (string), objective (string), expected_findings (string), success_criteria (string), mitre_techniques (array of strings).`
		userPrompt = fmt.Sprintf("Improve this hunt hypothesis:\nHunt: %s\nHypothesis: %s", body.HuntName, body.Hypothesis)
	case "generate_query":
		sysPrompt = `You are a threat hunting expert. Generate optimized hunt queries. Return JSON with fields: kql_query (string), process_query (string), log_query (string), sigma_rule (string), explanation (string), false_positive_notes (string).`
		userPrompt = fmt.Sprintf("Generate hunt queries for:\nHunt: %s\nHypothesis: %s\nContext: %s", body.HuntName, body.Hypothesis, body.Prompt)
	case "summarize":
		sysPrompt = `You are a threat hunting analyst. Summarize hunt findings for an executive report. Return JSON with fields: executive_summary (string), key_findings (array), risk_assessment (string), confidence (string), recommended_actions (array), next_steps (array).`
		userPrompt = fmt.Sprintf("Summarize findings for hunt '%s': %s", body.HuntName, body.Context)
	case "recommend":
		sysPrompt = `You are a threat hunting strategist. Recommend the next hunt based on current findings. Return JSON with fields: next_hunts (array of {name, rationale, priority, mitre_technique, category}), threat_landscape (string), coverage_gaps (array).`
		userPrompt = fmt.Sprintf("Recommend next hunts based on: %s\nCurrent context: %s", body.Prompt, body.Context)
	case "generate_sigma":
		sysPrompt = `You are a detection engineering expert. Generate a Sigma rule from the hunt description. Return JSON with fields: sigma_rule (string, YAML), description (string), tags (array), false_positive_rate (string).`
		userPrompt = fmt.Sprintf("Generate Sigma rule for hunt '%s':\nHypothesis: %s", body.HuntName, body.Hypothesis)
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "unknown action"})
		return
	}

	raw, err := services.CallLLM(sysPrompt + "\n\nUser: " + userPrompt)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if idx := strings.Index(raw, "```json"); idx != -1 {
		raw = raw[idx+7:]
	} else if idx := strings.Index(raw, "```"); idx != -1 {
		raw = raw[idx+3:]
	}
	if idx := strings.LastIndex(raw, "```"); idx != -1 {
		raw = raw[:idx]
	}
	c.Data(http.StatusOK, "application/json", []byte(strings.TrimSpace(raw)))
}

// GetThreatHuntMetrics returns analytics metrics for the hunt program.
func GetThreatHuntMetrics(c *gin.Context) {
	tid := tenantIDFromContext(c)

	type catStat struct {
		Category    string  `json:"category"`
		Total       int     `json:"total"`
		TotalHits   int     `json:"total_hits"`
		SuccessRate float64 `json:"success_rate"`
	}
	cRows, _ := database.DB.Query(`
		SELECT category, COUNT(*), COALESCE(SUM(hit_count),0),
		       COALESCE(SUM(success_count)::float/NULLIF(SUM(run_count),0)*100, 0)
		FROM threat_hunts WHERE tenant_id = $1
		GROUP BY category ORDER BY 2 DESC`, tid)
	var byCat []catStat
	if cRows != nil {
		defer cRows.Close()
		for cRows.Next() {
			var cs catStat
			if cRows.Scan(&cs.Category, &cs.Total, &cs.TotalHits, &cs.SuccessRate) == nil {
				byCat = append(byCat, cs)
			}
		}
	}
	if byCat == nil {
		byCat = []catStat{}
	}

	type analystStat struct {
		Analyst     string  `json:"analyst"`
		HuntCount   int     `json:"hunt_count"`
		TotalHits   int     `json:"total_hits"`
		SuccessRate float64 `json:"success_rate"`
	}
	aRows, _ := database.DB.Query(`
		SELECT COALESCE(NULLIF(assigned_analyst,''), author), COUNT(*), COALESCE(SUM(hit_count),0),
		       COALESCE(SUM(success_count)::float/NULLIF(SUM(run_count),0)*100, 0)
		FROM threat_hunts WHERE tenant_id = $1
		GROUP BY 1 ORDER BY 2 DESC LIMIT 10`, tid)
	var byAnalyst []analystStat
	if aRows != nil {
		defer aRows.Close()
		for aRows.Next() {
			var as analystStat
			if aRows.Scan(&as.Analyst, &as.HuntCount, &as.TotalHits, &as.SuccessRate) == nil {
				byAnalyst = append(byAnalyst, as)
			}
		}
	}
	if byAnalyst == nil {
		byAnalyst = []analystStat{}
	}

	type dailyPt struct {
		Date     string `json:"date"`
		Hunts    int    `json:"hunts"`
		Findings int    `json:"findings"`
	}
	dRows, _ := database.DB.Query(`
		SELECT DATE_TRUNC('day', thf.created_at)::date, COUNT(DISTINCT th.id), COUNT(thf.id)
		FROM threat_hunt_findings thf
		JOIN threat_hunts th ON th.id = thf.hunt_id
		WHERE thf.tenant_id = $1 AND thf.created_at > NOW() - INTERVAL '30 days'
		GROUP BY 1 ORDER BY 1`, tid)
	var daily []dailyPt
	if dRows != nil {
		defer dRows.Close()
		for dRows.Next() {
			var d time.Time
			var dp dailyPt
			if dRows.Scan(&d, &dp.Hunts, &dp.Findings) == nil {
				dp.Date = d.Format("2006-01-02")
				daily = append(daily, dp)
			}
		}
	}
	if daily == nil {
		daily = []dailyPt{}
	}

	c.JSON(http.StatusOK, gin.H{
		"by_category": byCat,
		"by_analyst":  byAnalyst,
		"daily":       daily,
	})
}

// GetThreatHuntCategories returns the category tree with per-category hunt counts.
func GetThreatHuntCategories(c *gin.Context) {
	tid := tenantIDFromContext(c)

	// Count existing hunts per category + sub_category
	type subCount struct{ sub string; cnt int }
	countMap := map[string]map[string]int{}
	rows, _ := database.DB.Query(`
		SELECT category, COALESCE(NULLIF(sub_category,''), 'other'), COUNT(*)
		FROM threat_hunts WHERE tenant_id = $1 GROUP BY 1,2`, tid)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var cat, sub string
			var cnt int
			if rows.Scan(&cat, &sub, &cnt) == nil {
				if countMap[cat] == nil {
					countMap[cat] = map[string]int{}
				}
				countMap[cat][sub] += cnt
			}
		}
	}

	type SubCat struct {
		Key   string `json:"key"`
		Label string `json:"label"`
		Count int    `json:"count"`
	}
	type Category struct {
		Key        string   `json:"key"`
		Label      string   `json:"label"`
		Icon       string   `json:"icon"`
		SubCats    []SubCat `json:"sub_categories"`
		TotalCount int      `json:"total_count"`
	}

	cats := []Category{
		{Key: "ioc", Label: "IOC Hunts", Icon: "🎯", SubCats: []SubCat{
			{Key: "ip", Label: "IP Address"}, {Key: "domain", Label: "Domain"}, {Key: "url", Label: "URL"},
			{Key: "sha256", Label: "SHA-256 Hash"}, {Key: "md5", Label: "MD5 Hash"},
			{Key: "email", Label: "Email"}, {Key: "ja3", Label: "JA3 Fingerprint"}, {Key: "certificate", Label: "Certificate"},
		}},
		{Key: "ttp", Label: "TTP Hunts", Icon: "⚔️", SubCats: []SubCat{
			{Key: "powershell", Label: "PowerShell"}, {Key: "persistence", Label: "Persistence"},
			{Key: "injection", Label: "Process Injection"}, {Key: "lsass", Label: "Credential Dumping"},
			{Key: "beaconing", Label: "C2 Beaconing"}, {Key: "lateral", Label: "Lateral Movement"}, {Key: "ransomware", Label: "Ransomware"},
		}},
		{Key: "actor", Label: "Threat Actor Hunts", Icon: "🕵️", SubCats: []SubCat{
			{Key: "apt29", Label: "APT29 (Cozy Bear)"}, {Key: "fin7", Label: "FIN7"}, {Key: "lazarus", Label: "Lazarus Group"},
			{Key: "scattered_spider", Label: "Scattered Spider"}, {Key: "custom", Label: "Custom Actor"},
		}},
		{Key: "malware", Label: "Malware Hunts", Icon: "🦠", SubCats: []SubCat{
			{Key: "cobalt_strike", Label: "Cobalt Strike"}, {Key: "sliver", Label: "Sliver"},
			{Key: "mimikatz", Label: "Mimikatz"}, {Key: "emotet", Label: "Emotet"}, {Key: "ransomware_family", Label: "Ransomware Families"},
		}},
		{Key: "cloud", Label: "Cloud Hunts", Icon: "☁️", SubCats: []SubCat{
			{Key: "aws_iam", Label: "AWS IAM Abuse"}, {Key: "azure_rbac", Label: "Azure RBAC Abuse"},
			{Key: "public_storage", Label: "Public Storage"}, {Key: "k8s_privesc", Label: "K8s Privilege Escalation"},
		}},
		{Key: "insider", Label: "Insider Hunts", Icon: "🔍", SubCats: []SubCat{
			{Key: "usb_copy", Label: "USB Copy"}, {Key: "data_exfil", Label: "Data Exfiltration"},
			{Key: "source_theft", Label: "Source Code Theft"}, {Key: "privilege_abuse", Label: "Privilege Abuse"},
		}},
	}

	for i, cat := range cats {
		total := 0
		for j, sub := range cat.SubCats {
			cnt := countMap[cat.Key][sub.Key]
			cats[i].SubCats[j].Count = cnt
			total += cnt
		}
		cats[i].TotalCount = total
	}

	c.JSON(http.StatusOK, gin.H{"categories": cats})
}

// PostThreatHuntSchedule configures scheduling for a threat hunt.
func PostThreatHuntSchedule(c *gin.Context) {
	tid := tenantIDFromContext(c)
	id, _ := strconv.Atoi(c.Param("id"))
	var body struct {
		ScheduleType       string `json:"schedule_type"`
		CronSchedule       string `json:"cron_schedule"`
		IsContinuous       bool   `json:"is_continuous"`
		ContinuousInterval string `json:"continuous_interval"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	database.DB.Exec(`
		UPDATE threat_hunts SET
			schedule_type = $1, cron_schedule = $2, is_continuous = $3,
			continuous_interval = $4, updated_at = NOW()
		WHERE id = $5 AND tenant_id = $6`,
		body.ScheduleType, body.CronSchedule, body.IsContinuous, body.ContinuousInterval, id, tid)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// PostThreatHuntExport exports hunt data in the requested format.
func PostThreatHuntExport(c *gin.Context) {
	tid := tenantIDFromContext(c)
	var body struct {
		HuntID int    `json:"hunt_id"`
		Format string `json:"format"` // csv, json, markdown, stix
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var name, category, hypothesis, mitre, queryText string
	var hitCount, runCount int
	database.DB.QueryRow(`
		SELECT name, category, hypothesis, mitre_techniques, query_text, hit_count, run_count
		FROM threat_hunts WHERE id = $1 AND tenant_id = $2`, body.HuntID, tid).
		Scan(&name, &category, &hypothesis, &mitre, &queryText, &hitCount, &runCount)

	switch body.Format {
	case "csv":
		var sb strings.Builder
		sb.WriteString("name,category,mitre_techniques,hit_count,run_count,query\n")
		sb.WriteString(fmt.Sprintf("%q,%s,%q,%d,%d,%q\n", name, category, mitre, hitCount, runCount, queryText))
		c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="hunt-%d.csv"`, body.HuntID))
		c.Data(http.StatusOK, "text/csv", []byte(sb.String()))
	case "markdown":
		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("# Threat Hunt: %s\n\n**Category:** %s  \n**MITRE:** %s  \n**Hits:** %d  \n**Runs:** %d\n\n", name, category, mitre, hitCount, runCount))
		if hypothesis != "" {
			sb.WriteString(fmt.Sprintf("## Hypothesis\n%s\n\n", hypothesis))
		}
		sb.WriteString(fmt.Sprintf("## Query\n```\n%s\n```\n", queryText))
		c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="hunt-%d.md"`, body.HuntID))
		c.Data(http.StatusOK, "text/markdown", []byte(sb.String()))
	case "stix":
		stix := fmt.Sprintf(`{"type":"bundle","id":"bundle--threat-hunt-%d","spec_version":"2.1","objects":[{"type":"threat-hunt","id":"hunt--%d","name":"%s","category":"%s","mitre_techniques":"%s","created":"2026-01-01T00:00:00Z"}]}`,
			body.HuntID, body.HuntID, name, category, mitre)
		c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="hunt-%d.stix.json"`, body.HuntID))
		c.Data(http.StatusOK, "application/json", []byte(stix))
	default: // json
		c.JSON(http.StatusOK, gin.H{"id": body.HuntID, "name": name, "category": category, "mitre_techniques": mitre, "hypothesis": hypothesis, "query_text": queryText, "hit_count": hitCount, "run_count": runCount})
	}
}

// PostThreatHuntResponse dispatches a response action from a hunt finding.
func PostThreatHuntResponse(c *gin.Context) {
	tid := tenantIDFromContext(c)
	user := usernameFromContext(c)
	var body struct {
		Action    string `json:"action"` // open_incident, open_case, isolate_host, block_ip, block_ioc, run_soar, hunt_similar
		HuntID    int    `json:"hunt_id"`
		FindingID int    `json:"finding_id"`
		Target    string `json:"target"`
		Reason    string `json:"reason"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	database.DB.Exec(`
		INSERT INTO audit_logs (tenant_id, user_id, action, resource_type, resource_id, details, created_at)
		VALUES ($1, 0, $2, 'threat_hunt_response', $3, $4, NOW()) ON CONFLICT DO NOTHING`,
		tid,
		fmt.Sprintf("threat_hunt.response.%s", body.Action),
		strconv.Itoa(body.HuntID),
		fmt.Sprintf(`{"action":"%s","target":"%s","finding_id":%d,"analyst":"%s","reason":"%s"}`,
			body.Action, body.Target, body.FindingID, user, body.Reason),
	)

	c.JSON(http.StatusOK, gin.H{
		"queued":  true,
		"action":  body.Action,
		"target":  body.Target,
		"message": fmt.Sprintf("Response action '%s' queued for target '%s'", body.Action, body.Target),
	})
}

// PostThreatHuntComment adds a comment to a threat hunt.
func PostThreatHuntComment(c *gin.Context) {
	tid := tenantIDFromContext(c)
	user := usernameFromContext(c)
	id, _ := strconv.Atoi(c.Param("id"))
	var body struct {
		Content string `json:"content"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Content == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "content is required"})
		return
	}
	var cid int
	database.DB.QueryRow(`
		INSERT INTO threat_hunt_comments (tenant_id, hunt_id, author, content)
		VALUES ($1,$2,$3,$4) RETURNING id`,
		tid, id, user, body.Content).Scan(&cid)
	c.JSON(http.StatusOK, gin.H{"id": cid})
}

// GetThreatHuntComments returns comments for a hunt.
func GetThreatHuntComments(c *gin.Context) {
	tid := tenantIDFromContext(c)
	id, _ := strconv.Atoi(c.Param("id"))

	type comment struct {
		ID        int    `json:"id"`
		Author    string `json:"author"`
		Content   string `json:"content"`
		CreatedAt string `json:"created_at"`
	}
	rows, _ := database.DB.Query(`
		SELECT id, author, content, created_at
		FROM threat_hunt_comments WHERE tenant_id = $1 AND hunt_id = $2
		ORDER BY created_at ASC`, tid, id)
	var comments []comment
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var co comment
			if rows.Scan(&co.ID, &co.Author, &co.Content, &co.CreatedAt) == nil {
				comments = append(comments, co)
			}
		}
	}
	if comments == nil {
		comments = []comment{}
	}
	c.JSON(http.StatusOK, comments)
}
