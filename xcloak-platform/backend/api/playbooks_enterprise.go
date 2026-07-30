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

func createPBTables() {
	database.DB.Exec(`CREATE TABLE IF NOT EXISTS pb_playbooks (
		id SERIAL PRIMARY KEY,
		tenant_id INTEGER NOT NULL,
		name TEXT NOT NULL,
		description TEXT,
		category TEXT DEFAULT 'custom',
		trigger_type TEXT DEFAULT 'manual',
		status TEXT DEFAULT 'draft',
		version TEXT DEFAULT '1.0.0',
		author TEXT,
		workflow JSONB DEFAULT '{"nodes":[],"edges":[]}',
		variables JSONB DEFAULT '{}',
		approval_policy TEXT DEFAULT 'automatic',
		execution_count INTEGER DEFAULT 0,
		success_count INTEGER DEFAULT 0,
		avg_runtime_s FLOAT DEFAULT 0,
		tags TEXT,
		created_at TIMESTAMPTZ DEFAULT NOW(),
		updated_at TIMESTAMPTZ DEFAULT NOW()
	)`)
	database.DB.Exec(`CREATE TABLE IF NOT EXISTS pb_executions (
		id SERIAL PRIMARY KEY,
		tenant_id INTEGER NOT NULL,
		playbook_id INTEGER NOT NULL,
		execution_id TEXT NOT NULL,
		status TEXT DEFAULT 'running',
		trigger_type TEXT,
		analyst TEXT,
		started_at TIMESTAMPTZ DEFAULT NOW(),
		ended_at TIMESTAMPTZ,
		duration_s FLOAT,
		failed_step TEXT,
		result JSONB DEFAULT '{}',
		step_log JSONB DEFAULT '[]',
		is_dry_run BOOLEAN DEFAULT false,
		created_at TIMESTAMPTZ DEFAULT NOW()
	)`)
	database.DB.Exec(`CREATE TABLE IF NOT EXISTS pb_approvals (
		id SERIAL PRIMARY KEY,
		tenant_id INTEGER NOT NULL,
		playbook_id INTEGER NOT NULL,
		execution_id TEXT,
		action TEXT,
		policy TEXT DEFAULT 'manager_approval',
		status TEXT DEFAULT 'pending',
		requestor TEXT,
		approver TEXT,
		notes TEXT,
		created_at TIMESTAMPTZ DEFAULT NOW(),
		decided_at TIMESTAMPTZ
	)`)
	database.DB.Exec(`CREATE TABLE IF NOT EXISTS pb_playbook_versions (
		id SERIAL PRIMARY KEY,
		tenant_id INTEGER NOT NULL,
		playbook_id INTEGER NOT NULL,
		version TEXT,
		author TEXT,
		status TEXT DEFAULT 'archived',
		changelog TEXT DEFAULT '',
		published_at TIMESTAMPTZ DEFAULT NOW()
	)`)
	database.DB.Exec(`CREATE TABLE IF NOT EXISTS pb_schedules (
		id SERIAL PRIMARY KEY,
		tenant_id INTEGER NOT NULL,
		playbook_id INTEGER NOT NULL,
		playbook_name TEXT,
		schedule_type TEXT DEFAULT 'daily',
		cron_expr TEXT,
		enabled BOOLEAN DEFAULT true,
		last_run TIMESTAMPTZ,
		next_run TIMESTAMPTZ,
		created_at TIMESTAMPTZ DEFAULT NOW()
	)`)
}

// GetPBDashboard — GET /api/pb/dashboard
func GetPBDashboard(c *gin.Context) {
	createPBTables()
	tid := tenantIDFromContext(c)
	type Stats struct {
		Total            int     `json:"total_playbooks"`
		Active           int     `json:"active_playbooks"`
		Draft            int     `json:"draft_playbooks"`
		Archived         int     `json:"archived_playbooks"`
		RunningExecs     int     `json:"running_executions"`
		SuccessfulRuns   int     `json:"successful_runs"`
		FailedRuns       int     `json:"failed_runs"`
		AvgExecTime      float64 `json:"avg_exec_time_s"`
		AutomationCov    float64 `json:"automation_coverage"`
		PendingApprovals int     `json:"pending_approvals"`
		TotalExecs       int     `json:"total_executions"`
	}
	var s Stats
	database.DB.QueryRow(`SELECT COUNT(*) FROM pb_playbooks WHERE tenant_id=$1`, tid).Scan(&s.Total)
	database.DB.QueryRow(`SELECT COUNT(*) FROM pb_playbooks WHERE tenant_id=$1 AND status='active'`, tid).Scan(&s.Active)
	database.DB.QueryRow(`SELECT COUNT(*) FROM pb_playbooks WHERE tenant_id=$1 AND status='draft'`, tid).Scan(&s.Draft)
	database.DB.QueryRow(`SELECT COUNT(*) FROM pb_playbooks WHERE tenant_id=$1 AND status='archived'`, tid).Scan(&s.Archived)
	database.DB.QueryRow(`SELECT COUNT(*) FROM pb_executions WHERE tenant_id=$1 AND status='running'`, tid).Scan(&s.RunningExecs)
	database.DB.QueryRow(`SELECT COUNT(*) FROM pb_executions WHERE tenant_id=$1 AND status='success'`, tid).Scan(&s.SuccessfulRuns)
	database.DB.QueryRow(`SELECT COUNT(*) FROM pb_executions WHERE tenant_id=$1 AND status='failed'`, tid).Scan(&s.FailedRuns)
	database.DB.QueryRow(`SELECT COUNT(*) FROM pb_executions WHERE tenant_id=$1`, tid).Scan(&s.TotalExecs)
	database.DB.QueryRow(`SELECT COALESCE(AVG(duration_s),0) FROM pb_executions WHERE tenant_id=$1 AND status='success'`, tid).Scan(&s.AvgExecTime)
	database.DB.QueryRow(`SELECT COUNT(*) FROM pb_approvals WHERE tenant_id=$1 AND status='pending'`, tid).Scan(&s.PendingApprovals)
	if s.Total > 0 {
		s.AutomationCov = float64(s.Active) / float64(s.Total) * 100
	}
	c.JSON(http.StatusOK, s)
}

// GetPBLibrary — GET /api/pb/library
func GetPBLibrary(c *gin.Context) {
	createPBTables()
	tid := tenantIDFromContext(c)
	limit := parseLimit(c, 50)
	q := `SELECT id,name,description,category,trigger_type,status,version,author,execution_count,success_count,avg_runtime_s,tags,created_at,updated_at
		FROM pb_playbooks WHERE tenant_id=$1`
	args := []interface{}{tid}
	i := 2
	if v := c.Query("status"); v != "" {
		q += fmt.Sprintf(" AND status=$%d", i)
		args = append(args, v)
		i++
	}
	if v := c.Query("category"); v != "" {
		q += fmt.Sprintf(" AND category=$%d", i)
		args = append(args, v)
		i++
	}
	q += fmt.Sprintf(" ORDER BY updated_at DESC LIMIT $%d", i)
	args = append(args, limit)
	rows, err := database.DB.Query(q, args...)
	type PB struct {
		ID             int     `json:"id"`
		Name           string  `json:"name"`
		Description    string  `json:"description"`
		Category       string  `json:"category"`
		TriggerType    string  `json:"trigger_type"`
		Status         string  `json:"status"`
		Version        string  `json:"version"`
		Author         string  `json:"author"`
		ExecutionCount int     `json:"execution_count"`
		SuccessCount   int     `json:"success_count"`
		AvgRuntimeS    float64 `json:"avg_runtime_s"`
		Tags           string  `json:"tags"`
		CreatedAt      string  `json:"created_at"`
		UpdatedAt      string  `json:"updated_at"`
	}
	list := []PB{}
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var p PB
			if rows.Scan(&p.ID, &p.Name, &p.Description, &p.Category, &p.TriggerType, &p.Status, &p.Version, &p.Author, &p.ExecutionCount, &p.SuccessCount, &p.AvgRuntimeS, &p.Tags, &p.CreatedAt, &p.UpdatedAt) == nil {
				list = append(list, p)
			}
		}
	}
	if list == nil {
		list = []PB{}
	}
	c.JSON(http.StatusOK, list)
}

// PostPBPlaybook — POST /api/pb/library
func PostPBPlaybook(c *gin.Context) {
	createPBTables()
	tid := tenantIDFromContext(c)
	var body struct {
		Name           string `json:"name"`
		Description    string `json:"description"`
		Category       string `json:"category"`
		TriggerType    string `json:"trigger_type"`
		ApprovalPolicy string `json:"approval_policy"`
		Tags           string `json:"tags"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name required"})
		return
	}
	if body.Category == "" {
		body.Category = "custom"
	}
	if body.TriggerType == "" {
		body.TriggerType = "manual"
	}
	if body.ApprovalPolicy == "" {
		body.ApprovalPolicy = "automatic"
	}
	author := usernameFromContext(c)
	var id int
	database.DB.QueryRow(`INSERT INTO pb_playbooks (tenant_id,name,description,category,trigger_type,approval_policy,author,tags)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id`,
		tid, body.Name, body.Description, body.Category, body.TriggerType, body.ApprovalPolicy, author, body.Tags).Scan(&id)
	c.JSON(http.StatusOK, gin.H{"id": id, "ok": true})
}

// GetPBPlaybook — GET /api/pb/library/:id
func GetPBPlaybook(c *gin.Context) {
	createPBTables()
	tid := tenantIDFromContext(c)
	pid, _ := strconv.Atoi(c.Param("id"))
	type PB struct {
		ID             int     `json:"id"`
		Name           string  `json:"name"`
		Description    string  `json:"description"`
		Category       string  `json:"category"`
		TriggerType    string  `json:"trigger_type"`
		Status         string  `json:"status"`
		Version        string  `json:"version"`
		Author         string  `json:"author"`
		Workflow       string  `json:"workflow"`
		Variables      string  `json:"variables"`
		ApprovalPolicy string  `json:"approval_policy"`
		ExecutionCount int     `json:"execution_count"`
		SuccessCount   int     `json:"success_count"`
		AvgRuntimeS    float64 `json:"avg_runtime_s"`
		Tags           string  `json:"tags"`
		CreatedAt      string  `json:"created_at"`
		UpdatedAt      string  `json:"updated_at"`
	}
	var p PB
	err := database.DB.QueryRow(`SELECT id,name,description,category,trigger_type,status,version,author,workflow::text,variables::text,approval_policy,execution_count,success_count,avg_runtime_s,tags,created_at,updated_at
		FROM pb_playbooks WHERE id=$1 AND tenant_id=$2`, pid, tid).Scan(&p.ID, &p.Name, &p.Description, &p.Category, &p.TriggerType, &p.Status, &p.Version, &p.Author, &p.Workflow, &p.Variables, &p.ApprovalPolicy, &p.ExecutionCount, &p.SuccessCount, &p.AvgRuntimeS, &p.Tags, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	c.JSON(http.StatusOK, p)
}

// PatchPBPlaybook — PATCH /api/pb/library/:id
func PatchPBPlaybook(c *gin.Context) {
	createPBTables()
	tid := tenantIDFromContext(c)
	pid, _ := strconv.Atoi(c.Param("id"))
	var body map[string]interface{}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	fields := []string{}
	vals := []interface{}{}
	i := 1
	for _, k := range []string{"name", "description", "category", "trigger_type", "status", "approval_policy", "tags"} {
		if v, ok := body[k]; ok {
			fields = append(fields, fmt.Sprintf("%s=$%d", k, i))
			vals = append(vals, v)
			i++
		}
	}
	if len(fields) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no fields"})
		return
	}
	fields = append(fields, fmt.Sprintf("updated_at=$%d", i))
	vals = append(vals, time.Now())
	i++
	vals = append(vals, pid, tid)
	database.DB.Exec(fmt.Sprintf(`UPDATE pb_playbooks SET %s WHERE id=$%d AND tenant_id=$%d`, strings.Join(fields, ","), i, i+1), vals...)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// DeletePBPlaybook — DELETE /api/pb/library/:id
func DeletePBPlaybook(c *gin.Context) {
	createPBTables()
	tid := tenantIDFromContext(c)
	pid, _ := strconv.Atoi(c.Param("id"))
	database.DB.Exec(`DELETE FROM pb_playbooks WHERE id=$1 AND tenant_id=$2`, pid, tid)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// PostPBPublish — POST /api/pb/library/:id/publish
func PostPBPublish(c *gin.Context) {
	createPBTables()
	tid := tenantIDFromContext(c)
	pid, _ := strconv.Atoi(c.Param("id"))
	var cur struct{ Version string }
	database.DB.QueryRow(`SELECT version FROM pb_playbooks WHERE id=$1 AND tenant_id=$2`, pid, tid).Scan(&cur.Version)
	parts := strings.Split(cur.Version, ".")
	minor := 0
	if len(parts) >= 2 {
		minor, _ = strconv.Atoi(parts[1])
	}
	newVer := fmt.Sprintf("%s.%d.0", parts[0], minor+1)
	database.DB.Exec(`UPDATE pb_playbooks SET status='active', version=$1, updated_at=NOW() WHERE id=$2 AND tenant_id=$3`, newVer, pid, tid)
	database.DB.Exec(`UPDATE pb_playbook_versions SET status='archived' WHERE tenant_id=$1 AND playbook_id=$2`, tid, pid)
	author := usernameFromContext(c)
	database.DB.Exec(`INSERT INTO pb_playbook_versions (tenant_id,playbook_id,version,author,status,changelog) VALUES ($1,$2,$3,$4,'active','Published from workflow builder')`,
		tid, pid, newVer, author)
	c.JSON(http.StatusOK, gin.H{"ok": true, "version": newVer})
}

// GetPBWorkflow — GET /api/pb/library/:id/workflow
func GetPBWorkflow(c *gin.Context) {
	createPBTables()
	tid := tenantIDFromContext(c)
	pid, _ := strconv.Atoi(c.Param("id"))
	var wf string
	database.DB.QueryRow(`SELECT workflow::text FROM pb_playbooks WHERE id=$1 AND tenant_id=$2`, pid, tid).Scan(&wf)
	if wf == "" {
		wf = `{"nodes":[],"edges":[]}`
	}
	c.Data(http.StatusOK, "application/json", []byte(wf))
}

// PatchPBWorkflow — PATCH /api/pb/library/:id/workflow
func PatchPBWorkflow(c *gin.Context) {
	createPBTables()
	tid := tenantIDFromContext(c)
	pid, _ := strconv.Atoi(c.Param("id"))
	body, _ := c.GetRawData()
	database.DB.Exec(`UPDATE pb_playbooks SET workflow=$1::jsonb, updated_at=NOW() WHERE id=$2 AND tenant_id=$3`, string(body), pid, tid)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// PostPBExecute — POST /api/pb/library/:id/execute
func PostPBExecute(c *gin.Context) {
	createPBTables()
	tid := tenantIDFromContext(c)
	pid, _ := strconv.Atoi(c.Param("id"))
	var body struct {
		TriggerType string `json:"trigger_type"`
		Variables   any    `json:"variables"`
	}
	c.ShouldBindJSON(&body)
	if body.TriggerType == "" {
		body.TriggerType = "manual"
	}
	var workflowJSON string
	if err := database.DB.QueryRow(`SELECT workflow::text FROM pb_playbooks WHERE id=$1 AND tenant_id=$2`, pid, tid).Scan(&workflowJSON); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "playbook not found"})
		return
	}
	analyst := usernameFromContext(c)
	execID := fmt.Sprintf("EX-%d-%06d", time.Now().Year(), time.Now().UnixNano()%1000000)
	var id int
	database.DB.QueryRow(`INSERT INTO pb_executions (tenant_id,playbook_id,execution_id,status,trigger_type,analyst)
		VALUES($1,$2,$3,'running',$4,$5) RETURNING id`, tid, pid, execID, body.TriggerType, analyst).Scan(&id)
	database.DB.Exec(`UPDATE pb_playbooks SET execution_count=execution_count+1, updated_at=NOW() WHERE id=$1 AND tenant_id=$2`, pid, tid)

	status, steps, durationS, failedStep := runPBWorkflow(tid, pid, execID, workflowJSON, false)
	stepLog, _ := json.Marshal(steps)
	if status == "pending" {
		database.DB.Exec(`UPDATE pb_executions SET status=$1, duration_s=$2, failed_step=$3, step_log=$4::jsonb WHERE id=$5 AND tenant_id=$6`,
			status, durationS, failedStep, string(stepLog), id, tid)
	} else {
		database.DB.Exec(`UPDATE pb_executions SET status=$1, ended_at=NOW(), duration_s=$2, failed_step=$3, step_log=$4::jsonb WHERE id=$5 AND tenant_id=$6`,
			status, durationS, failedStep, string(stepLog), id, tid)
	}
	if status == "success" {
		database.DB.Exec(`UPDATE pb_playbooks SET avg_runtime_s=(avg_runtime_s*success_count+$1)/(success_count+1), success_count=success_count+1 WHERE id=$2 AND tenant_id=$3`, durationS, pid, tid)
	}
	c.JSON(http.StatusOK, gin.H{"id": id, "execution_id": execID, "ok": true, "status": status})
}

// PostPBDryRun — POST /api/pb/library/:id/dry-run
func PostPBDryRun(c *gin.Context) {
	createPBTables()
	tid := tenantIDFromContext(c)
	pid, _ := strconv.Atoi(c.Param("id"))
	var body struct {
		Workflow json.RawMessage `json:"workflow"`
	}
	c.ShouldBindJSON(&body)
	workflowJSON := string(body.Workflow)
	if workflowJSON == "" || workflowJSON == "null" {
		database.DB.QueryRow(`SELECT workflow::text FROM pb_playbooks WHERE id=$1 AND tenant_id=$2`, pid, tid).Scan(&workflowJSON)
	}
	status, steps, durationS, _ := runPBWorkflow(tid, pid, "", workflowJSON, true)
	passed, failed := 0, 0
	warnings := []string{}
	for _, s := range steps {
		if s.Status == "failed" {
			failed++
		} else {
			passed++
		}
		if s.Status == "skipped" {
			warnings = append(warnings, fmt.Sprintf("%s: %s", s.Step, s.Message))
		}
	}
	c.JSON(http.StatusOK, gin.H{
		"ok":               status != "failed",
		"steps_passed":     passed,
		"steps_failed":     failed,
		"estimated_time_s": durationS,
		"warnings":         warnings,
		"step_results":     steps,
	})
}

// GetPBVersions — GET /api/pb/library/:id/versions
func GetPBVersions(c *gin.Context) {
	createPBTables()
	tid := tenantIDFromContext(c)
	pid, _ := strconv.Atoi(c.Param("id"))
	rows, err := database.DB.Query(`SELECT version,author,published_at,status,changelog FROM pb_playbook_versions WHERE tenant_id=$1 AND playbook_id=$2 ORDER BY published_at DESC`, tid, pid)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()
	type Ver struct {
		Version     string    `json:"version"`
		Author      string    `json:"author"`
		PublishedAt time.Time `json:"published_at"`
		Status      string    `json:"status"`
		Changelog   string    `json:"changelog"`
	}
	list := []Ver{}
	for rows.Next() {
		var v Ver
		if rows.Scan(&v.Version, &v.Author, &v.PublishedAt, &v.Status, &v.Changelog) == nil {
			list = append(list, v)
		}
	}
	c.JSON(http.StatusOK, list)
}

// GetPBExecutions — GET /api/pb/executions
func GetPBExecutions(c *gin.Context) {
	createPBTables()
	tid := tenantIDFromContext(c)
	limit := parseLimit(c, 50)
	rows, _ := database.DB.Query(`SELECT e.id,e.execution_id,e.status,e.trigger_type,e.analyst,e.started_at,e.ended_at,e.duration_s,e.failed_step,e.is_dry_run,p.name
		FROM pb_executions e LEFT JOIN pb_playbooks p ON e.playbook_id=p.id
		WHERE e.tenant_id=$1 ORDER BY e.created_at DESC LIMIT $2`, tid, limit)
	type Exec struct {
		ID           int     `json:"id"`
		ExecutionID  string  `json:"execution_id"`
		PlaybookName string  `json:"playbook_name"`
		Status       string  `json:"status"`
		TriggerType  string  `json:"trigger_type"`
		Analyst      string  `json:"analyst"`
		StartedAt    string  `json:"started_at"`
		EndedAt      *string `json:"ended_at"`
		DurationS    float64 `json:"duration_s"`
		FailedStep   string  `json:"failed_step"`
		IsDryRun     bool    `json:"is_dry_run"`
	}
	list := []Exec{}
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var e Exec
			if rows.Scan(&e.ID, &e.ExecutionID, &e.Status, &e.TriggerType, &e.Analyst, &e.StartedAt, &e.EndedAt, &e.DurationS, &e.FailedStep, &e.IsDryRun, &e.PlaybookName) == nil {
				list = append(list, e)
			}
		}
	}
	if list == nil {
		list = []Exec{}
	}
	c.JSON(http.StatusOK, list)
}

// GetPBExecutionByID — GET /api/pb/executions/:eid
func GetPBExecutionByID(c *gin.Context) {
	createPBTables()
	tid := tenantIDFromContext(c)
	eid, _ := strconv.Atoi(c.Param("eid"))
	type Exec struct {
		ID          int     `json:"id"`
		ExecutionID string  `json:"execution_id"`
		Status      string  `json:"status"`
		TriggerType string  `json:"trigger_type"`
		Analyst     string  `json:"analyst"`
		StartedAt   string  `json:"started_at"`
		EndedAt     *string `json:"ended_at"`
		DurationS   float64 `json:"duration_s"`
		FailedStep  string  `json:"failed_step"`
		StepLog     string  `json:"step_log"`
		IsDryRun    bool    `json:"is_dry_run"`
	}
	var e Exec
	err := database.DB.QueryRow(`SELECT id,execution_id,status,trigger_type,analyst,started_at,ended_at,duration_s,failed_step,step_log::text,is_dry_run
		FROM pb_executions WHERE id=$1 AND tenant_id=$2`, eid, tid).Scan(&e.ID, &e.ExecutionID, &e.Status, &e.TriggerType, &e.Analyst, &e.StartedAt, &e.EndedAt, &e.DurationS, &e.FailedStep, &e.StepLog, &e.IsDryRun)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	c.JSON(http.StatusOK, e)
}

// GetPBApprovals — GET /api/pb/approvals
func GetPBApprovals(c *gin.Context) {
	createPBTables()
	tid := tenantIDFromContext(c)
	rows, err := database.DB.Query(`SELECT a.id,a.execution_id,a.action,a.policy,a.status,a.requestor,COALESCE(a.approver,''),COALESCE(a.notes,''),a.created_at,COALESCE(p.name,'')
		FROM pb_approvals a LEFT JOIN pb_playbooks p ON a.playbook_id=p.id
		WHERE a.tenant_id=$1 ORDER BY a.created_at DESC LIMIT 50`, tid)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	type Approval struct {
		ID           int    `json:"id"`
		ExecutionID  string `json:"execution_id"`
		PlaybookName string `json:"playbook_name"`
		Action       string `json:"action"`
		Policy       string `json:"policy"`
		Status       string `json:"status"`
		Requestor    string `json:"requestor"`
		Approver     string `json:"approver"`
		Notes        string `json:"notes"`
		CreatedAt    string `json:"created_at"`
	}
	list := []Approval{}
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var a Approval
			if rows.Scan(&a.ID, &a.ExecutionID, &a.Action, &a.Policy, &a.Status, &a.Requestor, &a.Approver, &a.Notes, &a.CreatedAt, &a.PlaybookName) == nil {
				list = append(list, a)
			}
		}
	}
	if list == nil {
		list = []Approval{}
	}
	c.JSON(http.StatusOK, list)
}

// PostPBApprovalDecision — POST /api/pb/approvals/:aid/decision
func PostPBApprovalDecision(c *gin.Context) {
	createPBTables()
	tid := tenantIDFromContext(c)
	aid, _ := strconv.Atoi(c.Param("aid"))
	var body struct {
		Decision string `json:"decision"`
		Notes    string `json:"notes"`
	}
	c.ShouldBindJSON(&body)
	approver := usernameFromContext(c)
	database.DB.Exec(`UPDATE pb_approvals SET status=$1, approver=$2, notes=$3, decided_at=NOW() WHERE id=$4 AND tenant_id=$5`,
		body.Decision, approver, body.Notes, aid, tid)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// GetPBAnalytics — GET /api/pb/analytics
func GetPBAnalytics(c *gin.Context) {
	createPBTables()
	tid := tenantIDFromContext(c)
	var total, success, failed int
	var avgRuntime float64
	database.DB.QueryRow(`SELECT COUNT(*) FROM pb_executions WHERE tenant_id=$1`, tid).Scan(&total)
	database.DB.QueryRow(`SELECT COUNT(*) FROM pb_executions WHERE tenant_id=$1 AND status='success'`, tid).Scan(&success)
	database.DB.QueryRow(`SELECT COUNT(*) FROM pb_executions WHERE tenant_id=$1 AND status='failed'`, tid).Scan(&failed)
	database.DB.QueryRow(`SELECT COALESCE(AVG(duration_s),0) FROM pb_executions WHERE tenant_id=$1 AND status IN ('success','failed')`, tid).Scan(&avgRuntime)
	successRate := 0.0
	if total > 0 {
		successRate = float64(success) / float64(total) * 100
	}
	var totalPB, activePB int
	database.DB.QueryRow(`SELECT COUNT(*) FROM pb_playbooks WHERE tenant_id=$1`, tid).Scan(&totalPB)
	database.DB.QueryRow(`SELECT COUNT(*) FROM pb_playbooks WHERE tenant_id=$1 AND status='active'`, tid).Scan(&activePB)
	automationCov := 0.0
	if totalPB > 0 {
		automationCov = float64(activePB) / float64(totalPB) * 100
	}

	type usageRow struct {
		Name        string  `json:"name"`
		Runs        int     `json:"runs"`
		SuccessRate float64 `json:"success_rate"`
	}
	mostUsed := []usageRow{}
	uRows, _ := database.DB.Query(`
		SELECT name, execution_count, CASE WHEN execution_count>0 THEN success_count::float/execution_count*100 ELSE 0 END
		FROM pb_playbooks WHERE tenant_id=$1 AND execution_count>0 ORDER BY execution_count DESC LIMIT 5`, tid)
	if uRows != nil {
		defer uRows.Close()
		for uRows.Next() {
			var r usageRow
			if uRows.Scan(&r.Name, &r.Runs, &r.SuccessRate) == nil {
				mostUsed = append(mostUsed, r)
			}
		}
	}

	var manualCount, automatedCount int
	database.DB.QueryRow(`SELECT COUNT(*) FROM pb_executions WHERE tenant_id=$1 AND trigger_type='manual'`, tid).Scan(&manualCount)
	database.DB.QueryRow(`SELECT COUNT(*) FROM pb_executions WHERE tenant_id=$1 AND trigger_type!='manual'`, tid).Scan(&automatedCount)

	type failedStepRow struct {
		Step  string `json:"step"`
		Count int    `json:"count"`
	}
	failedSteps := []failedStepRow{}
	fRows, _ := database.DB.Query(`
		SELECT failed_step, COUNT(*) FROM pb_executions WHERE tenant_id=$1 AND status='failed' AND failed_step != ''
		GROUP BY failed_step ORDER BY COUNT(*) DESC LIMIT 5`, tid)
	if fRows != nil {
		defer fRows.Close()
		for fRows.Next() {
			var r failedStepRow
			if fRows.Scan(&r.Step, &r.Count) == nil {
				failedSteps = append(failedSteps, r)
			}
		}
	}

	type trendRow struct {
		Date    string `json:"date"`
		Runs    int    `json:"runs"`
		Success int    `json:"success"`
	}
	trend := []trendRow{}
	for i := 7; i >= 0; i-- {
		d := time.Now().AddDate(0, 0, -i)
		dayStr := d.Format("2006-01-02")
		var runs, succ int
		database.DB.QueryRow(`SELECT COUNT(*) FROM pb_executions WHERE tenant_id=$1 AND DATE(created_at)=$2`, tid, dayStr).Scan(&runs)
		database.DB.QueryRow(`SELECT COUNT(*) FROM pb_executions WHERE tenant_id=$1 AND DATE(created_at)=$2 AND status='success'`, tid, dayStr).Scan(&succ)
		trend = append(trend, trendRow{Date: d.Format("01-02"), Runs: runs, Success: succ})
	}

	c.JSON(http.StatusOK, gin.H{
		"success_rate":        successRate,
		"total_runs":          total,
		"successful_runs":     success,
		"failed_runs":         failed,
		"avg_runtime_s":       avgRuntime,
		"time_saved_h":        float64(success) * 0.75,
		"analyst_hours_saved": float64(success) * 0.5,
		"automation_coverage": automationCov,
		"most_used":           mostUsed,
		"manual_vs_automated": gin.H{"manual": manualCount, "automated": automatedCount},
		"failed_steps":        failedSteps,
		"trend":               trend,
	})
}

// GetPBTemplates — GET /api/pb/templates
func GetPBTemplates(c *gin.Context) {
	c.JSON(http.StatusOK, []interface{}{
		map[string]interface{}{"id": "ransomware", "name": "Ransomware Response", "icon": "🔐", "category": "incident_response", "description": "Automated ransomware containment — block C2, isolate endpoints, preserve evidence", "trigger": "alert_critical", "node_count": 12, "estimated_time_s": 90, "approval_policy": "dual_approval", "tags": "ransomware,critical,containment"},
		map[string]interface{}{"id": "phishing", "name": "Phishing Response", "icon": "🎣", "category": "email_security", "description": "Phishing email triage — pull headers, sandbox URL, block sender, notify users", "trigger": "alert_high", "node_count": 9, "estimated_time_s": 45, "approval_policy": "automatic", "tags": "phishing,email,awareness"},
		map[string]interface{}{"id": "malware", "name": "Malware Response", "icon": "🦠", "category": "endpoint", "description": "Malware detection → file quarantine, process kill, memory dump, threat intel lookup", "trigger": "ioc_match", "node_count": 10, "estimated_time_s": 60, "approval_policy": "manager_approval", "tags": "malware,edr,endpoint"},
		map[string]interface{}{"id": "insider_threat", "name": "Insider Threat", "icon": "👤", "category": "ueba", "description": "Insider risk — disable account, HR notification, legal hold, preserve audit logs", "trigger": "alert_high", "node_count": 8, "estimated_time_s": 30, "approval_policy": "dual_approval", "tags": "insider,hr,compliance"},
		map[string]interface{}{"id": "password_spray", "name": "Password Spray", "icon": "🔑", "category": "identity", "description": "Password spray detection → lock account, force MFA, alert AD team, threat hunt", "trigger": "alert_medium", "node_count": 7, "estimated_time_s": 20, "approval_policy": "automatic", "tags": "identity,ad,brute-force"},
		map[string]interface{}{"id": "cloud_incident", "name": "Cloud Incident", "icon": "☁", "category": "cloud", "description": "Cloud compromise → revoke credentials, snapshot instance, CloudTrail analysis, alert", "trigger": "alert_critical", "node_count": 11, "estimated_time_s": 75, "approval_policy": "security_approval", "tags": "cloud,aws,azure"},
		map[string]interface{}{"id": "data_exfil", "name": "Data Exfiltration", "icon": "📤", "category": "dlp", "description": "Data exfil detection → block egress, notify DLP team, legal hold, exec notification", "trigger": "alert_critical", "node_count": 10, "estimated_time_s": 40, "approval_policy": "dual_approval", "tags": "dlp,compliance,legal"},
		map[string]interface{}{"id": "web_shell", "name": "Web Shell Detection", "icon": "🐚", "category": "web_security", "description": "Web shell → collect IOCs, block process, snapshot server, notify DevOps", "trigger": "alert_high", "node_count": 8, "estimated_time_s": 35, "approval_policy": "automatic", "tags": "webshell,server,deface"},
	})
}

// GetPBMarketplace — GET /api/pb/marketplace
func GetPBMarketplace(c *gin.Context) {
	c.JSON(http.StatusOK, []interface{}{
		map[string]interface{}{"id": "crowdstrike-falcon", "name": "CrowdStrike Falcon", "vendor": "CrowdStrike", "icon": "🦅", "category": "edr", "description": "Full RTR response automation — isolate, collect, remediate directly via Falcon API", "downloads": 8421, "rating": 4.9, "tags": []interface{}{"edr", "endpoint", "falcon"}, "actions": []interface{}{"isolate_host", "collect_file", "run_rtr", "quarantine"}},
		map[string]interface{}{"id": "microsoft-defender", "name": "Microsoft Defender", "vendor": "Microsoft", "icon": "🛡", "category": "edr", "description": "Defender for Endpoint automation — isolate, investigate, hunt, remediate", "downloads": 6102, "rating": 4.7, "tags": []interface{}{"edr", "microsoft", "defender"}, "actions": []interface{}{"isolate", "collect_investigation", "run_av_scan", "live_response"}},
		map[string]interface{}{"id": "active-directory", "name": "Active Directory", "vendor": "Microsoft", "icon": "🏛", "category": "identity", "description": "AD automation — disable accounts, reset passwords, move OUs, audit groups", "downloads": 5543, "rating": 4.8, "tags": []interface{}{"ad", "identity", "ldap"}, "actions": []interface{}{"disable_user", "reset_password", "move_ou", "audit_groups"}},
		map[string]interface{}{"id": "aws-security", "name": "AWS Security", "vendor": "Amazon", "icon": "☁", "category": "cloud", "description": "AWS automation — revoke keys, snapshot EC2, quarantine SG, WAF rules", "downloads": 4219, "rating": 4.6, "tags": []interface{}{"aws", "cloud", "iam"}, "actions": []interface{}{"revoke_keys", "snapshot_ec2", "modify_sg", "waf_rule"}},
		map[string]interface{}{"id": "jira-tickets", "name": "Jira Integration", "vendor": "Atlassian", "icon": "🎫", "category": "ticketing", "description": "Auto-create Jira tickets with full incident context, links, and SLA tracking", "downloads": 7893, "rating": 4.5, "tags": []interface{}{"jira", "ticketing", "atlassian"}, "actions": []interface{}{"create_ticket", "update_ticket", "add_comment", "transition_status"}},
		map[string]interface{}{"id": "slack-notify", "name": "Slack Notifications", "vendor": "Slack", "icon": "💬", "category": "collaboration", "description": "Rich Slack notifications with incident details, action buttons, and approvals", "downloads": 9134, "rating": 4.9, "tags": []interface{}{"slack", "notify", "collaboration"}, "actions": []interface{}{"send_message", "create_channel", "post_alert", "request_approval"}},
		map[string]interface{}{"id": "pagerduty", "name": "PagerDuty", "vendor": "PagerDuty", "icon": "📟", "category": "alerting", "description": "PagerDuty incident creation, escalation policies, and on-call management", "downloads": 3876, "rating": 4.7, "tags": []interface{}{"pagerduty", "oncall", "escalation"}, "actions": []interface{}{"create_incident", "escalate", "resolve", "add_responder"}},
		map[string]interface{}{"id": "generic-rest", "name": "Generic REST API", "vendor": "XCloak", "icon": "🔌", "category": "integration", "description": "Universal REST action — call any HTTP API with auth, headers, body templating", "downloads": 11205, "rating": 4.6, "tags": []interface{}{"rest", "api", "universal"}, "actions": []interface{}{"http_get", "http_post", "http_put", "http_delete"}},
	})
}

// PostPBInstall — POST /api/pb/marketplace/:mid/install
func PostPBInstall(c *gin.Context) {
	createPBTables()
	tid := tenantIDFromContext(c)
	mid := c.Param("mid")
	author := usernameFromContext(c)
	var id int
	database.DB.QueryRow(`INSERT INTO pb_playbooks (tenant_id,name,description,category,author,status,tags)
		VALUES($1,$2,$3,'marketplace',$4,'draft',$5) RETURNING id`,
		tid, mid+" (Installed)", "Installed from XCloak Marketplace", author, mid).Scan(&id)
	c.JSON(http.StatusOK, gin.H{"ok": true, "playbook_id": id})
}

// GetPBSchedules — GET /api/pb/schedules
func GetPBSchedules(c *gin.Context) {
	createPBTables()
	tid := tenantIDFromContext(c)
	rows, _ := database.DB.Query(`SELECT s.id,s.playbook_id,s.playbook_name,s.schedule_type,s.cron_expr,s.enabled,s.last_run,s.next_run,p.name
		FROM pb_schedules s LEFT JOIN pb_playbooks p ON s.playbook_id=p.id
		WHERE s.tenant_id=$1 ORDER BY s.created_at DESC LIMIT 50`, tid)
	type Sched struct {
		ID           int     `json:"id"`
		PlaybookID   int     `json:"playbook_id"`
		PlaybookName string  `json:"playbook_name"`
		ScheduleType string  `json:"schedule_type"`
		CronExpr     string  `json:"cron_expr"`
		Enabled      bool    `json:"enabled"`
		LastRun      *string `json:"last_run"`
		NextRun      *string `json:"next_run"`
	}
	list := []Sched{}
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var s Sched
			var pbName string
			if rows.Scan(&s.ID, &s.PlaybookID, &s.PlaybookName, &s.ScheduleType, &s.CronExpr, &s.Enabled, &s.LastRun, &s.NextRun, &pbName) == nil {
				if s.PlaybookName == "" {
					s.PlaybookName = pbName
				}
				list = append(list, s)
			}
		}
	}
	if list == nil {
		list = []Sched{}
	}
	c.JSON(http.StatusOK, list)
}

// PostPBSchedule — POST /api/pb/schedules
func PostPBSchedule(c *gin.Context) {
	createPBTables()
	tid := tenantIDFromContext(c)
	var body struct {
		PlaybookID   int    `json:"playbook_id"`
		ScheduleType string `json:"schedule_type"`
		CronExpr     string `json:"cron_expr"`
	}
	c.ShouldBindJSON(&body)
	var pbName string
	database.DB.QueryRow(`SELECT name FROM pb_playbooks WHERE id=$1 AND tenant_id=$2`, body.PlaybookID, tid).Scan(&pbName)
	var id int
	database.DB.QueryRow(`INSERT INTO pb_schedules (tenant_id,playbook_id,playbook_name,schedule_type,cron_expr)
		VALUES($1,$2,$3,$4,$5) RETURNING id`, tid, body.PlaybookID, pbName, body.ScheduleType, body.CronExpr).Scan(&id)
	c.JSON(http.StatusOK, gin.H{"id": id, "ok": true})
}

// DeletePBSchedule — DELETE /api/pb/schedules/:sid
func DeletePBSchedule(c *gin.Context) {
	createPBTables()
	tid := tenantIDFromContext(c)
	sid, _ := strconv.Atoi(c.Param("sid"))
	database.DB.Exec(`DELETE FROM pb_schedules WHERE id=$1 AND tenant_id=$2`, sid, tid)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// GetPBIntegrations — GET /api/pb/integrations
func GetPBIntegrations(c *gin.Context) {
	c.JSON(http.StatusOK, []interface{}{
		map[string]interface{}{"category": "Security", "integrations": []interface{}{
			map[string]interface{}{"id": "active_directory", "name": "Active Directory", "status": "connected", "icon": "🏛"},
			map[string]interface{}{"id": "entra_id", "name": "Entra ID", "status": "connected", "icon": "🔷"},
			map[string]interface{}{"id": "firewall", "name": "Firewall", "status": "connected", "icon": "🔥"},
			map[string]interface{}{"id": "edr", "name": "EDR (CrowdStrike)", "status": "connected", "icon": "🦅"},
			map[string]interface{}{"id": "siem", "name": "SIEM", "status": "connected", "icon": "📊"},
			map[string]interface{}{"id": "threat_intel", "name": "Threat Intelligence", "status": "connected", "icon": "🕵"},
			map[string]interface{}{"id": "email_security", "name": "Email Security", "status": "connected", "icon": "📧"},
		}},
		map[string]interface{}{"category": "Collaboration", "integrations": []interface{}{
			map[string]interface{}{"id": "slack", "name": "Slack", "status": "connected", "icon": "💬"},
			map[string]interface{}{"id": "teams", "name": "Microsoft Teams", "status": "disconnected", "icon": "💼"},
			map[string]interface{}{"id": "jira", "name": "Jira", "status": "connected", "icon": "🎫"},
			map[string]interface{}{"id": "servicenow", "name": "ServiceNow", "status": "connected", "icon": "🎟"},
			map[string]interface{}{"id": "pagerduty", "name": "PagerDuty", "status": "connected", "icon": "📟"},
		}},
		map[string]interface{}{"category": "Cloud", "integrations": []interface{}{
			map[string]interface{}{"id": "aws", "name": "AWS", "status": "connected", "icon": "☁"},
			map[string]interface{}{"id": "azure", "name": "Azure", "status": "connected", "icon": "🔷"},
			map[string]interface{}{"id": "gcp", "name": "GCP", "status": "disconnected", "icon": "🌐"},
		}},
		map[string]interface{}{"category": "Infrastructure", "integrations": []interface{}{
			map[string]interface{}{"id": "ssh", "name": "SSH", "status": "connected", "icon": "🖥"},
			map[string]interface{}{"id": "rest_api", "name": "REST API", "status": "connected", "icon": "🔌"},
			map[string]interface{}{"id": "webhooks", "name": "Webhooks", "status": "connected", "icon": "🪝"},
		}},
	})
}

// PostPBAI — POST /api/pb/ai
func PostPBAI(c *gin.Context) {
	var body struct {
		Mode    string `json:"mode"`
		Content string `json:"content"`
		Context string `json:"context"`
	}
	c.ShouldBindJSON(&body)
	prompt := fmt.Sprintf(`You are a SOAR playbook expert. Mode: %s. Context: %s. User: %s.
Respond with a JSON object with fields: summary, workflow_suggestion (node steps), optimizations, explanation, warnings.
Keep response concise and actionable for a security analyst.`, body.Mode, body.Context, body.Content)
	raw, err := services.CallLLM(prompt)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"summary":             "Recommended 3-stage playbook: Alert triage → Approval gate → Automated response",
			"workflow_suggestion": []interface{}{"Trigger: Alert Created", "IF: severity=critical", "Approve Action", "Block IP", "Isolate Endpoint", "Create Ticket", "Send Email"},
			"optimizations":       []interface{}{"Add PARALLEL step to run Block IP and Send Email simultaneously", "Cache threat intel lookups to reduce API calls by 60%"},
			"explanation":         "This workflow provides immediate containment with human approval gate to prevent false-positive isolation.",
			"warnings":            []interface{}{"Ensure agent is online before Isolate Endpoint step", "Jira rate limits may delay ticket creation under load"},
		})
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

// PostPBReport — POST /api/pb/report
func PostPBReport(c *gin.Context) {
	createPBTables()
	tid := tenantIDFromContext(c)
	var body struct {
		ReportType string `json:"report_type"`
		Period     string `json:"period"`
		Context    string `json:"context"`
	}
	c.ShouldBindJSON(&body)
	if body.ReportType == "" {
		body.ReportType = "executive"
	}

	var total, success int
	var avgRuntime float64
	database.DB.QueryRow(`SELECT COUNT(*) FROM pb_executions WHERE tenant_id=$1`, tid).Scan(&total)
	database.DB.QueryRow(`SELECT COUNT(*) FROM pb_executions WHERE tenant_id=$1 AND status='success'`, tid).Scan(&success)
	database.DB.QueryRow(`SELECT COALESCE(AVG(duration_s),0) FROM pb_executions WHERE tenant_id=$1 AND status IN ('success','failed')`, tid).Scan(&avgRuntime)
	successRate := 0.0
	if total > 0 {
		successRate = float64(success) / float64(total) * 100
	}
	analystHoursSaved := float64(success) * 0.5

	type topPB struct {
		Name        string  `json:"name"`
		Runs        int     `json:"runs"`
		SuccessRate float64 `json:"success_rate"`
	}
	topPlaybooks := []topPB{}
	tRows, _ := database.DB.Query(`
		SELECT name, execution_count, CASE WHEN execution_count>0 THEN success_count::float/execution_count*100 ELSE 0 END
		FROM pb_playbooks WHERE tenant_id=$1 AND execution_count>0 ORDER BY execution_count DESC LIMIT 5`, tid)
	if tRows != nil {
		defer tRows.Close()
		for tRows.Next() {
			var r topPB
			if tRows.Scan(&r.Name, &r.Runs, &r.SuccessRate) == nil {
				topPlaybooks = append(topPlaybooks, r)
			}
		}
	}

	prompt := fmt.Sprintf(`You are a SOAR platform reporting assistant. Write a %s report for a security team based on these REAL metrics for this period: %d total playbook executions, %d successful, %.1f%% success rate, %.1fs average execution time, %.1f estimated analyst hours saved. Top playbooks by run count: %v. Respond as a JSON object with fields: executive_summary (2-3 sentences, grounded only in the numbers given, no invented incidents or figures), recommendations (a JSON array of up to 3 short actionable strings based on the real data given — if there isn't enough data, say so instead of inventing findings).`,
		body.ReportType, total, success, successRate, avgRuntime, analystHoursSaved, topPlaybooks)
	var summary string
	var recommendations []string
	raw, err := services.CallLLM(prompt)
	if err == nil {
		clean := raw
		if idx := strings.Index(clean, "```json"); idx != -1 {
			clean = clean[idx+7:]
		} else if idx := strings.Index(clean, "```"); idx != -1 {
			clean = clean[idx+3:]
		}
		if idx := strings.LastIndex(clean, "```"); idx != -1 {
			clean = clean[:idx]
		}
		var parsed struct {
			ExecutiveSummary string   `json:"executive_summary"`
			Recommendations  []string `json:"recommendations"`
		}
		if json.Unmarshal([]byte(strings.TrimSpace(clean)), &parsed) == nil {
			summary = parsed.ExecutiveSummary
			recommendations = parsed.Recommendations
		}
	}
	if summary == "" {
		if total == 0 {
			summary = "No playbook executions have been recorded for this tenant yet."
		} else {
			summary = fmt.Sprintf("The SOAR platform processed %d playbook executions this period, achieving a %.1f%% success rate and an estimated %.1f analyst hours saved.", total, successRate, analystHoursSaved)
		}
		recommendations = []string{}
	}

	c.JSON(http.StatusOK, gin.H{
		"title":             fmt.Sprintf("SOAR %s Report — %s", strings.Title(strings.ReplaceAll(body.ReportType, "_", " ")), time.Now().Format("Jan 2006")),
		"generated_at":      time.Now().Format(time.RFC3339),
		"report_type":       body.ReportType,
		"classification":    "CONFIDENTIAL",
		"executive_summary": summary,
		"key_metrics": gin.H{
			"total_executions":    total,
			"success_rate":        successRate,
			"analyst_hours_saved": analystHoursSaved,
			"avg_response_time_s": avgRuntime,
		},
		"top_playbooks":   topPlaybooks,
		"recommendations": recommendations,
	})
}
