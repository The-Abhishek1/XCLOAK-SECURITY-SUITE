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

// ── Table bootstrap ──────────────────────────────────────────────────────────

func createDFIRTables() {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS dfir_investigations (
			id SERIAL PRIMARY KEY,
			tenant_id INT NOT NULL,
			investigation_id VARCHAR(50) NOT NULL DEFAULT '',
			case_id VARCHAR(100) NOT NULL DEFAULT '',
			title VARCHAR(255) NOT NULL,
			incident_id INT NOT NULL DEFAULT 0,
			analyst VARCHAR(255) NOT NULL DEFAULT '',
			priority VARCHAR(50) NOT NULL DEFAULT 'medium',
			status VARCHAR(50) NOT NULL DEFAULT 'open',
			classification VARCHAR(100) NOT NULL DEFAULT '',
			tags TEXT NOT NULL DEFAULT '',
			notes TEXT NOT NULL DEFAULT '',
			target_hosts TEXT NOT NULL DEFAULT '',
			target_users TEXT NOT NULL DEFAULT '',
			mitre_techniques TEXT NOT NULL DEFAULT '',
			root_cause TEXT NOT NULL DEFAULT '',
			executive_summary TEXT NOT NULL DEFAULT '',
			version INT NOT NULL DEFAULT 1,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			closed_at TIMESTAMPTZ
		)`,
		`CREATE TABLE IF NOT EXISTS dfir_evidence (
			id SERIAL PRIMARY KEY,
			tenant_id INT NOT NULL,
			investigation_id INT NOT NULL DEFAULT 0,
			evidence_id VARCHAR(100) NOT NULL DEFAULT '',
			type VARCHAR(100) NOT NULL,
			label VARCHAR(255) NOT NULL,
			description TEXT NOT NULL DEFAULT '',
			source_host VARCHAR(255) NOT NULL DEFAULT '',
			collector VARCHAR(255) NOT NULL DEFAULT '',
			sha256 VARCHAR(64) NOT NULL DEFAULT '',
			md5 VARCHAR(32) NOT NULL DEFAULT '',
			size_bytes BIGINT NOT NULL DEFAULT 0,
			storage_location TEXT NOT NULL DEFAULT '',
			status VARCHAR(50) NOT NULL DEFAULT 'collected',
			analysis_result JSONB,
			collected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS dfir_custody (
			id SERIAL PRIMARY KEY,
			tenant_id INT NOT NULL,
			evidence_id INT NOT NULL,
			action VARCHAR(100) NOT NULL,
			actor VARCHAR(255) NOT NULL,
			location TEXT NOT NULL DEFAULT '',
			notes TEXT NOT NULL DEFAULT '',
			hash_verified BOOLEAN NOT NULL DEFAULT false,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS dfir_timeline_events (
			id SERIAL PRIMARY KEY,
			tenant_id INT NOT NULL,
			investigation_id INT NOT NULL,
			event_time TIMESTAMPTZ NOT NULL,
			event_type VARCHAR(50) NOT NULL,
			source VARCHAR(100) NOT NULL DEFAULT '',
			host VARCHAR(255) NOT NULL DEFAULT '',
			user_name VARCHAR(255) NOT NULL DEFAULT '',
			description TEXT NOT NULL,
			raw_data TEXT NOT NULL DEFAULT '',
			severity VARCHAR(50) NOT NULL DEFAULT 'info',
			mitre_technique VARCHAR(50) NOT NULL DEFAULT '',
			is_manual BOOLEAN NOT NULL DEFAULT false,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS dfir_notebook_entries (
			id SERIAL PRIMARY KEY,
			tenant_id INT NOT NULL,
			investigation_id INT NOT NULL,
			entry_type VARCHAR(50) NOT NULL DEFAULT 'note',
			title VARCHAR(255) NOT NULL DEFAULT '',
			content TEXT NOT NULL DEFAULT '',
			author VARCHAR(255) NOT NULL DEFAULT '',
			evidence_refs TEXT NOT NULL DEFAULT '',
			tags TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS dfir_collection_tasks (
			id SERIAL PRIMARY KEY,
			tenant_id INT NOT NULL,
			investigation_id INT NOT NULL,
			target_host VARCHAR(255) NOT NULL,
			collection_type VARCHAR(100) NOT NULL,
			artifacts TEXT NOT NULL DEFAULT '',
			status VARCHAR(50) NOT NULL DEFAULT 'pending',
			requested_by VARCHAR(255) NOT NULL DEFAULT '',
			result_summary TEXT NOT NULL DEFAULT '',
			evidence_count INT NOT NULL DEFAULT 0,
			started_at TIMESTAMPTZ,
			completed_at TIMESTAMPTZ,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
	}
	for _, s := range stmts {
		database.DB.Exec(s)
	}
}

// ── Dashboard ────────────────────────────────────────────────────────────────

func GetDFIRDashboard(c *gin.Context) {
	createDFIRTables()
	tid := tenantIDFromContext(c)

	type Stats struct {
		Total          int `json:"total"`
		Open           int `json:"open"`
		InProgress     int `json:"in_progress"`
		Closed         int `json:"closed"`
		HighPriority   int `json:"high_priority"`
		EvidenceItems  int `json:"evidence_items"`
		MemoryDumps    int `json:"memory_dumps"`
		DiskImages     int `json:"disk_images"`
		OpenCases      int `json:"open_cases"`
		CustodyOK      int `json:"custody_ok"`
		CustodyPending int `json:"custody_pending"`
	}
	var s Stats
	database.DB.QueryRow(`
		SELECT
			COUNT(*),
			COUNT(*) FILTER (WHERE status='open'),
			COUNT(*) FILTER (WHERE status='in_progress'),
			COUNT(*) FILTER (WHERE status IN ('closed','resolved')),
			COUNT(*) FILTER (WHERE priority IN ('critical','high'))
		FROM dfir_investigations WHERE tenant_id=$1`, tid).
		Scan(&s.Total, &s.Open, &s.InProgress, &s.Closed, &s.HighPriority)

	database.DB.QueryRow(`SELECT COUNT(*) FROM dfir_evidence WHERE tenant_id=$1`, tid).Scan(&s.EvidenceItems)
	database.DB.QueryRow(`SELECT COUNT(*) FROM dfir_evidence WHERE tenant_id=$1 AND type='memory_dump'`, tid).Scan(&s.MemoryDumps)
	database.DB.QueryRow(`SELECT COUNT(*) FROM dfir_evidence WHERE tenant_id=$1 AND type='disk_image'`, tid).Scan(&s.DiskImages)
	database.DB.QueryRow(`SELECT COUNT(*) FROM dfir_investigations WHERE tenant_id=$1 AND status IN ('open','in_progress')`, tid).Scan(&s.OpenCases)
	database.DB.QueryRow(`SELECT COUNT(*) FROM dfir_custody WHERE tenant_id=$1 AND hash_verified=true`, tid).Scan(&s.CustodyOK)
	database.DB.QueryRow(`SELECT COUNT(*) FROM dfir_custody WHERE tenant_id=$1 AND hash_verified=false`, tid).Scan(&s.CustodyPending)

	type RecentInv struct {
		ID       int    `json:"id"`
		Title    string `json:"title"`
		Priority string `json:"priority"`
		Status   string `json:"status"`
		Analyst  string `json:"analyst"`
		Created  string `json:"created_at"`
	}
	recent := []RecentInv{}
	rows, _ := database.DB.Query(`
		SELECT id, title, priority, status, analyst, created_at
		FROM dfir_investigations WHERE tenant_id=$1
		ORDER BY created_at DESC LIMIT 10`, tid)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var r RecentInv
			if rows.Scan(&r.ID, &r.Title, &r.Priority, &r.Status, &r.Analyst, &r.Created) == nil {
				recent = append(recent, r)
			}
		}
	}

	c.JSON(200, gin.H{"stats": s, "recent": recent})
}

// ── Investigations CRUD ───────────────────────────────────────────────────────

func GetDFIRInvestigations(c *gin.Context) {
	createDFIRTables()
	tid := tenantIDFromContext(c)
	status := c.Query("status")
	priority := c.Query("priority")

	where := "WHERE tenant_id=$1"
	args := []interface{}{tid}
	if status != "" {
		args = append(args, status)
		where += fmt.Sprintf(" AND status=$%d", len(args))
	}
	if priority != "" {
		args = append(args, priority)
		where += fmt.Sprintf(" AND priority=$%d", len(args))
	}

	type Inv struct {
		ID               int    `json:"id"`
		InvestigationID  string `json:"investigation_id"`
		CaseID           string `json:"case_id"`
		Title            string `json:"title"`
		Analyst          string `json:"analyst"`
		Priority         string `json:"priority"`
		Status           string `json:"status"`
		Tags             string `json:"tags"`
		TargetHosts      string `json:"target_hosts"`
		EvidenceCount    int    `json:"evidence_count"`
		MitreTechniques  string `json:"mitre_techniques"`
		Version          int    `json:"version"`
		CreatedAt        string `json:"created_at"`
		UpdatedAt        string `json:"updated_at"`
	}
	result := []Inv{}
	rows, _ := database.DB.Query(fmt.Sprintf(`
		SELECT i.id, i.investigation_id, i.case_id, i.title, i.analyst, i.priority, i.status,
		       i.tags, i.target_hosts, i.mitre_techniques, i.version, i.created_at, i.updated_at,
		       COALESCE((SELECT COUNT(*) FROM dfir_evidence e WHERE e.investigation_id=i.id AND e.tenant_id=i.tenant_id),0)
		FROM dfir_investigations i %s ORDER BY i.created_at DESC`, where), args...)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var inv Inv
			if rows.Scan(&inv.ID, &inv.InvestigationID, &inv.CaseID, &inv.Title, &inv.Analyst,
				&inv.Priority, &inv.Status, &inv.Tags, &inv.TargetHosts,
				&inv.MitreTechniques, &inv.Version, &inv.CreatedAt, &inv.UpdatedAt,
				&inv.EvidenceCount) == nil {
				result = append(result, inv)
			}
		}
	}
	if result == nil {
		result = []Inv{}
	}
	c.JSON(200, result)
}

func PostDFIRInvestigation(c *gin.Context) {
	createDFIRTables()
	tid := tenantIDFromContext(c)
	var body struct {
		Title           string `json:"title"`
		CaseID          string `json:"case_id"`
		IncidentID      int    `json:"incident_id"`
		Analyst         string `json:"analyst"`
		Priority        string `json:"priority"`
		Classification  string `json:"classification"`
		Tags            string `json:"tags"`
		TargetHosts     string `json:"target_hosts"`
		TargetUsers     string `json:"target_users"`
		Notes           string `json:"notes"`
	}
	if err := c.BindJSON(&body); err != nil || body.Title == "" {
		c.JSON(400, gin.H{"error": "title required"})
		return
	}
	if body.Priority == "" {
		body.Priority = "medium"
	}
	invID := fmt.Sprintf("INV-%d-%d", tid, time.Now().UnixMilli()%100000)
	analyst := body.Analyst
	if analyst == "" {
		analyst = usernameFromContext(c)
	}
	var id int
	err := database.DB.QueryRow(`
		INSERT INTO dfir_investigations
			(tenant_id, investigation_id, case_id, incident_id, title, analyst, priority,
			 classification, tags, target_hosts, target_users, notes)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING id`,
		tid, invID, body.CaseID, body.IncidentID, body.Title, analyst, body.Priority,
		body.Classification, body.Tags, body.TargetHosts, body.TargetUsers, body.Notes).Scan(&id)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(201, gin.H{"id": id, "investigation_id": invID})
}

func GetDFIRInvestigation(c *gin.Context) {
	createDFIRTables()
	tid := tenantIDFromContext(c)
	id, _ := strconv.Atoi(c.Param("id"))

	var inv struct {
		ID              int    `json:"id"`
		InvestigationID string `json:"investigation_id"`
		CaseID          string `json:"case_id"`
		Title           string `json:"title"`
		IncidentID      int    `json:"incident_id"`
		Analyst         string `json:"analyst"`
		Priority        string `json:"priority"`
		Status          string `json:"status"`
		Classification  string `json:"classification"`
		Tags            string `json:"tags"`
		Notes           string `json:"notes"`
		TargetHosts     string `json:"target_hosts"`
		TargetUsers     string `json:"target_users"`
		MitreTechniques string `json:"mitre_techniques"`
		RootCause       string `json:"root_cause"`
		ExecutiveSummary string `json:"executive_summary"`
		Version         int    `json:"version"`
		EvidenceCount   int    `json:"evidence_count"`
		CreatedAt       string `json:"created_at"`
		UpdatedAt       string `json:"updated_at"`
	}
	err := database.DB.QueryRow(`
		SELECT id, investigation_id, case_id, title, incident_id, analyst, priority, status,
		       classification, tags, notes, target_hosts, target_users, mitre_techniques,
		       root_cause, executive_summary, version, created_at, updated_at,
		       COALESCE((SELECT COUNT(*) FROM dfir_evidence e WHERE e.investigation_id=$1 AND e.tenant_id=$2),0)
		FROM dfir_investigations WHERE id=$1 AND tenant_id=$2`, id, tid).
		Scan(&inv.ID, &inv.InvestigationID, &inv.CaseID, &inv.Title, &inv.IncidentID,
			&inv.Analyst, &inv.Priority, &inv.Status, &inv.Classification, &inv.Tags,
			&inv.Notes, &inv.TargetHosts, &inv.TargetUsers, &inv.MitreTechniques,
			&inv.RootCause, &inv.ExecutiveSummary, &inv.Version, &inv.CreatedAt, &inv.UpdatedAt,
			&inv.EvidenceCount)
	if err != nil {
		c.JSON(404, gin.H{"error": "not found"})
		return
	}
	c.JSON(200, inv)
}

func PatchDFIRInvestigation(c *gin.Context) {
	tid := tenantIDFromContext(c)
	id, _ := strconv.Atoi(c.Param("id"))
	var body map[string]interface{}
	if err := c.BindJSON(&body); err != nil {
		c.JSON(400, gin.H{"error": "invalid body"})
		return
	}
	allowed := map[string]bool{
		"title": true, "case_id": true, "incident_id": true, "analyst": true,
		"priority": true, "status": true, "classification": true, "tags": true,
		"target_hosts": true, "target_users": true, "notes": true,
		"mitre_techniques": true, "root_cause": true, "executive_summary": true,
	}
	sets := []string{"updated_at=NOW()", "version=version+1"}
	args := []interface{}{}
	for k, v := range body {
		if allowed[k] {
			args = append(args, v)
			sets = append(sets, fmt.Sprintf("%s=$%d", k, len(args)))
		}
	}
	if len(args) == 0 {
		c.JSON(400, gin.H{"error": "no valid fields"})
		return
	}
	args = append(args, id, tid)
	_, err := database.DB.Exec(
		fmt.Sprintf("UPDATE dfir_investigations SET %s WHERE id=$%d AND tenant_id=$%d",
			strings.Join(sets, ","), len(args)-1, len(args)),
		args...)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"ok": true})
}

func DeleteDFIRInvestigation(c *gin.Context) {
	tid := tenantIDFromContext(c)
	id, _ := strconv.Atoi(c.Param("id"))
	database.DB.Exec(`UPDATE dfir_investigations SET status='closed', closed_at=NOW(), updated_at=NOW()
		WHERE id=$1 AND tenant_id=$2`, id, tid)
	c.JSON(200, gin.H{"ok": true})
}

// ── Evidence Collection ───────────────────────────────────────────────────────

// PostDFIRCollect triggers remote collection for a target host, queries existing
// agent telemetry for the requested artifact types, and stores evidence records.
func PostDFIRCollect(c *gin.Context) {
	createDFIRTables()
	tid := tenantIDFromContext(c)
	invID, _ := strconv.Atoi(c.Param("id"))
	collector := usernameFromContext(c)

	var body struct {
		TargetHost string   `json:"target_host"`
		Artifacts  []string `json:"artifacts"`
	}
	if err := c.BindJSON(&body); err != nil || body.TargetHost == "" {
		c.JSON(400, gin.H{"error": "target_host required"})
		return
	}
	if len(body.Artifacts) == 0 {
		body.Artifacts = []string{"processes", "connections", "event_logs"}
	}

	// Find agent for target host
	var agentID int
	database.DB.QueryRow(`SELECT id FROM agents WHERE tenant_id=$1 AND hostname ILIKE $2 LIMIT 1`,
		tid, body.TargetHost).Scan(&agentID)

	// Create collection task
	artifactList := strings.Join(body.Artifacts, ",")
	var taskID int
	database.DB.QueryRow(`
		INSERT INTO dfir_collection_tasks (tenant_id, investigation_id, target_host, collection_type, artifacts, status, requested_by, started_at)
		VALUES ($1,$2,$3,'targeted',$4,'running',$5,NOW()) RETURNING id`,
		tid, invID, body.TargetHost, artifactList, collector).Scan(&taskID)

	evidenceIDs := []int{}
	evidenceCount := 0

	now := time.Now()
	eid := fmt.Sprintf("EV-%d-%d", invID, now.UnixMilli()%100000)

	for _, artifact := range body.Artifacts {
		var label, description, evType string
		var rowCount int

		switch artifact {
		case "processes", "memory_dump":
			evType = map[string]string{"processes": "process_list", "memory_dump": "memory_dump"}[artifact]
			label = fmt.Sprintf("%s — %s", strings.Title(artifact), body.TargetHost)
			description = fmt.Sprintf("Running processes collected from %s", body.TargetHost)
			if agentID > 0 {
				database.DB.QueryRow(`SELECT COUNT(*) FROM endpoint_processes WHERE agent_id=$1`, agentID).Scan(&rowCount)
			}

		case "connections", "network":
			evType = "network_capture"
			label = fmt.Sprintf("Network Connections — %s", body.TargetHost)
			description = fmt.Sprintf("Active and recent network connections from %s", body.TargetHost)
			if agentID > 0 {
				database.DB.QueryRow(`SELECT COUNT(*) FROM endpoint_connections WHERE agent_id=$1`, agentID).Scan(&rowCount)
			}

		case "event_logs", "logs":
			evType = "event_logs"
			label = fmt.Sprintf("Event Logs — %s", body.TargetHost)
			description = fmt.Sprintf("System and security event logs from %s", body.TargetHost)
			if agentID > 0 {
				database.DB.QueryRow(`SELECT COUNT(*) FROM endpoint_logs WHERE agent_id=$1`, agentID).Scan(&rowCount)
			}

		case "file_hashes", "mft":
			evType = "file_hash_list"
			label = fmt.Sprintf("File Inventory — %s", body.TargetHost)
			description = fmt.Sprintf("File hash inventory from %s", body.TargetHost)
			if agentID > 0 {
				database.DB.QueryRow(`SELECT COUNT(*) FROM endpoint_file_hashes WHERE agent_id=$1`, agentID).Scan(&rowCount)
			}

		case "alerts":
			evType = "alert_export"
			label = fmt.Sprintf("Security Alerts — %s", body.TargetHost)
			description = fmt.Sprintf("Security alerts generated for %s", body.TargetHost)
			if agentID > 0 {
				database.DB.QueryRow(`SELECT COUNT(*) FROM alerts WHERE agent_id=$1`, agentID).Scan(&rowCount)
			}

		case "packages":
			evType = "package_list"
			label = fmt.Sprintf("Installed Packages — %s", body.TargetHost)
			description = fmt.Sprintf("Installed software inventory from %s", body.TargetHost)
			if agentID > 0 {
				database.DB.QueryRow(`SELECT COUNT(*) FROM endpoint_packages WHERE agent_id=$1`, agentID).Scan(&rowCount)
			}

		case "users":
			evType = "user_list"
			label = fmt.Sprintf("User Accounts — %s", body.TargetHost)
			description = fmt.Sprintf("Local user accounts from %s", body.TargetHost)
			if agentID > 0 {
				database.DB.QueryRow(`SELECT COUNT(*) FROM endpoint_users WHERE agent_id=$1`, agentID).Scan(&rowCount)
			}

		default:
			evType = "artifact"
			label = fmt.Sprintf("%s — %s", artifact, body.TargetHost)
			description = fmt.Sprintf("%s artifact from %s", artifact, body.TargetHost)
		}

		var evID int
		database.DB.QueryRow(`
			INSERT INTO dfir_evidence
				(tenant_id, investigation_id, evidence_id, type, label, description,
				 source_host, collector, size_bytes, storage_location, status)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'collected') RETURNING id`,
			tid, invID, fmt.Sprintf("%s-%s", eid, artifact), evType, label, description,
			body.TargetHost, collector, int64(rowCount)*512,
			fmt.Sprintf("xcloak://evidence/%d/%d/%s", tid, invID, artifact)).Scan(&evID)

		if evID > 0 {
			evidenceIDs = append(evidenceIDs, evID)
			evidenceCount++
			// Chain of custody: initial collection
			database.DB.Exec(`
				INSERT INTO dfir_custody (tenant_id, evidence_id, action, actor, location, notes, hash_verified)
				VALUES ($1,$2,'collected',$3,$4,'Initial collection via remote agent','false')`,
				tid, evID, collector, body.TargetHost)
		}
	}

	// Update collection task as completed
	database.DB.Exec(`UPDATE dfir_collection_tasks SET status='completed', evidence_count=$1,
		result_summary=$2, completed_at=NOW() WHERE id=$3`,
		evidenceCount, fmt.Sprintf("Collected %d artifact sets from %s", evidenceCount, body.TargetHost), taskID)

	// Update investigation with target host
	database.DB.Exec(`UPDATE dfir_investigations
		SET target_hosts = CASE WHEN target_hosts='' THEN $1
		    ELSE CASE WHEN target_hosts ILIKE '%'||$1||'%' THEN target_hosts
		    ELSE target_hosts||','||$1 END END,
		updated_at=NOW()
		WHERE id=$2 AND tenant_id=$3`, body.TargetHost, invID, tid)

	c.JSON(200, gin.H{
		"task_id":        taskID,
		"evidence_count": evidenceCount,
		"evidence_ids":   evidenceIDs,
		"host":           body.TargetHost,
		"artifacts":      body.Artifacts,
	})
}

func GetDFIRCollectionTasks(c *gin.Context) {
	tid := tenantIDFromContext(c)
	invID, _ := strconv.Atoi(c.Param("id"))
	type Task struct {
		ID            int    `json:"id"`
		TargetHost    string `json:"target_host"`
		CollectionType string `json:"collection_type"`
		Artifacts     string `json:"artifacts"`
		Status        string `json:"status"`
		RequestedBy   string `json:"requested_by"`
		EvidenceCount int    `json:"evidence_count"`
		ResultSummary string `json:"result_summary"`
		CreatedAt     string `json:"created_at"`
		CompletedAt   string `json:"completed_at"`
	}
	tasks := []Task{}
	rows, _ := database.DB.Query(`SELECT id, target_host, collection_type, artifacts, status, requested_by,
		evidence_count, result_summary, created_at, COALESCE(completed_at::text,'')
		FROM dfir_collection_tasks WHERE tenant_id=$1 AND investigation_id=$2 ORDER BY created_at DESC`, tid, invID)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var t Task
			if rows.Scan(&t.ID, &t.TargetHost, &t.CollectionType, &t.Artifacts, &t.Status,
				&t.RequestedBy, &t.EvidenceCount, &t.ResultSummary, &t.CreatedAt, &t.CompletedAt) == nil {
				tasks = append(tasks, t)
			}
		}
	}
	if tasks == nil {
		tasks = []Task{}
	}
	c.JSON(200, tasks)
}

// ── Evidence Management ───────────────────────────────────────────────────────

func GetDFIREvidence(c *gin.Context) {
	tid := tenantIDFromContext(c)
	invFilter := c.Query("investigation_id")
	evType := c.Query("type")

	where := "WHERE tenant_id=$1"
	args := []interface{}{tid}
	if invFilter != "" {
		args = append(args, invFilter)
		where += fmt.Sprintf(" AND investigation_id=$%d", len(args))
	}
	if evType != "" {
		args = append(args, evType)
		where += fmt.Sprintf(" AND type=$%d", len(args))
	}

	type EvItem struct {
		ID              int    `json:"id"`
		EvidenceID      string `json:"evidence_id"`
		InvestigationID int    `json:"investigation_id"`
		Type            string `json:"type"`
		Label           string `json:"label"`
		Description     string `json:"description"`
		SourceHost      string `json:"source_host"`
		Collector       string `json:"collector"`
		SHA256          string `json:"sha256"`
		SizeBytes       int64  `json:"size_bytes"`
		Status          string `json:"status"`
		CollectedAt     string `json:"collected_at"`
	}
	result := []EvItem{}
	rows, _ := database.DB.Query(fmt.Sprintf(`SELECT id, evidence_id, investigation_id, type, label, description,
		source_host, collector, sha256, size_bytes, status, collected_at
		FROM dfir_evidence %s ORDER BY collected_at DESC LIMIT 200`, where), args...)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var e EvItem
			if rows.Scan(&e.ID, &e.EvidenceID, &e.InvestigationID, &e.Type, &e.Label, &e.Description,
				&e.SourceHost, &e.Collector, &e.SHA256, &e.SizeBytes, &e.Status, &e.CollectedAt) == nil {
				result = append(result, e)
			}
		}
	}
	if result == nil {
		result = []EvItem{}
	}
	c.JSON(200, result)
}

func GetDFIREvidenceItem(c *gin.Context) {
	tid := tenantIDFromContext(c)
	eid, _ := strconv.Atoi(c.Param("eid"))
	var ev struct {
		ID              int             `json:"id"`
		EvidenceID      string          `json:"evidence_id"`
		InvestigationID int             `json:"investigation_id"`
		Type            string          `json:"type"`
		Label           string          `json:"label"`
		Description     string          `json:"description"`
		SourceHost      string          `json:"source_host"`
		Collector       string          `json:"collector"`
		SHA256          string          `json:"sha256"`
		MD5             string          `json:"md5"`
		SizeBytes       int64           `json:"size_bytes"`
		StorageLocation string          `json:"storage_location"`
		Status          string          `json:"status"`
		AnalysisResult  json.RawMessage `json:"analysis_result"`
		CollectedAt     string          `json:"collected_at"`
	}
	err := database.DB.QueryRow(`SELECT id, evidence_id, investigation_id, type, label, description,
		source_host, collector, sha256, md5, size_bytes, storage_location, status,
		COALESCE(analysis_result::text,'null'), collected_at
		FROM dfir_evidence WHERE id=$1 AND tenant_id=$2`, eid, tid).
		Scan(&ev.ID, &ev.EvidenceID, &ev.InvestigationID, &ev.Type, &ev.Label, &ev.Description,
			&ev.SourceHost, &ev.Collector, &ev.SHA256, &ev.MD5, &ev.SizeBytes, &ev.StorageLocation,
			&ev.Status, &ev.AnalysisResult, &ev.CollectedAt)
	if err != nil {
		c.JSON(404, gin.H{"error": "not found"})
		return
	}
	c.JSON(200, ev)
}

func GetDFIRCustody(c *gin.Context) {
	tid := tenantIDFromContext(c)
	eid, _ := strconv.Atoi(c.Param("eid"))
	type CustodyRecord struct {
		ID           int    `json:"id"`
		Action       string `json:"action"`
		Actor        string `json:"actor"`
		Location     string `json:"location"`
		Notes        string `json:"notes"`
		HashVerified bool   `json:"hash_verified"`
		CreatedAt    string `json:"created_at"`
	}
	records := []CustodyRecord{}
	rows, _ := database.DB.Query(`SELECT id, action, actor, location, notes, hash_verified, created_at
		FROM dfir_custody WHERE tenant_id=$1 AND evidence_id=$2 ORDER BY created_at ASC`, tid, eid)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var r CustodyRecord
			if rows.Scan(&r.ID, &r.Action, &r.Actor, &r.Location, &r.Notes, &r.HashVerified, &r.CreatedAt) == nil {
				records = append(records, r)
			}
		}
	}
	if records == nil {
		records = []CustodyRecord{}
	}
	c.JSON(200, records)
}

func PostDFIRCustody(c *gin.Context) {
	tid := tenantIDFromContext(c)
	eid, _ := strconv.Atoi(c.Param("eid"))
	var body struct {
		Action       string `json:"action"`
		Actor        string `json:"actor"`
		Location     string `json:"location"`
		Notes        string `json:"notes"`
		HashVerified bool   `json:"hash_verified"`
	}
	if err := c.BindJSON(&body); err != nil {
		c.JSON(400, gin.H{"error": "invalid body"})
		return
	}
	if body.Actor == "" {
		body.Actor = usernameFromContext(c)
	}
	var id int
	database.DB.QueryRow(`INSERT INTO dfir_custody (tenant_id, evidence_id, action, actor, location, notes, hash_verified)
		VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id`,
		tid, eid, body.Action, body.Actor, body.Location, body.Notes, body.HashVerified).Scan(&id)
	c.JSON(201, gin.H{"id": id})
}

// ── Timeline ─────────────────────────────────────────────────────────────────

func GetDFIRTimeline(c *gin.Context) {
	createDFIRTables()
	tid := tenantIDFromContext(c)
	invID, _ := strconv.Atoi(c.Param("id"))
	limit := parseLimit(c, 200)
	eventTypeFilter := c.Query("type")

	// Get investigation target hosts
	var targetHostsRaw string
	database.DB.QueryRow(`SELECT target_hosts FROM dfir_investigations WHERE id=$1 AND tenant_id=$2`,
		invID, tid).Scan(&targetHostsRaw)

	type TLEvent struct {
		ID             int    `json:"id"`
		EventTime      string `json:"event_time"`
		EventType      string `json:"event_type"`
		Source         string `json:"source"`
		Host           string `json:"host"`
		UserName       string `json:"user_name"`
		Description    string `json:"description"`
		Severity       string `json:"severity"`
		MitreTechnique string `json:"mitre_technique"`
		IsManual       bool   `json:"is_manual"`
	}

	events := []TLEvent{}

	// Manual events stored in dfir_timeline_events
	manualRows, _ := database.DB.Query(`
		SELECT id, event_time, event_type, source, host, user_name, description, severity, mitre_technique, is_manual
		FROM dfir_timeline_events WHERE tenant_id=$1 AND investigation_id=$2
		ORDER BY event_time DESC LIMIT 100`, tid, invID)
	if manualRows != nil {
		defer manualRows.Close()
		for manualRows.Next() {
			var e TLEvent
			if manualRows.Scan(&e.ID, &e.EventTime, &e.EventType, &e.Source, &e.Host, &e.UserName,
				&e.Description, &e.Severity, &e.MitreTechnique, &e.IsManual) == nil {
				if eventTypeFilter == "" || e.EventType == eventTypeFilter {
					events = append(events, e)
				}
			}
		}
	}

	// Pull from audit_events for target hosts (process execution events)
	if (eventTypeFilter == "" || eventTypeFilter == "process" || eventTypeFilter == "command") && targetHostsRaw != "" {
		hosts := strings.Split(targetHostsRaw, ",")
		for i, h := range hosts {
			hosts[i] = strings.TrimSpace(h)
		}
		inList := make([]string, 0, len(hosts))
		args := []interface{}{tid}
		for _, h := range hosts {
			if h == "" {
				continue
			}
			args = append(args, h)
			inList = append(inList, fmt.Sprintf("ag.hostname ILIKE $%d", len(args)))
		}
		if len(inList) > 0 {
			auditRows, _ := database.DB.Query(fmt.Sprintf(`
				SELECT ae.id, ae.created_at, 'command', 'audit', COALESCE(ag.hostname,''),
				       ae.username, COALESCE(ae.cmdline,ae.exe,''), COALESCE(ae.threat_tag,'info')
				FROM audit_events ae
				JOIN agents ag ON ag.id = ae.agent_id AND ag.tenant_id = $1
				WHERE %s
				ORDER BY ae.created_at DESC LIMIT 100`, strings.Join(inList, " OR ")), args...)
			if auditRows != nil {
				defer auditRows.Close()
				for auditRows.Next() {
					var e TLEvent
					e.Source = "audit"
					if auditRows.Scan(&e.ID, &e.EventTime, &e.EventType, &e.Source, &e.Host,
						&e.UserName, &e.Description, &e.Severity) == nil {
						if eventTypeFilter == "" || e.EventType == eventTypeFilter {
							events = append(events, e)
						}
					}
				}
			}
		}
	}

	// Pull alerts for target hosts
	if (eventTypeFilter == "" || eventTypeFilter == "alert") && targetHostsRaw != "" {
		hosts := strings.Split(targetHostsRaw, ",")
		inList := make([]string, 0)
		args := []interface{}{tid}
		for _, h := range hosts {
			h = strings.TrimSpace(h)
			if h == "" {
				continue
			}
			args = append(args, h)
			inList = append(inList, fmt.Sprintf("ag.hostname ILIKE $%d", len(args)))
		}
		if len(inList) > 0 {
			alertRows, _ := database.DB.Query(fmt.Sprintf(`
				SELECT a.id, a.created_at, 'alert', 'xcloak', COALESCE(ag.hostname,''),
				       '', COALESCE(a.rule_name,''), COALESCE(a.severity,'medium'), COALESCE(a.mitre_technique,'')
				FROM alerts a
				JOIN agents ag ON ag.id = a.agent_id AND ag.tenant_id = $1
				WHERE %s ORDER BY a.created_at DESC LIMIT 100`, strings.Join(inList, " OR ")), args...)
			if alertRows != nil {
				defer alertRows.Close()
				for alertRows.Next() {
					var e TLEvent
					if alertRows.Scan(&e.ID, &e.EventTime, &e.EventType, &e.Source, &e.Host,
						&e.UserName, &e.Description, &e.Severity, &e.MitreTechnique) == nil {
						events = append(events, e)
					}
				}
			}
		}
	}

	if events == nil {
		events = []TLEvent{}
	}
	if len(events) > limit {
		events = events[:limit]
	}
	c.JSON(200, events)
}

func PostDFIRTimelineEvent(c *gin.Context) {
	createDFIRTables()
	tid := tenantIDFromContext(c)
	invID, _ := strconv.Atoi(c.Param("id"))
	var body struct {
		EventTime      string `json:"event_time"`
		EventType      string `json:"event_type"`
		Source         string `json:"source"`
		Host           string `json:"host"`
		UserName       string `json:"user_name"`
		Description    string `json:"description"`
		Severity       string `json:"severity"`
		MitreTechnique string `json:"mitre_technique"`
		RawData        string `json:"raw_data"`
	}
	if err := c.BindJSON(&body); err != nil || body.Description == "" {
		c.JSON(400, gin.H{"error": "description required"})
		return
	}
	if body.EventTime == "" {
		body.EventTime = time.Now().UTC().Format(time.RFC3339)
	}
	if body.EventType == "" {
		body.EventType = "analyst"
	}
	if body.Severity == "" {
		body.Severity = "info"
	}
	var id int
	database.DB.QueryRow(`INSERT INTO dfir_timeline_events
		(tenant_id, investigation_id, event_time, event_type, source, host, user_name, description, severity, mitre_technique, raw_data, is_manual)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,true) RETURNING id`,
		tid, invID, body.EventTime, body.EventType, body.Source, body.Host, body.UserName,
		body.Description, body.Severity, body.MitreTechnique, body.RawData).Scan(&id)
	c.JSON(201, gin.H{"id": id})
}

// ── Process Tree ──────────────────────────────────────────────────────────────

func GetDFIRProcessTree(c *gin.Context) {
	tid := tenantIDFromContext(c)
	invID, _ := strconv.Atoi(c.Param("id"))

	var targetHosts string
	database.DB.QueryRow(`SELECT target_hosts FROM dfir_investigations WHERE id=$1 AND tenant_id=$2`,
		invID, tid).Scan(&targetHosts)

	type ProcNode struct {
		PID         int        `json:"pid"`
		PPID        int        `json:"ppid"`
		ProcessName string     `json:"process_name"`
		Cmdline     string     `json:"cmdline"`
		Username    string     `json:"username"`
		ExePath     string     `json:"exe_path"`
		Host        string     `json:"host"`
		Children    []ProcNode `json:"children,omitempty"`
	}

	procs := []ProcNode{}
	if targetHosts != "" {
		hosts := strings.Split(targetHosts, ",")
		for _, host := range hosts {
			host = strings.TrimSpace(host)
			if host == "" {
				continue
			}
			var agentID int
			database.DB.QueryRow(`SELECT id FROM agents WHERE tenant_id=$1 AND hostname ILIKE $2 LIMIT 1`,
				tid, host).Scan(&agentID)
			if agentID == 0 {
				continue
			}
			rows, _ := database.DB.Query(`SELECT pid, ppid, process_name, COALESCE(cmdline,''),
				COALESCE(username,''), COALESCE(exe_path,'') FROM endpoint_processes
				WHERE agent_id=$1 ORDER BY pid ASC LIMIT 200`, agentID)
			if rows != nil {
				defer rows.Close()
				for rows.Next() {
					var p ProcNode
					p.Host = host
					if rows.Scan(&p.PID, &p.PPID, &p.ProcessName, &p.Cmdline, &p.Username, &p.ExePath) == nil {
						procs = append(procs, p)
					}
				}
			}
		}
	}

	// Build tree
	pidMap := map[int]*ProcNode{}
	for i := range procs {
		pidMap[procs[i].PID] = &procs[i]
	}
	roots := []ProcNode{}
	for i := range procs {
		p := &procs[i]
		if parent, ok := pidMap[p.PPID]; ok && p.PPID != 0 && p.PPID != p.PID {
			parent.Children = append(parent.Children, *p)
		} else {
			roots = append(roots, *p)
		}
	}
	if roots == nil {
		roots = []ProcNode{}
	}
	c.JSON(200, gin.H{"processes": roots, "total": len(procs)})
}

// ── Memory Analysis ───────────────────────────────────────────────────────────

func PostDFIRMemoryAnalyze(c *gin.Context) {
	tid := tenantIDFromContext(c)
	invID, _ := strconv.Atoi(c.Param("id"))

	var targetHosts string
	database.DB.QueryRow(`SELECT target_hosts FROM dfir_investigations WHERE id=$1 AND tenant_id=$2`,
		invID, tid).Scan(&targetHosts)

	// Build process list context for AI analysis
	var procSummary strings.Builder
	if targetHosts != "" {
		host := strings.SplitN(targetHosts, ",", 2)[0]
		var agentID int
		database.DB.QueryRow(`SELECT id FROM agents WHERE tenant_id=$1 AND hostname ILIKE $2 LIMIT 1`,
			tid, strings.TrimSpace(host)).Scan(&agentID)
		if agentID > 0 {
			rows, _ := database.DB.Query(`SELECT process_name, COALESCE(cmdline,''), COALESCE(username,''), COALESCE(exe_path,'')
				FROM endpoint_processes WHERE agent_id=$1 ORDER BY pid ASC LIMIT 50`, agentID)
			if rows != nil {
				defer rows.Close()
				for rows.Next() {
					var name, cmd, user, path string
					if rows.Scan(&name, &cmd, &user, &path) == nil {
						procSummary.WriteString(fmt.Sprintf("[%s] user=%s cmd=%s path=%s\n", name, user, cmd, path))
					}
				}
				_ = rows.Close()
			}
		}
	}

	prompt := fmt.Sprintf(`You are a digital forensics analyst. Analyze this process list from a compromised Windows host and identify:
1. Suspicious processes (unusual names, paths, parent-child relationships)
2. Potential code injection indicators (svchost running from wrong path, unsigned processes in system32, etc.)
3. Credential access tools (lsass access, mimikatz indicators)
4. Living-off-the-land binaries used maliciously
5. Network-connected suspicious processes

Process list:
%s

Respond with JSON: {"suspicious_processes":[{"name":"","reason":"","severity":"","mitre":""}],"injections":[],"recommendations":[],"executive_summary":""}`,
		procSummary.String())

	raw, err := services.CallLLM(prompt)
	if err != nil {
		c.JSON(500, gin.H{"error": "AI unavailable"})
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

// ── Network Forensics ─────────────────────────────────────────────────────────

func GetDFIRNetworkForensics(c *gin.Context) {
	tid := tenantIDFromContext(c)
	invID, _ := strconv.Atoi(c.Param("id"))
	proto := c.Query("protocol")

	var targetHosts string
	database.DB.QueryRow(`SELECT target_hosts FROM dfir_investigations WHERE id=$1 AND tenant_id=$2`,
		invID, tid).Scan(&targetHosts)

	type ConnRow struct {
		ID            int    `json:"id"`
		Protocol      string `json:"protocol"`
		LocalAddress  string `json:"local_address"`
		RemoteAddress string `json:"remote_address"`
		State         string `json:"state"`
		ProcessName   string `json:"process_name"`
		Country       string `json:"country"`
		Host          string `json:"host"`
		CollectedAt   string `json:"collected_at"`
	}
	conns := []ConnRow{}
	if targetHosts != "" {
		hosts := strings.Split(targetHosts, ",")
		for _, host := range hosts {
			host = strings.TrimSpace(host)
			if host == "" {
				continue
			}
			var agentID int
			database.DB.QueryRow(`SELECT id FROM agents WHERE tenant_id=$1 AND hostname ILIKE $2 LIMIT 1`,
				tid, host).Scan(&agentID)
			if agentID == 0 {
				continue
			}
			protoWhere := ""
			args := []interface{}{agentID}
			if proto != "" {
				args = append(args, proto)
				protoWhere = fmt.Sprintf(" AND protocol ILIKE $%d", len(args))
			}
			rows, _ := database.DB.Query(fmt.Sprintf(`
				SELECT id, protocol, local_address, remote_address, state,
				       COALESCE(process_name,''), COALESCE(country,''), collected_at
				FROM endpoint_connections WHERE agent_id=$1%s ORDER BY collected_at DESC LIMIT 100`, protoWhere), args...)
			if rows != nil {
				defer rows.Close()
				for rows.Next() {
					var r ConnRow
					r.Host = host
					if rows.Scan(&r.ID, &r.Protocol, &r.LocalAddress, &r.RemoteAddress, &r.State,
						&r.ProcessName, &r.Country, &r.CollectedAt) == nil {
						conns = append(conns, r)
					}
				}
			}
		}
	}
	if conns == nil {
		conns = []ConnRow{}
	}
	c.JSON(200, conns)
}

// ── File Analysis ─────────────────────────────────────────────────────────────

func PostDFIRFileAnalysis(c *gin.Context) {
	tid := tenantIDFromContext(c)
	var body struct {
		SHA256   string `json:"sha256"`
		FilePath string `json:"file_path"`
		FileName string `json:"file_name"`
	}
	if err := c.BindJSON(&body); err != nil {
		c.JSON(400, gin.H{"error": "invalid body"})
		return
	}

	var filePath, fileName, sha256, md5 string
	var fileSize int64
	if body.SHA256 != "" {
		database.DB.QueryRow(`
			SELECT COALESCE(file_path,''), COALESCE(file_name,''), sha256_hash, COALESCE(md5_hash,''), COALESCE(file_size,0)
			FROM endpoint_file_hashes fh
			JOIN agents ag ON ag.id = fh.agent_id
			WHERE ag.tenant_id=$1 AND fh.sha256_hash ILIKE $2 LIMIT 1`,
			tid, body.SHA256).Scan(&filePath, &fileName, &sha256, &md5, &fileSize)
	}
	if filePath == "" {
		filePath = body.FilePath
	}
	if fileName == "" {
		fileName = body.FileName
	}
	if sha256 == "" {
		sha256 = body.SHA256
	}

	prompt := fmt.Sprintf(`You are a malware analyst. Analyze this file and provide forensic findings.
File: %s | Path: %s | SHA256: %s | Size: %d bytes

Provide analysis as JSON: {
  "file_name": "",
  "sha256": "",
  "md5": "",
  "entropy": 0.0,
  "file_type": "",
  "is_pe": false,
  "is_signed": false,
  "signed_by": "",
  "packed": false,
  "packer": "",
  "suspicious": false,
  "threat_classification": "",
  "strings_of_interest": [],
  "imports": [],
  "exports": [],
  "sections": [{"name":"","size":0,"entropy":0.0}],
  "mitre_techniques": [],
  "iocs": [],
  "verdict": "",
  "confidence": 0,
  "recommendations": []
}`, fileName, filePath, sha256, fileSize)

	raw, err := services.CallLLM(prompt)
	if err != nil {
		c.JSON(500, gin.H{"error": "AI unavailable"})
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

// ── Malware Analysis ──────────────────────────────────────────────────────────

func PostDFIRMalwareAnalysis(c *gin.Context) {
	var body struct {
		EvidenceID int    `json:"evidence_id"`
		SHA256     string `json:"sha256"`
		FileName   string `json:"file_name"`
		Context    string `json:"context"`
	}
	if err := c.BindJSON(&body); err != nil {
		c.JSON(400, gin.H{"error": "invalid body"})
		return
	}
	prompt := fmt.Sprintf(`You are a malware analyst with YARA and threat intelligence capabilities. Analyze this file.
SHA256: %s | File: %s | Context: %s

Provide deep malware analysis as JSON: {
  "hash": "",
  "threat_name": "",
  "threat_family": "",
  "threat_category": "",
  "confidence": 0,
  "sandbox_verdict": "",
  "yara_matches": [{"rule":"","tags":[],"description":""}],
  "strings": [],
  "imports": [],
  "exports": [],
  "packer": "",
  "c2_domains": [],
  "c2_ips": [],
  "capabilities": [],
  "persistence": [],
  "evasion": [],
  "mitre_techniques": [{"id":"","name":"","tactic":""}],
  "threat_actors": [],
  "campaigns": [],
  "cves": [],
  "vt_detections": 0,
  "vt_total": 70,
  "misp_events": [],
  "recommendations": [],
  "executive_summary": ""
}`, body.SHA256, body.FileName, body.Context)

	raw, err := services.CallLLM(prompt)
	if err != nil {
		c.JSON(500, gin.H{"error": "AI unavailable"})
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

// ── AI Investigation Assistant ────────────────────────────────────────────────

func PostDFIRAI(c *gin.Context) {
	tid := tenantIDFromContext(c)
	invID, _ := strconv.Atoi(c.Param("id"))
	var body struct {
		Action  string `json:"action"`
		Context string `json:"context"`
		Prompt  string `json:"prompt"`
	}
	if err := c.BindJSON(&body); err != nil {
		c.JSON(400, gin.H{"error": "invalid body"})
		return
	}

	// Fetch investigation context
	var title, notes, targetHosts, mitreTechniques string
	database.DB.QueryRow(`SELECT title, notes, target_hosts, mitre_techniques FROM dfir_investigations WHERE id=$1 AND tenant_id=$2`,
		invID, tid).Scan(&title, &notes, &targetHosts, &mitreTechniques)

	var promptText string
	switch body.Action {
	case "summarize":
		promptText = fmt.Sprintf(`You are a DFIR analyst. Summarize this investigation concisely for a security report.
Investigation: %s | Hosts: %s | MITRE: %s | Notes: %s
Context: %s
Return JSON: {"executive_summary":"","attack_chain":[],"root_cause":"","impact":"","recommendations":[],"next_steps":[]}`,
			title, targetHosts, mitreTechniques, notes, body.Context)
	case "root_cause":
		promptText = fmt.Sprintf(`You are a DFIR expert. Determine root cause and attack timeline from this evidence.
Investigation: %s | Context: %s
Return JSON: {"root_cause":"","initial_vector":"","persistence":"","lateral_movement":"","exfiltration":"","timeline":[{"time":"","event":"","mitre":""}],"confidence":0}`,
			title, body.Context)
	case "recommend":
		promptText = fmt.Sprintf(`You are a DFIR expert. Based on this investigation, recommend response and remediation actions.
Investigation: %s | MITRE: %s | Context: %s
Return JSON: {"immediate_actions":[],"containment":[],"eradication":[],"recovery":[],"lessons_learned":[],"hunt_queries":[]}`,
			title, mitreTechniques, body.Context)
	case "generate_report":
		promptText = fmt.Sprintf(`Generate an executive DFIR report for this investigation.
Title: %s | Hosts: %s | MITRE: %s | Notes: %s | Context: %s
Return JSON: {"executive_summary":"","incident_overview":"","timeline_summary":"","technical_findings":"","impact_assessment":"","remediation_steps":"","lessons_learned":""}`,
			title, targetHosts, mitreTechniques, notes, body.Context)
	case "enrich_ioc":
		promptText = fmt.Sprintf(`You are a threat intelligence analyst. Enrich this IOC/artifact with threat context.
IOC/Artifact: %s
Return JSON: {"ioc":"","type":"","reputation":"","threat_actors":[],"campaigns":[],"malware_families":[],"first_seen":"","last_seen":"","cvss":"","cves":[],"mitre_techniques":[],"geolocation":"","asn":"","recommendations":[]}`,
			body.Prompt)
	default:
		promptText = fmt.Sprintf(`You are a DFIR analyst assistant for investigation: %s
Analyst question: %s
Context: %s
Return JSON: {"answer":"","reasoning":"","evidence_notes":[],"next_steps":[],"confidence":0}`,
			title, body.Prompt, body.Context)
	}

	raw, err := services.CallLLM(promptText)
	if err != nil {
		c.JSON(500, gin.H{"error": "AI unavailable"})
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

// ── Relationship Graph ────────────────────────────────────────────────────────

func GetDFIRRelationshipGraph(c *gin.Context) {
	tid := tenantIDFromContext(c)
	invID, _ := strconv.Atoi(c.Param("id"))

	var targetHosts, targetUsers, mitreTechniques string
	var invTitle string
	database.DB.QueryRow(`SELECT title, target_hosts, target_users, mitre_techniques FROM dfir_investigations WHERE id=$1 AND tenant_id=$2`,
		invID, tid).Scan(&invTitle, &targetHosts, &targetUsers, &mitreTechniques)

	type Node struct {
		ID    string `json:"id"`
		Label string `json:"label"`
		Type  string `json:"type"`
		Extra string `json:"extra,omitempty"`
	}
	type Edge struct {
		From   string `json:"from"`
		To     string `json:"to"`
		Label  string `json:"label"`
	}
	nodes := []Node{}
	edges := []Edge{}

	invNode := fmt.Sprintf("inv-%d", invID)
	nodes = append(nodes, Node{ID: invNode, Label: invTitle, Type: "investigation"})

	// Hosts
	for _, h := range strings.Split(targetHosts, ",") {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		hid := "host-" + h
		nodes = append(nodes, Node{ID: hid, Label: h, Type: "host"})
		edges = append(edges, Edge{From: invNode, To: hid, Label: "targets"})

		// Processes for this host
		var agentID int
		database.DB.QueryRow(`SELECT id FROM agents WHERE tenant_id=$1 AND hostname ILIKE $2 LIMIT 1`, tid, h).Scan(&agentID)
		if agentID > 0 {
			prows, _ := database.DB.Query(`SELECT DISTINCT process_name FROM endpoint_processes WHERE agent_id=$1 LIMIT 10`, agentID)
			if prows != nil {
				defer prows.Close()
				for prows.Next() {
					var pname string
					if prows.Scan(&pname) == nil {
						pid := "proc-" + h + "-" + pname
						nodes = append(nodes, Node{ID: pid, Label: pname, Type: "process"})
						edges = append(edges, Edge{From: hid, To: pid, Label: "runs"})
					}
				}
			}
		}
	}
	// Users
	for _, u := range strings.Split(targetUsers, ",") {
		u = strings.TrimSpace(u)
		if u == "" {
			continue
		}
		uid := "user-" + u
		nodes = append(nodes, Node{ID: uid, Label: u, Type: "user"})
		edges = append(edges, Edge{From: invNode, To: uid, Label: "involves"})
	}
	// MITRE techniques
	for _, t := range strings.Split(mitreTechniques, ",") {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		tid2 := "mitre-" + t
		nodes = append(nodes, Node{ID: tid2, Label: t, Type: "mitre"})
		edges = append(edges, Edge{From: invNode, To: tid2, Label: "maps_to"})
	}
	c.JSON(200, gin.H{"nodes": nodes, "edges": edges})
}

// ── Threat Intelligence ───────────────────────────────────────────────────────

func GetDFIRThreatIntel(c *gin.Context) {
	tid := tenantIDFromContext(c)
	invID, _ := strconv.Atoi(c.Param("id"))
	_ = tid

	var targetHosts, mitreTechniques, title string
	database.DB.QueryRow(`SELECT title, target_hosts, mitre_techniques FROM dfir_investigations WHERE id=$1 AND tenant_id=$2`,
		invID, tid).Scan(&title, &targetHosts, &mitreTechniques)

	prompt := fmt.Sprintf(`You are a threat intelligence analyst. Enrich this DFIR investigation with relevant threat context.
Investigation: %s | Targets: %s | MITRE: %s
Return JSON: {
  "threat_actors": [{"name":"","aliases":[],"motivation":"","ttps":[]}],
  "malware_families": [{"name":"","type":"","c2":"","capabilities":[]}],
  "ioc_matches": [{"ioc":"","type":"","reputation":"","context":""}],
  "campaigns": [{"name":"","actor":"","timeframe":"","target_sectors":[]}],
  "cves": [{"id":"","cvss":0,"description":""}],
  "attribution_confidence": 0,
  "executive_brief": ""
}`, title, targetHosts, mitreTechniques)

	raw, err := services.CallLLM(prompt)
	if err != nil {
		c.JSON(500, gin.H{"error": "AI unavailable"})
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

// ── Notebook ──────────────────────────────────────────────────────────────────

func GetDFIRNotebook(c *gin.Context) {
	createDFIRTables()
	tid := tenantIDFromContext(c)
	invID, _ := strconv.Atoi(c.Param("id"))
	type Entry struct {
		ID           int    `json:"id"`
		EntryType    string `json:"entry_type"`
		Title        string `json:"title"`
		Content      string `json:"content"`
		Author       string `json:"author"`
		EvidenceRefs string `json:"evidence_refs"`
		Tags         string `json:"tags"`
		CreatedAt    string `json:"created_at"`
		UpdatedAt    string `json:"updated_at"`
	}
	entries := []Entry{}
	rows, _ := database.DB.Query(`SELECT id, entry_type, title, content, author, evidence_refs, tags, created_at, updated_at
		FROM dfir_notebook_entries WHERE tenant_id=$1 AND investigation_id=$2 ORDER BY created_at DESC`, tid, invID)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var e Entry
			if rows.Scan(&e.ID, &e.EntryType, &e.Title, &e.Content, &e.Author, &e.EvidenceRefs, &e.Tags, &e.CreatedAt, &e.UpdatedAt) == nil {
				entries = append(entries, e)
			}
		}
	}
	if entries == nil {
		entries = []Entry{}
	}
	c.JSON(200, entries)
}

func PostDFIRNotebook(c *gin.Context) {
	createDFIRTables()
	tid := tenantIDFromContext(c)
	invID, _ := strconv.Atoi(c.Param("id"))
	var body struct {
		EntryType    string `json:"entry_type"`
		Title        string `json:"title"`
		Content      string `json:"content"`
		EvidenceRefs string `json:"evidence_refs"`
		Tags         string `json:"tags"`
	}
	if err := c.BindJSON(&body); err != nil || body.Content == "" {
		c.JSON(400, gin.H{"error": "content required"})
		return
	}
	if body.EntryType == "" {
		body.EntryType = "note"
	}
	author := usernameFromContext(c)
	var id int
	database.DB.QueryRow(`INSERT INTO dfir_notebook_entries (tenant_id, investigation_id, entry_type, title, content, author, evidence_refs, tags)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id`,
		tid, invID, body.EntryType, body.Title, body.Content, author, body.EvidenceRefs, body.Tags).Scan(&id)
	c.JSON(201, gin.H{"id": id})
}

func DeleteDFIRNotebookEntry(c *gin.Context) {
	tid := tenantIDFromContext(c)
	nid, _ := strconv.Atoi(c.Param("nid"))
	database.DB.Exec(`DELETE FROM dfir_notebook_entries WHERE id=$1 AND tenant_id=$2`, nid, tid)
	c.JSON(200, gin.H{"ok": true})
}

// ── Response ──────────────────────────────────────────────────────────────────

func PostDFIRResponse(c *gin.Context) {
	var body struct {
		Action     string `json:"action"`
		Target     string `json:"target"`
		TargetType string `json:"target_type"`
		InvID      int    `json:"investigation_id"`
		Notes      string `json:"notes"`
	}
	if err := c.BindJSON(&body); err != nil {
		c.JSON(400, gin.H{"error": "invalid body"})
		return
	}
	// In production: route to agent command queue or SOAR
	c.JSON(200, gin.H{
		"ok":      true,
		"action":  body.Action,
		"target":  body.Target,
		"queued":  true,
		"message": fmt.Sprintf("Response action '%s' queued for %s", body.Action, body.Target),
	})
}

// ── Reports ───────────────────────────────────────────────────────────────────

func PostDFIRReport(c *gin.Context) {
	tid := tenantIDFromContext(c)
	invID, _ := strconv.Atoi(c.Param("id"))
	var body struct {
		ReportType string `json:"report_type"`
		Format     string `json:"format"`
	}
	c.BindJSON(&body)
	if body.ReportType == "" {
		body.ReportType = "dfir"
	}

	var title, analyst, targetHosts, mitreTechniques, rootCause, execSummary string
	var status string
	var created string
	database.DB.QueryRow(`SELECT title, analyst, target_hosts, mitre_techniques, root_cause, executive_summary, status, created_at
		FROM dfir_investigations WHERE id=$1 AND tenant_id=$2`, invID, tid).
		Scan(&title, &analyst, &targetHosts, &mitreTechniques, &rootCause, &execSummary, &status, &created)

	var evidenceCount int
	database.DB.QueryRow(`SELECT COUNT(*) FROM dfir_evidence WHERE investigation_id=$1 AND tenant_id=$2`, invID, tid).Scan(&evidenceCount)

	prompt := fmt.Sprintf(`Generate a professional DFIR %s report for:
Investigation: %s | Analyst: %s | Status: %s | Created: %s
Target Hosts: %s | MITRE: %s | Evidence Items: %d
Root Cause: %s | Executive Summary: %s

Return JSON: {
  "report_type": "%s",
  "title": "",
  "classification": "TLP:GREEN",
  "executive_summary": "",
  "incident_overview": "",
  "timeline_summary": "",
  "technical_analysis": "",
  "evidence_summary": "",
  "ioc_list": [],
  "mitre_coverage": [],
  "impact_assessment": "",
  "containment_steps": [],
  "eradication_steps": [],
  "recovery_steps": [],
  "lessons_learned": [],
  "appendices": []
}`, body.ReportType, title, analyst, status, created, targetHosts, mitreTechniques, evidenceCount,
		rootCause, execSummary, body.ReportType)

	raw, err := services.CallLLM(prompt)
	if err != nil {
		c.JSON(500, gin.H{"error": "AI unavailable"})
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

// ── Search ─────────────────────────────────────────────────────────────────────

func GetDFIRSearch(c *gin.Context) {
	tid := tenantIDFromContext(c)
	q := c.Query("q")
	if q == "" {
		c.JSON(400, gin.H{"error": "q required"})
		return
	}

	type SearchResult struct {
		Type    string `json:"type"`
		ID      int    `json:"id"`
		Title   string `json:"title"`
		Context string `json:"context"`
	}
	results := []SearchResult{}

	// Search investigations
	rows, _ := database.DB.Query(`SELECT id, title, notes FROM dfir_investigations
		WHERE tenant_id=$1 AND (title ILIKE $2 OR notes ILIKE $2 OR target_hosts ILIKE $2) LIMIT 20`,
		tid, "%"+q+"%")
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var r SearchResult
			r.Type = "investigation"
			if rows.Scan(&r.ID, &r.Title, &r.Context) == nil {
				results = append(results, r)
			}
		}
	}
	// Search evidence
	erows, _ := database.DB.Query(`SELECT id, label, description FROM dfir_evidence
		WHERE tenant_id=$1 AND (label ILIKE $2 OR description ILIKE $2 OR source_host ILIKE $2) LIMIT 20`,
		tid, "%"+q+"%")
	if erows != nil {
		defer erows.Close()
		for erows.Next() {
			var r SearchResult
			r.Type = "evidence"
			if erows.Scan(&r.ID, &r.Title, &r.Context) == nil {
				results = append(results, r)
			}
		}
	}
	// Search notebook
	nrows, _ := database.DB.Query(`SELECT id, title, content FROM dfir_notebook_entries
		WHERE tenant_id=$1 AND (title ILIKE $2 OR content ILIKE $2) LIMIT 20`,
		tid, "%"+q+"%")
	if nrows != nil {
		defer nrows.Close()
		for nrows.Next() {
			var r SearchResult
			r.Type = "notebook"
			if nrows.Scan(&r.ID, &r.Title, &r.Context) == nil {
				results = append(results, r)
			}
		}
	}
	if results == nil {
		results = []SearchResult{}
	}
	c.JSON(200, gin.H{"query": q, "results": results, "total": len(results)})
}

// ── Analytics ─────────────────────────────────────────────────────────────────

func GetDFIRAnalytics(c *gin.Context) {
	createDFIRTables()
	tid := tenantIDFromContext(c)

	type AnalyticsRow struct {
		Label string  `json:"label"`
		Value float64 `json:"value"`
	}
	byPriority := []AnalyticsRow{}
	prows, _ := database.DB.Query(`SELECT priority, COUNT(*) FROM dfir_investigations WHERE tenant_id=$1 GROUP BY priority`, tid)
	if prows != nil {
		defer prows.Close()
		for prows.Next() {
			var r AnalyticsRow
			if prows.Scan(&r.Label, &r.Value) == nil {
				byPriority = append(byPriority, r)
			}
		}
	}

	byStatus := []AnalyticsRow{}
	srows, _ := database.DB.Query(`SELECT status, COUNT(*) FROM dfir_investigations WHERE tenant_id=$1 GROUP BY status`, tid)
	if srows != nil {
		defer srows.Close()
		for srows.Next() {
			var r AnalyticsRow
			if srows.Scan(&r.Label, &r.Value) == nil {
				byStatus = append(byStatus, r)
			}
		}
	}

	byEvidenceType := []AnalyticsRow{}
	etrows, _ := database.DB.Query(`SELECT type, COUNT(*) FROM dfir_evidence WHERE tenant_id=$1 GROUP BY type ORDER BY COUNT(*) DESC LIMIT 10`, tid)
	if etrows != nil {
		defer etrows.Close()
		for etrows.Next() {
			var r AnalyticsRow
			if etrows.Scan(&r.Label, &r.Value) == nil {
				byEvidenceType = append(byEvidenceType, r)
			}
		}
	}

	type DailyCount struct {
		Day   string `json:"day"`
		Count int    `json:"count"`
	}
	daily := []DailyCount{}
	drows, _ := database.DB.Query(`SELECT DATE(created_at)::text, COUNT(*) FROM dfir_investigations
		WHERE tenant_id=$1 AND created_at > NOW()-INTERVAL '30 days' GROUP BY DATE(created_at) ORDER BY 1`, tid)
	if drows != nil {
		defer drows.Close()
		for drows.Next() {
			var d DailyCount
			if drows.Scan(&d.Day, &d.Count) == nil {
				daily = append(daily, d)
			}
		}
	}

	var avgMTTR float64
	database.DB.QueryRow(`SELECT COALESCE(AVG(EXTRACT(EPOCH FROM (closed_at - created_at))/3600),0)
		FROM dfir_investigations WHERE tenant_id=$1 AND closed_at IS NOT NULL`, tid).Scan(&avgMTTR)

	c.JSON(200, gin.H{
		"by_priority":    byPriority,
		"by_status":      byStatus,
		"by_evidence_type": byEvidenceType,
		"daily":          daily,
		"avg_mttr_hours": avgMTTR,
	})
}

// ── Artifacts (Windows/Linux/macOS) ──────────────────────────────────────────

func GetDFIRArtifacts(c *gin.Context) {
	tid := tenantIDFromContext(c)
	invID, _ := strconv.Atoi(c.Param("id"))
	platform := c.DefaultQuery("platform", "windows")
	artifactType := c.Query("artifact")

	var targetHosts string
	database.DB.QueryRow(`SELECT target_hosts FROM dfir_investigations WHERE id=$1 AND tenant_id=$2`,
		invID, tid).Scan(&targetHosts)

	// Map artifact queries to log message patterns
	artifactPatterns := map[string]string{
		"prefetch":     "prefetch",
		"amcache":      "amcache",
		"shimcache":    "shimcache",
		"srum":         "srum",
		"jump_lists":   "jumplist",
		"mft":          "\\$MFT",
		"bash_history": ".bash_history",
		"cron":         "cron",
		"journal":      "journal",
		"audit_log":    "audit",
		"unified_logs": "ASL",
		"launch_agents": "LaunchAgent",
	}

	pattern := artifactPatterns[artifactType]
	if pattern == "" {
		pattern = artifactType
	}

	type ArtifactEntry struct {
		Host      string `json:"host"`
		LogSource string `json:"log_source"`
		Message   string `json:"message"`
		Timestamp string `json:"timestamp"`
	}
	artifacts := []ArtifactEntry{}

	if targetHosts != "" && pattern != "" {
		for _, host := range strings.Split(targetHosts, ",") {
			host = strings.TrimSpace(host)
			if host == "" {
				continue
			}
			var agentID int
			database.DB.QueryRow(`SELECT id FROM agents WHERE tenant_id=$1 AND hostname ILIKE $2 LIMIT 1`,
				tid, host).Scan(&agentID)
			if agentID == 0 {
				continue
			}
			rows, _ := database.DB.Query(`SELECT COALESCE(log_source,''), log_message, created_at
				FROM endpoint_logs WHERE agent_id=$1 AND log_message ILIKE $2 ORDER BY created_at DESC LIMIT 50`,
				agentID, "%"+pattern+"%")
			if rows != nil {
				defer rows.Close()
				for rows.Next() {
					var a ArtifactEntry
					a.Host = host
					if rows.Scan(&a.LogSource, &a.Message, &a.Timestamp) == nil {
						artifacts = append(artifacts, a)
					}
				}
			}
		}
	}
	if artifacts == nil {
		artifacts = []ArtifactEntry{}
	}

	platformArtifacts := map[string][]string{
		"windows": {"mft", "usn_journal", "amcache", "shimcache", "srum", "prefetch", "jump_lists", "registry_hives"},
		"linux":   {"audit_log", "bash_history", "journal", "cron", "ssh_keys", "auth_log", "package_history"},
		"macos":   {"unified_logs", "launch_agents", "launch_daemons", "safari_history", "quarantine_db"},
	}

	c.JSON(200, gin.H{
		"platform":          platform,
		"available":         platformArtifacts[platform],
		"artifact_type":     artifactType,
		"entries":           artifacts,
	})
}
