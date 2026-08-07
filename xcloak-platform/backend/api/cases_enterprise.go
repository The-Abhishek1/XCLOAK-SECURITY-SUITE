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
	"xcloak-platform/repositories"
	"xcloak-platform/services"
)

// createCasesTables creates only the tables with no real migrated
// equivalent (case_tasks/case_notes/case_timeline). The real `cases`,
// `case_alerts`, `case_comments`, and `case_evidence` tables already exist
// via migration (see repositories/case_repository.go) with a schema that
// does NOT match what this file's handlers used to assume — every handler
// below has been rewritten to use the real columns. `tags`/`template` are
// added defensively since no real column exists for either and the
// frontend actively uses both.
func createCasesTables() {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS case_tasks (
			id SERIAL PRIMARY KEY, case_id INTEGER NOT NULL,
			tenant_id INTEGER NOT NULL, title TEXT DEFAULT '',
			status TEXT DEFAULT 'pending', priority TEXT DEFAULT 'medium',
			assignee TEXT DEFAULT '', due_date TIMESTAMPTZ,
			checklist TEXT DEFAULT '', notes TEXT DEFAULT '',
			created_at TIMESTAMPTZ DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS case_notes (
			id SERIAL PRIMARY KEY, case_id INTEGER NOT NULL,
			tenant_id INTEGER NOT NULL, content TEXT DEFAULT '',
			author TEXT DEFAULT '', note_type TEXT DEFAULT 'markdown',
			created_at TIMESTAMPTZ DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS case_timeline (
			id SERIAL PRIMARY KEY, case_id INTEGER NOT NULL,
			tenant_id INTEGER NOT NULL, event TEXT DEFAULT '',
			actor TEXT DEFAULT '', event_type TEXT DEFAULT '',
			created_at TIMESTAMPTZ DEFAULT NOW()
		)`,
	}
	for _, s := range stmts {
		database.DB.Exec(s)
	}
	database.DB.Exec(`ALTER TABLE cases ADD COLUMN IF NOT EXISTS tags TEXT DEFAULT ''`)
	database.DB.Exec(`ALTER TABLE cases ADD COLUMN IF NOT EXISTS template TEXT DEFAULT ''`)
	database.DB.Exec(`ALTER TABLE case_evidence ADD COLUMN IF NOT EXISTS file_hash TEXT DEFAULT ''`)
	database.DB.Exec(`ALTER TABLE case_evidence ADD COLUMN IF NOT EXISTS collector TEXT DEFAULT ''`)
	database.DB.Exec(`ALTER TABLE case_evidence ADD COLUMN IF NOT EXISTS current_owner TEXT DEFAULT ''`)
	database.DB.Exec(`ALTER TABLE case_evidence ADD COLUMN IF NOT EXISTS verified BOOLEAN DEFAULT false`)
	database.DB.Exec(`ALTER TABLE case_evidence ADD COLUMN IF NOT EXISTS custody_chain TEXT DEFAULT '[]'`)
}

// caseSLAStatus derives the same "ok/warning/breach" concept the old fake
// schema stored directly, from the real sla_breached/sla_breach_at columns.
func caseSLAStatus(slaBreached bool, slaBreachAt *time.Time) string {
	if slaBreached {
		return "breach"
	}
	if slaBreachAt == nil {
		return "ok"
	}
	if time.Until(*slaBreachAt) < 2*time.Hour {
		return "warning"
	}
	return "ok"
}

var caseTemplateTasks = map[string][]string{
	"malware":        {"Collect memory dump", "Run YARA scan", "Extract IOCs", "Check threat intel", "Isolate endpoint", "Notify IT"},
	"phishing":       {"Collect phishing email headers", "Extract URLs and attachments", "Analyse payload", "Identify impacted users", "Block sender and URLs", "Notify affected users"},
	"ransomware":     {"Isolate affected hosts", "Identify patient zero", "Preserve forensic images", "Check backups", "Assess blast radius", "Initiate recovery", "Legal notification"},
	"insider_threat": {"Preserve user activity logs", "HR notification", "Legal hold", "Interview manager", "Collect DLP data", "Document findings"},
	"cloud_incident": {"Identify compromised credentials", "Audit CloudTrail/Activity Logs", "Check IAM changes", "Assess data exposure", "Rotate credentials", "Harden posture"},
	"ad_attack":      {"Identify compromised accounts", "Check for Golden Ticket", "Audit domain admin membership", "Reset KRBTGT", "Force password resets", "Review ACLs"},
	"data_exfil":     {"Identify exfil channel", "Quantify data volume", "Preserve network logs", "Block destination", "Legal/compliance notification", "PR preparation"},
}

// GetCasesDashboard — GET /api/cases/dashboard
func GetCasesDashboard(c *gin.Context) {
	createCasesTables()
	tid := tenantIDFromContext(c)
	var open, inProgress, waiting, escalated, closed int
	var slaBreach, slaWarning int
	// "investigating" and "resolved" are real statuses this schema allows
	// (see repositories.GetCaseMetrics's own open/closed split) that the
	// dashboard's 5-bucket UI doesn't have a dedicated card for — folded
	// into the closest existing bucket so every case is counted somewhere.
	database.DB.QueryRow(`SELECT COUNT(*) FROM cases WHERE tenant_id=$1 AND status='open'`, tid).Scan(&open)
	database.DB.QueryRow(`SELECT COUNT(*) FROM cases WHERE tenant_id=$1 AND status IN ('in_progress','investigating')`, tid).Scan(&inProgress)
	database.DB.QueryRow(`SELECT COUNT(*) FROM cases WHERE tenant_id=$1 AND status='waiting_approval'`, tid).Scan(&waiting)
	database.DB.QueryRow(`SELECT COUNT(*) FROM cases WHERE tenant_id=$1 AND status='escalated'`, tid).Scan(&escalated)
	database.DB.QueryRow(`SELECT COUNT(*) FROM cases WHERE tenant_id=$1 AND status IN ('closed','resolved')`, tid).Scan(&closed)
	database.DB.QueryRow(`SELECT COUNT(*) FROM cases WHERE tenant_id=$1 AND sla_breached=true`, tid).Scan(&slaBreach)
	database.DB.QueryRow(`SELECT COUNT(*) FROM cases WHERE tenant_id=$1 AND sla_breached=false AND sla_breach_at IS NOT NULL AND sla_breach_at < NOW()+INTERVAL '2 hours'`, tid).Scan(&slaWarning)

	_, _, mttrHours, _, _ := repositories.GetCaseMetrics(tid)

	type analystRow struct {
		Analyst    string `json:"analyst"`
		Open       int    `json:"open"`
		InProgress int    `json:"in_progress"`
		Closed     int    `json:"closed"`
	}
	workload := []analystRow{}
	wRows, _ := database.DB.Query(`
		SELECT assigned_to_name,
			COUNT(*) FILTER (WHERE status='open'),
			COUNT(*) FILTER (WHERE status='in_progress'),
			COUNT(*) FILTER (WHERE status='closed')
		FROM cases WHERE tenant_id=$1 AND assigned_to_name != ''
		GROUP BY assigned_to_name ORDER BY COUNT(*) DESC LIMIT 10`, tid)
	if wRows != nil {
		defer wRows.Close()
		for wRows.Next() {
			var r analystRow
			if wRows.Scan(&r.Analyst, &r.Open, &r.InProgress, &r.Closed) == nil {
				workload = append(workload, r)
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"open":             open,
		"in_progress":      inProgress,
		"waiting_approval": waiting,
		"escalated":        escalated,
		"closed":           closed,
		"sla_breach":       slaBreach,
		"sla_warning":      slaWarning,
		"avg_resolution_h": int(mttrHours),
		"analyst_workload": workload,
	})
}

// GetCasesAnalytics — GET /api/cases/analytics
func GetCasesAnalytics(c *gin.Context) {
	createCasesTables()
	tid := tenantIDFromContext(c)
	type TrendPoint struct {
		Date  string `json:"date"`
		Count int    `json:"count"`
	}
	trend := []TrendPoint{}
	for i := 13; i >= 0; i-- {
		d := time.Now().AddDate(0, 0, -i).Format("2006-01-02")
		var cnt int
		database.DB.QueryRow(`SELECT COUNT(*) FROM cases WHERE tenant_id=$1 AND DATE(created_at)<=$2`, tid, d).Scan(&cnt)
		trend = append(trend, TrendPoint{Date: d, Count: cnt})
	}

	type sevRow struct {
		Severity string `json:"severity"`
		Count    int    `json:"count"`
	}
	bySeverity := []sevRow{}
	sRows, _ := database.DB.Query(`SELECT severity, COUNT(*) FROM cases WHERE tenant_id=$1 GROUP BY severity ORDER BY COUNT(*) DESC`, tid)
	if sRows != nil {
		defer sRows.Close()
		for sRows.Next() {
			var r sevRow
			if sRows.Scan(&r.Severity, &r.Count) == nil {
				bySeverity = append(bySeverity, r)
			}
		}
	}

	type analystCountRow struct {
		Analyst string `json:"analyst"`
		Count   int    `json:"count"`
	}
	byAnalyst := []analystCountRow{}
	aRows, _ := database.DB.Query(`SELECT assigned_to_name, COUNT(*) FROM cases WHERE tenant_id=$1 AND assigned_to_name != '' GROUP BY assigned_to_name ORDER BY COUNT(*) DESC LIMIT 10`, tid)
	if aRows != nil {
		defer aRows.Close()
		for aRows.Next() {
			var r analystCountRow
			if aRows.Scan(&r.Analyst, &r.Count) == nil {
				byAnalyst = append(byAnalyst, r)
			}
		}
	}

	type resolutionRow struct {
		Severity string  `json:"severity"`
		Hours    float64 `json:"hours"`
	}
	avgResolution := []resolutionRow{}
	rRows, _ := database.DB.Query(`
		SELECT severity, COALESCE(AVG(EXTRACT(EPOCH FROM (closed_at-created_at))/3600),0)
		FROM cases WHERE tenant_id=$1 AND closed_at IS NOT NULL
		GROUP BY severity`, tid)
	if rRows != nil {
		defer rRows.Close()
		for rRows.Next() {
			var r resolutionRow
			if rRows.Scan(&r.Severity, &r.Hours) == nil {
				avgResolution = append(avgResolution, r)
			}
		}
	}

	_, _, _, slaRate, _ := repositories.GetCaseMetrics(tid)

	c.JSON(http.StatusOK, gin.H{
		"case_trend":           trend,
		"by_severity":          bySeverity,
		"by_analyst":           byAnalyst,
		"avg_resolution_hours": avgResolution,
		"sla_compliance":       int(slaRate),
	})
}

// GetCasesTemplates — GET /api/cases/templates
func GetCasesTemplates(c *gin.Context) {
	createCasesTables()
	c.JSON(http.StatusOK, []map[string]interface{}{
		{"id": "malware", "name": "Malware Investigation", "icon": "🦠", "description": "Malware triage, memory forensics, IOC extraction", "tasks": []string{"Collect memory dump", "Run YARA scan", "Extract IOCs", "Check threat intel", "Isolate endpoint", "Notify IT"}},
		{"id": "phishing", "name": "Phishing Investigation", "icon": "🎣", "description": "Email phishing analysis and user impact assessment", "tasks": []string{"Collect phishing email headers", "Extract URLs and attachments", "Analyse payload", "Identify impacted users", "Block sender and URLs", "Notify affected users"}},
		{"id": "ransomware", "name": "Ransomware Response", "icon": "🔐", "description": "Ransomware containment, recovery, and forensics", "tasks": []string{"Isolate affected hosts", "Identify patient zero", "Preserve forensic images", "Check backups", "Assess blast radius", "Initiate recovery", "Legal notification"}},
		{"id": "insider_threat", "name": "Insider Threat", "icon": "👤", "description": "Insider threat investigation with HR/Legal involvement", "tasks": []string{"Preserve user activity logs", "HR notification", "Legal hold", "Interview manager", "Collect DLP data", "Document findings"}},
		{"id": "cloud_incident", "name": "Cloud Incident", "icon": "☁", "description": "Cloud environment compromise investigation", "tasks": []string{"Identify compromised credentials", "Audit CloudTrail/Activity Logs", "Check IAM changes", "Assess data exposure", "Rotate credentials", "Harden posture"}},
		{"id": "ad_attack", "name": "AD Attack", "icon": "🏛", "description": "Active Directory compromise response", "tasks": []string{"Identify compromised accounts", "Check for Golden Ticket", "Audit domain admin membership", "Reset KRBTGT", "Force password resets", "Review ACLs"}},
		{"id": "data_exfil", "name": "Data Exfiltration", "icon": "📤", "description": "Data exfiltration detection and containment", "tasks": []string{"Identify exfil channel", "Quantify data volume", "Preserve network logs", "Block destination", "Legal/compliance notification", "PR preparation"}},
	})
}

type caseJSON struct {
	ID          int        `json:"id"`
	CaseID      string     `json:"case_id"`
	Title       string     `json:"title"`
	Description string     `json:"description"`
	Severity    string     `json:"severity"`
	Priority    string     `json:"priority"`
	Status      string     `json:"status"`
	Owner       string     `json:"owner"`
	DueDate     *time.Time `json:"due_date"`
	SLAStatus   string     `json:"sla_status"`
	Tags        string     `json:"tags"`
	Template    string     `json:"template"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

// GetCasesEnt — GET /api/cases
func GetCasesEnt(c *gin.Context) {
	createCasesTables()
	tid := tenantIDFromContext(c)
	limit := parseLimit(c, 50)
	q := `SELECT id, title, description, severity, status, assigned_to_name, sla_breach_at, sla_breached, tags, template, created_at, updated_at
		FROM cases WHERE tenant_id=$1`
	args := []interface{}{tid}
	i := 2
	if v := c.Query("status"); v != "" {
		q += fmt.Sprintf(" AND status=$%d", i)
		args = append(args, v)
		i++
	}
	if v := c.Query("severity"); v != "" {
		q += fmt.Sprintf(" AND severity=$%d", i)
		args = append(args, v)
		i++
	}
	if v := c.Query("owner"); v != "" {
		q += fmt.Sprintf(" AND assigned_to_name=$%d", i)
		args = append(args, v)
		i++
	}
	q += fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d", i)
	args = append(args, limit)
	rows, err := database.DB.Query(q, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()
	cases := []caseJSON{}
	for rows.Next() {
		var cs caseJSON
		var owner string
		var slaBreachAt *time.Time
		var slaBreached bool
		if rows.Scan(&cs.ID, &cs.Title, &cs.Description, &cs.Severity, &cs.Status, &owner, &slaBreachAt, &slaBreached, &cs.Tags, &cs.Template, &cs.CreatedAt, &cs.UpdatedAt) == nil {
			cs.CaseID = fmt.Sprintf("CASE-%04d", cs.ID)
			cs.Priority = cs.Severity
			cs.Owner = owner
			cs.DueDate = slaBreachAt
			cs.SLAStatus = caseSLAStatus(slaBreached, slaBreachAt)
			cases = append(cases, cs)
		}
	}
	c.JSON(http.StatusOK, cases)
}

// PostCase — POST /api/cases
func PostCase(c *gin.Context) {
	createCasesTables()
	tid := tenantIDFromContext(c)
	var body struct {
		Title       string `json:"title"`
		Description string `json:"description"`
		Severity    string `json:"severity"`
		Owner       string `json:"owner"`
		Template    string `json:"template"`
		Tags        string `json:"tags"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Title == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "title required"})
		return
	}
	if body.Severity == "" {
		body.Severity = "medium"
	}
	slaHours := repositories.SLAHoursForSeverity(body.Severity)
	slaBreachAt := repositories.SLABreachTime(body.Severity)
	var id int
	if err := database.DB.QueryRow(`
		INSERT INTO cases (tenant_id, title, description, severity, status, assigned_to_name, sla_hours, sla_breach_at, tags, template)
		VALUES ($1,$2,$3,$4,'open',$5,$6,$7,$8,$9) RETURNING id`,
		tid, body.Title, body.Description, body.Severity, body.Owner, slaHours, slaBreachAt, body.Tags, body.Template,
	).Scan(&id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if tasks, ok := caseTemplateTasks[body.Template]; ok {
		for _, title := range tasks {
			database.DB.Exec(`INSERT INTO case_tasks (case_id, tenant_id, title, status, priority) VALUES ($1,$2,$3,'pending','medium')`, id, tid, title)
		}
	}
	c.JSON(http.StatusOK, gin.H{"id": id, "case_id": fmt.Sprintf("CASE-%04d", id), "ok": true})
}

// GetCaseByIDEnt — GET /api/cases/:id
func GetCaseByIDEnt(c *gin.Context) {
	createCasesTables()
	tid := tenantIDFromContext(c)
	cid, _ := strconv.Atoi(c.Param("id"))
	var cs caseJSON
	var owner string
	var slaBreachAt *time.Time
	var slaBreached bool
	err := database.DB.QueryRow(`
		SELECT id, title, description, severity, status, assigned_to_name, sla_breach_at, sla_breached, tags, template, created_at, updated_at
		FROM cases WHERE id=$1 AND tenant_id=$2`, cid, tid,
	).Scan(&cs.ID, &cs.Title, &cs.Description, &cs.Severity, &cs.Status, &owner, &slaBreachAt, &slaBreached, &cs.Tags, &cs.Template, &cs.CreatedAt, &cs.UpdatedAt)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	cs.CaseID = fmt.Sprintf("CASE-%04d", cs.ID)
	cs.Priority = cs.Severity
	cs.Owner = owner
	cs.DueDate = slaBreachAt
	cs.SLAStatus = caseSLAStatus(slaBreached, slaBreachAt)
	c.JSON(http.StatusOK, cs)
}

// PatchCase — PATCH /api/cases/:id
func PatchCase(c *gin.Context) {
	createCasesTables()
	tid := tenantIDFromContext(c)
	cid, _ := strconv.Atoi(c.Param("id"))
	var body map[string]interface{}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	// Map the frontend's field names onto the real schema's columns.
	colFor := map[string]string{
		"title": "title", "description": "description", "severity": "severity",
		"status": "status", "owner": "assigned_to_name", "tags": "tags", "template": "template",
	}
	fields := []string{}
	vals := []interface{}{}
	i := 1
	for _, k := range []string{"title", "description", "severity", "status", "owner", "tags", "template"} {
		if v, ok := body[k]; ok {
			fields = append(fields, fmt.Sprintf("%s=$%d", colFor[k], i))
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
	vals = append(vals, cid, tid)
	if _, err := database.DB.Exec(fmt.Sprintf(`UPDATE cases SET %s WHERE id=$%d AND tenant_id=$%d`, strings.Join(fields, ","), i, i+1), vals...); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// DeleteCaseEnt — DELETE /api/cases/:id
func DeleteCaseEnt(c *gin.Context) {
	createCasesTables()
	tid := tenantIDFromContext(c)
	cid, _ := strconv.Atoi(c.Param("id"))
	// case_alerts/case_comments/case_evidence cascade via real FKs; the
	// lazily-created case_tasks/case_notes/case_timeline have none, so
	// clean those up explicitly to avoid orphaned rows.
	database.DB.Exec(`DELETE FROM case_tasks WHERE case_id=$1 AND tenant_id=$2`, cid, tid)
	database.DB.Exec(`DELETE FROM case_notes WHERE case_id=$1 AND tenant_id=$2`, cid, tid)
	database.DB.Exec(`DELETE FROM case_timeline WHERE case_id=$1 AND tenant_id=$2`, cid, tid)
	database.DB.Exec(`DELETE FROM cases WHERE id=$1 AND tenant_id=$2`, cid, tid)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// GetCaseTasks — GET /api/cases/:id/tasks
func GetCaseTasks(c *gin.Context) {
	createCasesTables()
	tid := tenantIDFromContext(c)
	cid, _ := strconv.Atoi(c.Param("id"))
	rows, _ := database.DB.Query(`SELECT id,title,status,priority,assignee,due_date,checklist,notes,created_at
		FROM case_tasks WHERE case_id=$1 AND tenant_id=$2 ORDER BY created_at`, cid, tid)
	type Task struct {
		ID        int     `json:"id"`
		Title     string  `json:"title"`
		Status    string  `json:"status"`
		Priority  string  `json:"priority"`
		Assignee  string  `json:"assignee"`
		DueDate   *string `json:"due_date"`
		Checklist string  `json:"checklist"`
		Notes     string  `json:"notes"`
		CreatedAt string  `json:"created_at"`
	}
	tasks := []Task{}
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var t Task
			if rows.Scan(&t.ID, &t.Title, &t.Status, &t.Priority, &t.Assignee, &t.DueDate, &t.Checklist, &t.Notes, &t.CreatedAt) == nil {
				tasks = append(tasks, t)
			}
		}
	}
	if tasks == nil {
		tasks = []Task{}
	}
	c.JSON(http.StatusOK, tasks)
}

// PostCaseTask — POST /api/cases/:id/tasks
func PostCaseTask(c *gin.Context) {
	createCasesTables()
	tid := tenantIDFromContext(c)
	cid, _ := strconv.Atoi(c.Param("id"))
	var body struct {
		Title     string `json:"title"`
		Priority  string `json:"priority"`
		Assignee  string `json:"assignee"`
		Checklist string `json:"checklist"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Title == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "title required"})
		return
	}
	if body.Priority == "" {
		body.Priority = "medium"
	}
	var id int
	database.DB.QueryRow(`INSERT INTO case_tasks(case_id,tenant_id,title,status,priority,assignee,checklist) VALUES($1,$2,$3,'pending',$4,$5,$6) RETURNING id`,
		cid, tid, body.Title, body.Priority, body.Assignee, body.Checklist).Scan(&id)
	c.JSON(http.StatusOK, gin.H{"id": id, "ok": true})
}

// PatchCaseTask — PATCH /api/cases/:id/tasks/:tid
func PatchCaseTask(c *gin.Context) {
	createCasesTables()
	tid := tenantIDFromContext(c)
	taskID, _ := strconv.Atoi(c.Param("tid"))
	var body struct {
		Status    string `json:"status"`
		Assignee  string `json:"assignee"`
		Notes     string `json:"notes"`
		Checklist string `json:"checklist"`
	}
	c.ShouldBindJSON(&body)
	database.DB.Exec(`UPDATE case_tasks SET status=COALESCE(NULLIF($1,''),status), assignee=COALESCE(NULLIF($2,''),assignee), notes=COALESCE(NULLIF($3,''),notes), checklist=COALESCE(NULLIF($4,''),checklist) WHERE id=$5 AND tenant_id=$6`,
		body.Status, body.Assignee, body.Notes, body.Checklist, taskID, tid)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// GetCaseEvidence — GET /api/cases/:id/evidence
func GetCaseEvidence(c *gin.Context) {
	createCasesTables()
	tid := tenantIDFromContext(c)
	cid, _ := strconv.Atoi(c.Param("id"))
	rows, err := database.DB.Query(`
		SELECT ce.id, ce.title, ce.evidence_type, ce.file_hash, ce.collector, ce.current_owner, ce.verified, ce.custody_chain, ce.description, ce.created_at
		FROM case_evidence ce JOIN cases cs ON cs.id = ce.case_id
		WHERE ce.case_id=$1 AND cs.tenant_id=$2 ORDER BY ce.created_at DESC`, cid, tid)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()
	type Evidence struct {
		ID           int    `json:"id"`
		EvidenceID   string `json:"evidence_id"`
		Title        string `json:"title"`
		EvidenceType string `json:"evidence_type"`
		FileHash     string `json:"file_hash"`
		Collector    string `json:"collector"`
		CurrentOwner string `json:"current_owner"`
		Verified     bool   `json:"verified"`
		CustodyChain string `json:"custody_chain"`
		Notes        string `json:"notes"`
		CreatedAt    string `json:"created_at"`
	}
	items := []Evidence{}
	for rows.Next() {
		var e Evidence
		if rows.Scan(&e.ID, &e.Title, &e.EvidenceType, &e.FileHash, &e.Collector, &e.CurrentOwner, &e.Verified, &e.CustodyChain, &e.Notes, &e.CreatedAt) == nil {
			e.EvidenceID = fmt.Sprintf("EVD-%04d", e.ID)
			items = append(items, e)
		}
	}
	c.JSON(http.StatusOK, items)
}

// PostCaseEvidence — POST /api/cases/:id/evidence
func PostCaseEvidence(c *gin.Context) {
	createCasesTables()
	tid := tenantIDFromContext(c)
	cid, _ := strconv.Atoi(c.Param("id"))
	var owns bool
	database.DB.QueryRow(`SELECT EXISTS(SELECT 1 FROM cases WHERE id=$1 AND tenant_id=$2)`, cid, tid).Scan(&owns)
	if !owns {
		c.JSON(http.StatusNotFound, gin.H{"error": "case not found"})
		return
	}
	var body struct {
		Title        string `json:"title"`
		EvidenceType string `json:"evidence_type"`
		FileHash     string `json:"file_hash"`
		Collector    string `json:"collector"`
		Notes        string `json:"notes"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Title == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "title required"})
		return
	}
	addedBy := usernameFromContext(c)
	uid := userIDFromContext(c)
	// added_by is a nullable int FK to users.id — API-key-authenticated
	// requests get user_id=0 from context (a key isn't tied to a real
	// users row), and inserting that raw 0 violated
	// case_evidence_added_by_fkey on every single "Add Evidence" call made
	// over an API key.
	var uidArg *int
	if uid != 0 {
		uidArg = &uid
	}
	custody, _ := json.Marshal([]map[string]interface{}{
		{"action": "collected", "from": "", "to": addedBy, "timestamp": time.Now().Format(time.RFC3339)},
	})
	var id int
	if err := database.DB.QueryRow(`
		INSERT INTO case_evidence (case_id, evidence_type, title, description, added_by, added_by_name, file_hash, collector, current_owner, verified, custody_chain)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$8,false,$9) RETURNING id`,
		cid, body.EvidenceType, body.Title, body.Notes, uidArg, addedBy, body.FileHash, body.Collector, string(custody),
	).Scan(&id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"id": id, "evidence_id": fmt.Sprintf("EVD-%04d", id), "ok": true})
}

// GetCaseNotes — GET /api/cases/:id/notes
func GetCaseNotes(c *gin.Context) {
	createCasesTables()
	tid := tenantIDFromContext(c)
	cid, _ := strconv.Atoi(c.Param("id"))
	rows, _ := database.DB.Query(`SELECT id,content,author,note_type,created_at FROM case_notes WHERE case_id=$1 AND tenant_id=$2 ORDER BY created_at DESC`, cid, tid)
	type Note struct {
		ID        int    `json:"id"`
		Content   string `json:"content"`
		Author    string `json:"author"`
		NoteType  string `json:"note_type"`
		CreatedAt string `json:"created_at"`
	}
	notes := []Note{}
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var n Note
			if rows.Scan(&n.ID, &n.Content, &n.Author, &n.NoteType, &n.CreatedAt) == nil {
				notes = append(notes, n)
			}
		}
	}
	if notes == nil {
		notes = []Note{}
	}
	c.JSON(http.StatusOK, notes)
}

// PostCaseNote — POST /api/cases/:id/notes
func PostCaseNote(c *gin.Context) {
	createCasesTables()
	tid := tenantIDFromContext(c)
	cid, _ := strconv.Atoi(c.Param("id"))
	var body struct {
		Content  string `json:"content"`
		Author   string `json:"author"`
		NoteType string `json:"note_type"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Content == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "content required"})
		return
	}
	if body.NoteType == "" {
		body.NoteType = "markdown"
	}
	var id int
	database.DB.QueryRow(`INSERT INTO case_notes(case_id,tenant_id,content,author,note_type) VALUES($1,$2,$3,$4,$5) RETURNING id`,
		cid, tid, body.Content, body.Author, body.NoteType).Scan(&id)
	c.JSON(http.StatusOK, gin.H{"id": id, "ok": true})
}

// GetCaseTimeline — GET /api/cases/:id/timeline
func GetCaseTimeline(c *gin.Context) {
	createCasesTables()
	tid := tenantIDFromContext(c)
	cid, _ := strconv.Atoi(c.Param("id"))
	rows, _ := database.DB.Query(`SELECT id,event,actor,event_type,created_at FROM case_timeline WHERE case_id=$1 AND tenant_id=$2 ORDER BY created_at`, cid, tid)
	type TLEvent struct {
		ID        int    `json:"id"`
		Event     string `json:"event"`
		Actor     string `json:"actor"`
		EventType string `json:"event_type"`
		CreatedAt string `json:"created_at"`
	}
	events := []TLEvent{}
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var e TLEvent
			if rows.Scan(&e.ID, &e.Event, &e.Actor, &e.EventType, &e.CreatedAt) == nil {
				events = append(events, e)
			}
		}
	}
	if events == nil {
		events = []TLEvent{}
	}
	c.JSON(http.StatusOK, events)
}

// GetCaseComments — GET /api/cases/:id/comments
func GetCaseComments(c *gin.Context) {
	createCasesTables()
	tid := tenantIDFromContext(c)
	cid, _ := strconv.Atoi(c.Param("id"))
	rows, err := database.DB.Query(`
		SELECT cc.id, cc.body, cc.username, cc.is_system, cc.created_at
		FROM case_comments cc JOIN cases cs ON cs.id = cc.case_id
		WHERE cc.case_id=$1 AND cs.tenant_id=$2 ORDER BY cc.created_at`, cid, tid)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()
	type Comment struct {
		ID        int    `json:"id"`
		Content   string `json:"content"`
		Author    string `json:"author"`
		IsSystem  bool   `json:"is_system"`
		CreatedAt string `json:"created_at"`
	}
	comments := []Comment{}
	for rows.Next() {
		var cm Comment
		if rows.Scan(&cm.ID, &cm.Content, &cm.Author, &cm.IsSystem, &cm.CreatedAt) == nil {
			comments = append(comments, cm)
		}
	}
	c.JSON(http.StatusOK, comments)
}

// PostCaseComment — POST /api/cases/:id/comments
func PostCaseComment(c *gin.Context) {
	createCasesTables()
	tid := tenantIDFromContext(c)
	cid, _ := strconv.Atoi(c.Param("id"))
	var owns bool
	database.DB.QueryRow(`SELECT EXISTS(SELECT 1 FROM cases WHERE id=$1 AND tenant_id=$2)`, cid, tid).Scan(&owns)
	if !owns {
		c.JSON(http.StatusNotFound, gin.H{"error": "case not found"})
		return
	}
	var body struct {
		Content string `json:"content"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Content == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "content required"})
		return
	}
	uid := userIDFromContext(c)
	username := usernameFromContext(c)
	// user_id is a nullable int FK to users.id — API-key requests get
	// user_id=0 from context, and inserting that raw 0 violated
	// case_comments_user_id_fkey on every comment posted over an API key.
	var uidArg *int
	if uid != 0 {
		uidArg = &uid
	}
	var id int
	if err := database.DB.QueryRow(`INSERT INTO case_comments (case_id, user_id, username, body, is_system) VALUES ($1,$2,$3,$4,false) RETURNING id`,
		cid, uidArg, username, body.Content).Scan(&id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"id": id, "ok": true})
}

// PostCasesAI — POST /api/cases/ai
func PostCasesAI(c *gin.Context) {
	createCasesTables()
	var body struct {
		Mode    string `json:"mode"`
		CaseID  string `json:"case_id"`
		Content string `json:"content"`
		Context string `json:"context"`
	}
	c.ShouldBindJSON(&body)
	var prompt string
	switch body.Mode {
	case "summarize":
		prompt = fmt.Sprintf(`You are a senior SOC analyst. Summarize this incident case:
Case ID: %s
Context: %s
Provide compact JSON: {"summary":"2-3 sentence case summary","key_findings":["finding"],"current_status":"status","risk_level":"critical|high|medium|low","next_steps":["step"]}`, body.CaseID, body.Context)
	case "next_steps":
		prompt = fmt.Sprintf(`You are a senior SOC analyst. Based on this case context, suggest the next investigation steps:
%s
Provide compact JSON: {"next_steps":["step1","step2"],"missing_evidence":["evidence item"],"recommended_playbook":"playbook name","estimated_time_hours":4}`, body.Context)
	case "root_cause":
		prompt = fmt.Sprintf(`You are a DFIR expert. Identify and document the root cause for this case:
%s
Provide compact JSON: {"initial_access":"description","persistence":"description","lateral_movement":"description","impact":"description","root_cause":"root cause sentence","lessons_learned":["lesson"]}`, body.Context)
	default:
		prompt = fmt.Sprintf(`You are a senior SOC analyst. Answer this case investigation question: %s
Provide compact JSON: {"answer":"expert answer","confidence":88,"related_techniques":["technique"],"recommended_actions":["action"]}`, body.Content)
	}
	raw, err := services.CallLLM(prompt)
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

// PostCasesReport — POST /api/cases/report
func PostCasesReport(c *gin.Context) {
	createCasesTables()
	var body struct {
		ReportType string `json:"report_type"`
		CaseID     string `json:"case_id"`
		Context    string `json:"context"`
	}
	c.ShouldBindJSON(&body)
	prompt := fmt.Sprintf(`Generate a %s report for this security incident case:
Case ID: %s
Context: %s
Provide compact JSON: {"title":"report title","executive_summary":"3 sentences","timeline":["event1","event2"],"technical_findings":["finding"],"iocs":["ioc"],"recommendations":["recommendation"],"lessons_learned":["lesson"],"classification":"TLP:AMBER"}`,
		body.ReportType, body.CaseID, body.Context)
	raw, err := services.CallLLM(prompt)
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
