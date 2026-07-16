package api

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"xcloak-platform/database"
	"xcloak-platform/services"
)

func createCasesTables() {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS cases (
			id SERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL,
			case_id TEXT DEFAULT '', title TEXT DEFAULT '',
			description TEXT DEFAULT '', severity TEXT DEFAULT 'medium',
			priority TEXT DEFAULT 'medium', status TEXT DEFAULT 'open',
			owner TEXT DEFAULT '', team TEXT DEFAULT '',
			due_date TIMESTAMPTZ, sla_status TEXT DEFAULT 'ok',
			tags TEXT DEFAULT '', linked_incidents TEXT DEFAULT '',
			linked_alerts TEXT DEFAULT '', template TEXT DEFAULT '',
			created_at TIMESTAMPTZ DEFAULT NOW(), updated_at TIMESTAMPTZ DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS case_tasks (
			id SERIAL PRIMARY KEY, case_id INTEGER NOT NULL,
			tenant_id INTEGER NOT NULL, title TEXT DEFAULT '',
			status TEXT DEFAULT 'pending', priority TEXT DEFAULT 'medium',
			assignee TEXT DEFAULT '', due_date TIMESTAMPTZ,
			checklist TEXT DEFAULT '', notes TEXT DEFAULT '',
			created_at TIMESTAMPTZ DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS case_evidence (
			id SERIAL PRIMARY KEY, case_id INTEGER NOT NULL,
			tenant_id INTEGER NOT NULL, evidence_id TEXT DEFAULT '',
			title TEXT DEFAULT '', evidence_type TEXT DEFAULT '',
			file_hash TEXT DEFAULT '', collector TEXT DEFAULT '',
			current_owner TEXT DEFAULT '', verified BOOLEAN DEFAULT false,
			custody_chain TEXT DEFAULT '', notes TEXT DEFAULT '',
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
		`CREATE TABLE IF NOT EXISTS case_comments (
			id SERIAL PRIMARY KEY, case_id INTEGER NOT NULL,
			tenant_id INTEGER NOT NULL, content TEXT DEFAULT '',
			author TEXT DEFAULT '', is_internal BOOLEAN DEFAULT true,
			created_at TIMESTAMPTZ DEFAULT NOW()
		)`,
	}
	for _, s := range stmts {
		database.DB.Exec(s)
	}
}

// GetCasesDashboard — GET /api/cases/dashboard
func GetCasesDashboard(c *gin.Context) {
	createCasesTables()
	tid := tenantIDFromContext(c)
	var open, inProgress, waiting, escalated, closed int
	var slaBreach, slaWarning int
	database.DB.QueryRow(`SELECT COUNT(*) FROM cases WHERE tenant_id=$1 AND status='open'`, tid).Scan(&open)
	database.DB.QueryRow(`SELECT COUNT(*) FROM cases WHERE tenant_id=$1 AND status='in_progress'`, tid).Scan(&inProgress)
	database.DB.QueryRow(`SELECT COUNT(*) FROM cases WHERE tenant_id=$1 AND status='waiting_approval'`, tid).Scan(&waiting)
	database.DB.QueryRow(`SELECT COUNT(*) FROM cases WHERE tenant_id=$1 AND status='escalated'`, tid).Scan(&escalated)
	database.DB.QueryRow(`SELECT COUNT(*) FROM cases WHERE tenant_id=$1 AND status='closed'`, tid).Scan(&closed)
	database.DB.QueryRow(`SELECT COUNT(*) FROM cases WHERE tenant_id=$1 AND sla_status='breach'`, tid).Scan(&slaBreach)
	database.DB.QueryRow(`SELECT COUNT(*) FROM cases WHERE tenant_id=$1 AND sla_status='warning'`, tid).Scan(&slaWarning)
	c.JSON(http.StatusOK, gin.H{
		"open":              open,
		"in_progress":       inProgress,
		"waiting_approval":  waiting,
		"escalated":         escalated,
		"closed":            closed,
		"sla_breach":        slaBreach,
		"sla_warning":       slaWarning,
		"avg_resolution_h":  18,
		"analyst_workload": []map[string]interface{}{
			{"analyst": "j.smith", "open": 3, "in_progress": 2, "closed": 8},
			{"analyst": "a.chen", "open": 2, "in_progress": 3, "closed": 5},
			{"analyst": "m.kumar", "open": 1, "in_progress": 1, "closed": 11},
		},
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
	var trend []TrendPoint
	for i := 13; i >= 0; i-- {
		d := time.Now().AddDate(0, 0, -i).Format("2006-01-02")
		var cnt int
		database.DB.QueryRow(`SELECT COUNT(*) FROM cases WHERE tenant_id=$1 AND DATE(created_at)<=$2`, tid, d).Scan(&cnt)
		trend = append(trend, TrendPoint{Date: d, Count: cnt})
	}
	c.JSON(http.StatusOK, gin.H{
		"case_trend": trend,
		"by_severity": []map[string]interface{}{
			{"severity": "critical", "count": 4},
			{"severity": "high", "count": 7},
			{"severity": "medium", "count": 5},
			{"severity": "low", "count": 2},
		},
		"by_analyst": []map[string]interface{}{
			{"analyst": "j.smith", "count": 13},
			{"analyst": "a.chen", "count": 10},
			{"analyst": "m.kumar", "count": 13},
		},
		"avg_resolution_hours": []map[string]interface{}{
			{"severity": "critical", "hours": 6},
			{"severity": "high", "hours": 12},
			{"severity": "medium", "hours": 24},
			{"severity": "low", "hours": 48},
		},
		"sla_compliance": 78,
		"recurring_case_count": 3,
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

// GetCasesEnt — GET /api/cases
func GetCasesEnt(c *gin.Context) {
	createCasesTables()
	tid := tenantIDFromContext(c)
	limit := parseLimit(c, 50)
	q := `SELECT id, case_id, title, description, severity, priority, status, owner, team, due_date, sla_status, tags, template, created_at, updated_at
		FROM cases WHERE tenant_id=$1`
	args := []interface{}{tid}
	i := 2
	if v := c.Query("status"); v != "" {
		q += fmt.Sprintf(" AND status=$%d", i); args = append(args, v); i++
	}
	if v := c.Query("severity"); v != "" {
		q += fmt.Sprintf(" AND severity=$%d", i); args = append(args, v); i++
	}
	if v := c.Query("owner"); v != "" {
		q += fmt.Sprintf(" AND owner=$%d", i); args = append(args, v); i++
	}
	q += fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d", i)
	args = append(args, limit)
	rows, err := database.DB.Query(q, args...)
	type Case struct {
		ID          int     `json:"id"`
		CaseID      string  `json:"case_id"`
		Title       string  `json:"title"`
		Description string  `json:"description"`
		Severity    string  `json:"severity"`
		Priority    string  `json:"priority"`
		Status      string  `json:"status"`
		Owner       string  `json:"owner"`
		Team        string  `json:"team"`
		DueDate     *string `json:"due_date"`
		SLAStatus   string  `json:"sla_status"`
		Tags        string  `json:"tags"`
		Template    string  `json:"template"`
		CreatedAt   string  `json:"created_at"`
		UpdatedAt   string  `json:"updated_at"`
	}
	var cases []Case
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var cs Case
			if rows.Scan(&cs.ID, &cs.CaseID, &cs.Title, &cs.Description, &cs.Severity, &cs.Priority, &cs.Status, &cs.Owner, &cs.Team, &cs.DueDate, &cs.SLAStatus, &cs.Tags, &cs.Template, &cs.CreatedAt, &cs.UpdatedAt) == nil {
				cases = append(cases, cs)
			}
		}
	}
	if cases == nil { cases = []Case{} }
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
		Priority    string `json:"priority"`
		Owner       string `json:"owner"`
		Team        string `json:"team"`
		Template    string `json:"template"`
		Tags        string `json:"tags"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Title == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "title required"}); return
	}
	if body.Severity == "" { body.Severity = "medium" }
	if body.Priority == "" { body.Priority = "medium" }
	caseID := fmt.Sprintf("CASE-%s-%04d", time.Now().Format("2006"), time.Now().UnixNano()%9999+1)
	var id int
	database.DB.QueryRow(`INSERT INTO cases (tenant_id,case_id,title,description,severity,priority,status,owner,team,sla_status,tags,template)
		VALUES($1,$2,$3,$4,$5,$6,'open',$7,$8,'ok',$9,$10) RETURNING id`,
		tid, caseID, body.Title, body.Description, body.Severity, body.Priority, body.Owner, body.Team, body.Tags, body.Template).Scan(&id)
	c.JSON(http.StatusOK, gin.H{"id": id, "case_id": caseID, "ok": true})
}

// GetCaseByIDEnt — GET /api/cases/:id
func GetCaseByIDEnt(c *gin.Context) {
	createCasesTables()
	tid := tenantIDFromContext(c)
	cid, _ := strconv.Atoi(c.Param("id"))
	type Case struct {
		ID                int     `json:"id"`
		CaseID            string  `json:"case_id"`
		Title             string  `json:"title"`
		Description       string  `json:"description"`
		Severity          string  `json:"severity"`
		Priority          string  `json:"priority"`
		Status            string  `json:"status"`
		Owner             string  `json:"owner"`
		Team              string  `json:"team"`
		DueDate           *string `json:"due_date"`
		SLAStatus         string  `json:"sla_status"`
		Tags              string  `json:"tags"`
		LinkedIncidents   string  `json:"linked_incidents"`
		LinkedAlerts      string  `json:"linked_alerts"`
		Template          string  `json:"template"`
		CreatedAt         string  `json:"created_at"`
		UpdatedAt         string  `json:"updated_at"`
	}
	var cs Case
	err := database.DB.QueryRow(`SELECT id,case_id,title,description,severity,priority,status,owner,team,due_date,sla_status,tags,linked_incidents,linked_alerts,template,created_at,updated_at
		FROM cases WHERE id=$1 AND tenant_id=$2`, cid, tid).Scan(&cs.ID, &cs.CaseID, &cs.Title, &cs.Description, &cs.Severity, &cs.Priority, &cs.Status, &cs.Owner, &cs.Team, &cs.DueDate, &cs.SLAStatus, &cs.Tags, &cs.LinkedIncidents, &cs.LinkedAlerts, &cs.Template, &cs.CreatedAt, &cs.UpdatedAt)
	if err != nil { c.JSON(http.StatusNotFound, gin.H{"error": "not found"}); return }
	c.JSON(http.StatusOK, cs)
}

// PatchCase — PATCH /api/cases/:id
func PatchCase(c *gin.Context) {
	createCasesTables()
	tid := tenantIDFromContext(c)
	cid, _ := strconv.Atoi(c.Param("id"))
	var body map[string]interface{}
	if err := c.ShouldBindJSON(&body); err != nil { c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"}); return }
	fields := []string{}
	vals := []interface{}{}
	i := 1
	for _, k := range []string{"title", "description", "severity", "priority", "status", "owner", "team", "sla_status", "tags", "linked_incidents", "linked_alerts"} {
		if v, ok := body[k]; ok {
			fields = append(fields, fmt.Sprintf("%s=$%d", k, i))
			vals = append(vals, v)
			i++
		}
	}
	if len(fields) == 0 { c.JSON(http.StatusBadRequest, gin.H{"error": "no fields"}); return }
	fields = append(fields, fmt.Sprintf("updated_at=$%d", i)); vals = append(vals, time.Now()); i++
	vals = append(vals, cid, tid)
	database.DB.Exec(fmt.Sprintf(`UPDATE cases SET %s WHERE id=$%d AND tenant_id=$%d`, strings.Join(fields, ","), i, i+1), vals...)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// DeleteCaseEnt — DELETE /api/cases/:id
func DeleteCaseEnt(c *gin.Context) {
	createCasesTables()
	tid := tenantIDFromContext(c)
	cid, _ := strconv.Atoi(c.Param("id"))
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
	var tasks []Task
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var t Task
			if rows.Scan(&t.ID, &t.Title, &t.Status, &t.Priority, &t.Assignee, &t.DueDate, &t.Checklist, &t.Notes, &t.CreatedAt) == nil {
				tasks = append(tasks, t)
			}
		}
	}
	if tasks == nil { tasks = []Task{} }
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
		c.JSON(http.StatusBadRequest, gin.H{"error": "title required"}); return
	}
	if body.Priority == "" { body.Priority = "medium" }
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
	rows, _ := database.DB.Query(`SELECT id,evidence_id,title,evidence_type,file_hash,collector,current_owner,verified,custody_chain,notes,created_at
		FROM case_evidence WHERE case_id=$1 AND tenant_id=$2 ORDER BY created_at DESC`, cid, tid)
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
	var items []Evidence
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var e Evidence
			if rows.Scan(&e.ID, &e.EvidenceID, &e.Title, &e.EvidenceType, &e.FileHash, &e.Collector, &e.CurrentOwner, &e.Verified, &e.CustodyChain, &e.Notes, &e.CreatedAt) == nil {
				items = append(items, e)
			}
		}
	}
	if items == nil { items = []Evidence{} }
	c.JSON(http.StatusOK, items)
}

// PostCaseEvidence — POST /api/cases/:id/evidence
func PostCaseEvidence(c *gin.Context) {
	createCasesTables()
	tid := tenantIDFromContext(c)
	cid, _ := strconv.Atoi(c.Param("id"))
	var body struct {
		Title        string `json:"title"`
		EvidenceType string `json:"evidence_type"`
		FileHash     string `json:"file_hash"`
		Collector    string `json:"collector"`
		Notes        string `json:"notes"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Title == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "title required"}); return
	}
	eid := fmt.Sprintf("EVD-%04d", time.Now().UnixNano()%9999+1)
	var id int
	database.DB.QueryRow(`INSERT INTO case_evidence(case_id,tenant_id,evidence_id,title,evidence_type,file_hash,collector,current_owner,verified,notes) VALUES($1,$2,$3,$4,$5,$6,$7,$7,false,$8) RETURNING id`,
		cid, tid, eid, body.Title, body.EvidenceType, body.FileHash, body.Collector, body.Notes).Scan(&id)
	c.JSON(http.StatusOK, gin.H{"id": id, "evidence_id": eid, "ok": true})
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
	var notes []Note
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var n Note
			if rows.Scan(&n.ID, &n.Content, &n.Author, &n.NoteType, &n.CreatedAt) == nil {
				notes = append(notes, n)
			}
		}
	}
	if notes == nil { notes = []Note{} }
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
		c.JSON(http.StatusBadRequest, gin.H{"error": "content required"}); return
	}
	if body.NoteType == "" { body.NoteType = "markdown" }
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
	var events []TLEvent
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var e TLEvent
			if rows.Scan(&e.ID, &e.Event, &e.Actor, &e.EventType, &e.CreatedAt) == nil {
				events = append(events, e)
			}
		}
	}
	if events == nil { events = []TLEvent{} }
	c.JSON(http.StatusOK, events)
}

// GetCaseComments — GET /api/cases/:id/comments
func GetCaseComments(c *gin.Context) {
	createCasesTables()
	tid := tenantIDFromContext(c)
	cid, _ := strconv.Atoi(c.Param("id"))
	rows, _ := database.DB.Query(`SELECT id,content,author,is_internal,created_at FROM case_comments WHERE case_id=$1 AND tenant_id=$2 ORDER BY created_at`, cid, tid)
	type Comment struct {
		ID         int    `json:"id"`
		Content    string `json:"content"`
		Author     string `json:"author"`
		IsInternal bool   `json:"is_internal"`
		CreatedAt  string `json:"created_at"`
	}
	var comments []Comment
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var cm Comment
			if rows.Scan(&cm.ID, &cm.Content, &cm.Author, &cm.IsInternal, &cm.CreatedAt) == nil {
				comments = append(comments, cm)
			}
		}
	}
	if comments == nil { comments = []Comment{} }
	c.JSON(http.StatusOK, comments)
}

// PostCaseComment — POST /api/cases/:id/comments
func PostCaseComment(c *gin.Context) {
	createCasesTables()
	tid := tenantIDFromContext(c)
	cid, _ := strconv.Atoi(c.Param("id"))
	var body struct {
		Content    string `json:"content"`
		Author     string `json:"author"`
		IsInternal bool   `json:"is_internal"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Content == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "content required"}); return
	}
	var id int
	database.DB.QueryRow(`INSERT INTO case_comments(case_id,tenant_id,content,author,is_internal) VALUES($1,$2,$3,$4,$5) RETURNING id`,
		cid, tid, body.Content, body.Author, body.IsInternal).Scan(&id)
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
	if err != nil { c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()}); return }
	if idx := strings.Index(raw, "```json"); idx != -1 { raw = raw[idx+7:] } else if idx := strings.Index(raw, "```"); idx != -1 { raw = raw[idx+3:] }
	if idx := strings.LastIndex(raw, "```"); idx != -1 { raw = raw[:idx] }
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
	if err != nil { c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()}); return }
	if idx := strings.Index(raw, "```json"); idx != -1 { raw = raw[idx+7:] } else if idx := strings.Index(raw, "```"); idx != -1 { raw = raw[idx+3:] }
	if idx := strings.LastIndex(raw, "```"); idx != -1 { raw = raw[:idx] }
	c.Data(http.StatusOK, "application/json", []byte(strings.TrimSpace(raw)))
}
