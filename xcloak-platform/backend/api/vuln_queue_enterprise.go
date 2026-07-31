package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"xcloak-platform/database"
	"xcloak-platform/services"
)

func createVQTables() {
	database.DB.Exec(`CREATE TABLE IF NOT EXISTS vq_items (
		id SERIAL PRIMARY KEY,
		tenant_id INTEGER NOT NULL,
		queue_id TEXT NOT NULL,
		cve_id TEXT NOT NULL,
		asset_name TEXT NOT NULL,
		asset_ip TEXT,
		asset_owner TEXT,
		business_unit TEXT,
		priority TEXT DEFAULT 'medium',
		risk_score REAL DEFAULT 0,
		status TEXT DEFAULT 'unassigned',
		assigned_team TEXT,
		assigned_to TEXT,
		due_date TIMESTAMPTZ,
		sla_hours INTEGER DEFAULT 168,
		remediation_action TEXT,
		notes TEXT,
		blocker_type TEXT,
		blocker_notes TEXT,
		verified_at TIMESTAMPTZ,
		closed_at TIMESTAMPTZ,
		created_at TIMESTAMPTZ DEFAULT NOW(),
		updated_at TIMESTAMPTZ DEFAULT NOW()
	)`)
	database.DB.Exec(`CREATE TABLE IF NOT EXISTS vq_exceptions (
		id SERIAL PRIMARY KEY,
		tenant_id INTEGER NOT NULL,
		vq_item_id INTEGER,
		cve_id TEXT,
		exception_type TEXT NOT NULL,
		reason TEXT NOT NULL,
		compensating_control TEXT,
		approver TEXT,
		expiration_date TIMESTAMPTZ,
		review_schedule TEXT,
		status TEXT DEFAULT 'pending',
		created_by TEXT,
		created_at TIMESTAMPTZ DEFAULT NOW()
	)`)
	database.DB.Exec(`CREATE TABLE IF NOT EXISTS vq_dependencies (
		id SERIAL PRIMARY KEY,
		tenant_id INTEGER NOT NULL,
		vq_item_id INTEGER NOT NULL,
		blocker_type TEXT NOT NULL,
		notes TEXT,
		status TEXT DEFAULT 'open',
		created_at TIMESTAMPTZ DEFAULT NOW()
	)`)
}

// GET /api/vq/dashboard
func GetVQDashboard(c *gin.Context) {
	createVQTables()
	tid := tenantIDFromContext(c)
	row := database.DB.QueryRow(`SELECT
		COUNT(*) FILTER (WHERE status != 'closed'),
		COUNT(*) FILTER (WHERE status = 'unassigned'),
		COUNT(*) FILTER (WHERE status = 'assigned'),
		COUNT(*) FILTER (WHERE status = 'in_progress'),
		COUNT(*) FILTER (WHERE status = 'awaiting_verification'),
		COUNT(*) FILTER (WHERE status = 'verified'),
		COUNT(*) FILTER (WHERE status = 'closed'),
		COUNT(*) FILTER (WHERE due_date < NOW() AND status NOT IN ('closed','verified'))
		FROM vq_items WHERE tenant_id=$1`, tid)
	var total, unassigned, assigned, inProgress, awaitingVerify, verified, closed, overdue int
	_ = row.Scan(&total, &unassigned, &assigned, &inProgress, &awaitingVerify, &verified, &closed, &overdue)
	slaCompliance := 100.0
	if total > 0 {
		slaCompliance = float64(total-overdue) / float64(total) * 100
	}
	var mttr float64
	database.DB.QueryRow(`SELECT COALESCE(AVG(EXTRACT(EPOCH FROM (closed_at-created_at))/86400),0) FROM vq_items WHERE tenant_id=$1 AND status='closed' AND closed_at IS NOT NULL`, tid).Scan(&mttr)

	type teamRow struct {
		Team    string `json:"team"`
		Total   int    `json:"total"`
		Overdue int    `json:"overdue"`
	}
	teamBreakdown := []teamRow{}
	tRows, _ := database.DB.Query(`
		SELECT COALESCE(NULLIF(assigned_team,''),'Unassigned'), COUNT(*),
			COUNT(*) FILTER (WHERE due_date < NOW() AND status NOT IN ('closed','verified'))
		FROM vq_items WHERE tenant_id=$1 AND status != 'closed' GROUP BY 1 ORDER BY COUNT(*) DESC`, tid)
	if tRows != nil {
		defer tRows.Close()
		for tRows.Next() {
			var r teamRow
			if tRows.Scan(&r.Team, &r.Total, &r.Overdue) == nil {
				teamBreakdown = append(teamBreakdown, r)
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"total":                 total,
		"unassigned":            unassigned,
		"assigned":              assigned,
		"in_progress":           inProgress,
		"awaiting_verification": awaitingVerify,
		"verified":              verified,
		"closed":                closed,
		"overdue":               overdue,
		"sla_compliance":        slaCompliance,
		"mttr_days":             mttr,
		"team_breakdown":        teamBreakdown,
	})
}

// GET /api/vq/queue
func GetVQQueue(c *gin.Context) {
	createVQTables()
	tid := tenantIDFromContext(c)
	limit := parseLimit(c, 100)
	status := c.Query("status")
	team := c.Query("assigned_team")
	priority := c.Query("priority")
	search := c.Query("search")

	where := []string{"tenant_id=$1"}
	args := []interface{}{tid}
	idx := 2
	if status != "" && status != "all" {
		where = append(where, fmt.Sprintf("status=$%d", idx))
		args = append(args, status)
		idx++
	}
	if team != "" {
		where = append(where, fmt.Sprintf("assigned_team=$%d", idx))
		args = append(args, team)
		idx++
	}
	if priority != "" {
		where = append(where, fmt.Sprintf("priority=$%d", idx))
		args = append(args, priority)
		idx++
	}
	if search != "" {
		where = append(where, fmt.Sprintf("(cve_id ILIKE $%d OR asset_name ILIKE $%d OR asset_owner ILIKE $%d)", idx, idx, idx))
		args = append(args, "%"+search+"%")
		idx++
	}
	q := fmt.Sprintf("SELECT id,queue_id,cve_id,asset_name,asset_ip,asset_owner,business_unit,priority,risk_score,status,assigned_team,assigned_to,due_date,sla_hours,remediation_action,blocker_type,notes,created_at,updated_at FROM vq_items WHERE %s ORDER BY risk_score DESC LIMIT $%d", strings.Join(where, " AND "), idx)
	args = append(args, limit)
	rows, err := database.DB.Query(q, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()
	type Item struct {
		ID                int        `json:"id"`
		QueueID           string     `json:"queue_id"`
		CVEID             string     `json:"cve_id"`
		AssetName         string     `json:"asset_name"`
		AssetIP           *string    `json:"asset_ip"`
		AssetOwner        *string    `json:"asset_owner"`
		BusinessUnit      *string    `json:"business_unit"`
		Priority          string     `json:"priority"`
		RiskScore         float64    `json:"risk_score"`
		Status            string     `json:"status"`
		AssignedTeam      *string    `json:"assigned_team"`
		AssignedTo        *string    `json:"assigned_to"`
		DueDate           *time.Time `json:"due_date"`
		SLAHours          int        `json:"sla_hours"`
		RemediationAction *string    `json:"remediation_action"`
		BlockerType       *string    `json:"blocker_type"`
		Notes             *string    `json:"notes"`
		CreatedAt         time.Time  `json:"created_at"`
		UpdatedAt         time.Time  `json:"updated_at"`
	}
	items := []Item{}
	for rows.Next() {
		var it Item
		if err := rows.Scan(&it.ID, &it.QueueID, &it.CVEID, &it.AssetName, &it.AssetIP, &it.AssetOwner, &it.BusinessUnit, &it.Priority, &it.RiskScore, &it.Status, &it.AssignedTeam, &it.AssignedTo, &it.DueDate, &it.SLAHours, &it.RemediationAction, &it.BlockerType, &it.Notes, &it.CreatedAt, &it.UpdatedAt); err == nil {
			items = append(items, it)
		}
	}
	if items == nil {
		items = []Item{}
	}
	c.JSON(http.StatusOK, items)
}

// GET /api/vq/items/:id
func GetVQItem(c *gin.Context) {
	createVQTables()
	tid := tenantIDFromContext(c)
	id := c.Param("id")
	row := database.DB.QueryRow(`SELECT id,queue_id,cve_id,asset_name,asset_ip,asset_owner,business_unit,priority,risk_score,status,assigned_team,assigned_to,due_date,sla_hours,remediation_action,blocker_type,blocker_notes,notes,verified_at,closed_at,created_at,updated_at FROM vq_items WHERE id=$1 AND tenant_id=$2`, id, tid)
	var it struct {
		ID                int        `json:"id"`
		QueueID           string     `json:"queue_id"`
		CVEID             string     `json:"cve_id"`
		AssetName         string     `json:"asset_name"`
		AssetIP           *string    `json:"asset_ip"`
		AssetOwner        *string    `json:"asset_owner"`
		BusinessUnit      *string    `json:"business_unit"`
		Priority          string     `json:"priority"`
		RiskScore         float64    `json:"risk_score"`
		Status            string     `json:"status"`
		AssignedTeam      *string    `json:"assigned_team"`
		AssignedTo        *string    `json:"assigned_to"`
		DueDate           *time.Time `json:"due_date"`
		SLAHours          int        `json:"sla_hours"`
		RemediationAction *string    `json:"remediation_action"`
		BlockerType       *string    `json:"blocker_type"`
		BlockerNotes      *string    `json:"blocker_notes"`
		Notes             *string    `json:"notes"`
		VerifiedAt        *time.Time `json:"verified_at"`
		ClosedAt          *time.Time `json:"closed_at"`
		CreatedAt         time.Time  `json:"created_at"`
		UpdatedAt         time.Time  `json:"updated_at"`
	}
	if err := row.Scan(&it.ID, &it.QueueID, &it.CVEID, &it.AssetName, &it.AssetIP, &it.AssetOwner, &it.BusinessUnit, &it.Priority, &it.RiskScore, &it.Status, &it.AssignedTeam, &it.AssignedTo, &it.DueDate, &it.SLAHours, &it.RemediationAction, &it.BlockerType, &it.BlockerNotes, &it.Notes, &it.VerifiedAt, &it.ClosedAt, &it.CreatedAt, &it.UpdatedAt); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	c.JSON(http.StatusOK, it)
}

// POST /api/vq/items/:id/assign
func PostVQAssign(c *gin.Context) {
	createVQTables()
	tid := tenantIDFromContext(c)
	id := c.Param("id")
	var body struct {
		AssignedTeam string `json:"assigned_team"`
		AssignedTo   string `json:"assigned_to"`
		Notes        string `json:"notes"`
	}
	_ = c.ShouldBindJSON(&body)
	_, err := database.DB.Exec(`UPDATE vq_items SET assigned_team=$1, assigned_to=$2, status='assigned', notes=COALESCE(NULLIF($3,''), notes), updated_at=NOW() WHERE id=$4 AND tenant_id=$5`, body.AssignedTeam, body.AssignedTo, body.Notes, id, tid)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// POST /api/vq/items/:id/action
func PostVQAction(c *gin.Context) {
	createVQTables()
	tid := tenantIDFromContext(c)
	id := c.Param("id")
	var body struct {
		Action  string `json:"action"`
		Notes   string `json:"notes"`
		Blocker string `json:"blocker"`
	}
	_ = c.ShouldBindJSON(&body)
	status := "in_progress"
	switch body.Action {
	case "complete":
		status = "awaiting_verification"
	case "block":
		status = "blocked"
	case "close":
		database.DB.Exec(`UPDATE vq_items SET status='closed', closed_at=NOW(), remediation_action=$1, updated_at=NOW() WHERE id=$2 AND tenant_id=$3`, body.Action, id, tid)
		c.JSON(http.StatusOK, gin.H{"ok": true})
		return
	}
	_, err := database.DB.Exec(`UPDATE vq_items SET status=$1, remediation_action=COALESCE(NULLIF($2,''), remediation_action), blocker_type=COALESCE(NULLIF($3,''), blocker_type), notes=COALESCE(NULLIF($4,''), notes), updated_at=NOW() WHERE id=$5 AND tenant_id=$6`, status, body.Action, body.Blocker, body.Notes, id, tid)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "status": status})
}

// POST /api/vq/items/:id/verify
func PostVQVerify(c *gin.Context) {
	createVQTables()
	tid := tenantIDFromContext(c)
	id := c.Param("id")
	var body struct {
		Pass  bool   `json:"pass"`
		Notes string `json:"notes"`
	}
	_ = c.ShouldBindJSON(&body)
	if body.Pass {
		database.DB.Exec(`UPDATE vq_items SET status='verified', verified_at=NOW(), notes=COALESCE(NULLIF($1,''), notes), updated_at=NOW() WHERE id=$2 AND tenant_id=$3`, body.Notes, id, tid)
	} else {
		database.DB.Exec(`UPDATE vq_items SET status='in_progress', notes=COALESCE(NULLIF($1,''), notes), updated_at=NOW() WHERE id=$2 AND tenant_id=$3`, body.Notes, id, tid)
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "pass": body.Pass})
}

// POST /api/vq/bulk
func PostVQBulk(c *gin.Context) {
	createVQTables()
	tid := tenantIDFromContext(c)
	var body struct {
		IDs          []int  `json:"ids"`
		Action       string `json:"action"`
		AssignedTeam string `json:"assigned_team"`
		Priority     string `json:"priority"`
		Notes        string `json:"notes"`
	}
	_ = c.ShouldBindJSON(&body)
	if len(body.IDs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no ids"})
		return
	}
	for _, id := range body.IDs {
		switch body.Action {
		case "assign":
			database.DB.Exec(`UPDATE vq_items SET assigned_team=$1, status='assigned', updated_at=NOW() WHERE id=$2 AND tenant_id=$3`, body.AssignedTeam, id, tid)
		case "set_priority":
			database.DB.Exec(`UPDATE vq_items SET priority=$1, updated_at=NOW() WHERE id=$2 AND tenant_id=$3`, body.Priority, id, tid)
		case "close":
			database.DB.Exec(`UPDATE vq_items SET status='closed', closed_at=NOW(), updated_at=NOW() WHERE id=$1 AND tenant_id=$2`, id, tid)
		case "trigger_patch":
			database.DB.Exec(`UPDATE vq_items SET remediation_action='apply_patch', status='in_progress', updated_at=NOW() WHERE id=$1 AND tenant_id=$2`, id, tid)
		}
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "affected": len(body.IDs)})
}

// GET /api/vq/exceptions
func GetVQExceptions(c *gin.Context) {
	createVQTables()
	tid := tenantIDFromContext(c)
	rows, err := database.DB.Query(`SELECT id,vq_item_id,cve_id,exception_type,reason,compensating_control,approver,expiration_date,review_schedule,status,created_by,created_at FROM vq_exceptions WHERE tenant_id=$1 ORDER BY created_at DESC`, tid)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()
	type Ex struct {
		ID                  int        `json:"id"`
		VQItemID            *int       `json:"vq_item_id"`
		CVEID               *string    `json:"cve_id"`
		ExceptionType       string     `json:"exception_type"`
		Reason              string     `json:"reason"`
		CompensatingControl *string    `json:"compensating_control"`
		Approver            *string    `json:"approver"`
		ExpirationDate      *time.Time `json:"expiration_date"`
		ReviewSchedule      *string    `json:"review_schedule"`
		Status              string     `json:"status"`
		CreatedBy           *string    `json:"created_by"`
		CreatedAt           time.Time  `json:"created_at"`
	}
	exs := []Ex{}
	for rows.Next() {
		var e Ex
		if err := rows.Scan(&e.ID, &e.VQItemID, &e.CVEID, &e.ExceptionType, &e.Reason, &e.CompensatingControl, &e.Approver, &e.ExpirationDate, &e.ReviewSchedule, &e.Status, &e.CreatedBy, &e.CreatedAt); err == nil {
			exs = append(exs, e)
		}
	}
	if exs == nil {
		exs = []Ex{}
	}
	c.JSON(http.StatusOK, exs)
}

// POST /api/vq/exceptions
func PostVQException(c *gin.Context) {
	createVQTables()
	tid := tenantIDFromContext(c)
	user := usernameFromContext(c)
	var body struct {
		VQItemID            int    `json:"vq_item_id"`
		CVEID               string `json:"cve_id"`
		ExceptionType       string `json:"exception_type"`
		Reason              string `json:"reason"`
		CompensatingControl string `json:"compensating_control"`
		ReviewSchedule      string `json:"review_schedule"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var id int
	_ = database.DB.QueryRow(`INSERT INTO vq_exceptions (tenant_id,vq_item_id,cve_id,exception_type,reason,compensating_control,review_schedule,status,created_by) VALUES ($1,$2,$3,$4,$5,$6,$7,'pending',$8) RETURNING id`, tid, body.VQItemID, body.CVEID, body.ExceptionType, body.Reason, body.CompensatingControl, body.ReviewSchedule, user).Scan(&id)
	c.JSON(http.StatusOK, gin.H{"id": id, "ok": true})
}

// PATCH /api/vq/exceptions/:eid
func PatchVQException(c *gin.Context) {
	createVQTables()
	tid := tenantIDFromContext(c)
	eid := c.Param("eid")
	user := usernameFromContext(c)
	var body struct {
		Status string `json:"status"`
	}
	_ = c.ShouldBindJSON(&body)
	database.DB.Exec(`UPDATE vq_exceptions SET status=$1, approver=$2 WHERE id=$3 AND tenant_id=$4`, body.Status, user, eid, tid)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// DELETE /api/vq/exceptions/:eid
func DeleteVQException(c *gin.Context) {
	createVQTables()
	tid := tenantIDFromContext(c)
	eid := c.Param("eid")
	database.DB.Exec(`DELETE FROM vq_exceptions WHERE id=$1 AND tenant_id=$2`, eid, tid)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// GET /api/vq/items/:id/dependencies
func GetVQDependencies(c *gin.Context) {
	createVQTables()
	tid := tenantIDFromContext(c)
	id := c.Param("id")
	rows, err := database.DB.Query(`SELECT id,blocker_type,notes,status,created_at FROM vq_dependencies WHERE vq_item_id=$1 AND tenant_id=$2 ORDER BY created_at DESC`, id, tid)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()
	type Dep struct {
		ID          int       `json:"id"`
		BlockerType string    `json:"blocker_type"`
		Notes       *string   `json:"notes"`
		Status      string    `json:"status"`
		CreatedAt   time.Time `json:"created_at"`
	}
	deps := []Dep{}
	for rows.Next() {
		var d Dep
		if err := rows.Scan(&d.ID, &d.BlockerType, &d.Notes, &d.Status, &d.CreatedAt); err == nil {
			deps = append(deps, d)
		}
	}
	if deps == nil {
		deps = []Dep{}
	}
	c.JSON(http.StatusOK, deps)
}

// POST /api/vq/items/:id/dependencies
func PostVQDependency(c *gin.Context) {
	createVQTables()
	tid := tenantIDFromContext(c)
	id := c.Param("id")
	var body struct {
		BlockerType string `json:"blocker_type"`
		Notes       string `json:"notes"`
	}
	_ = c.ShouldBindJSON(&body)
	var did int
	_ = database.DB.QueryRow(`INSERT INTO vq_dependencies (tenant_id,vq_item_id,blocker_type,notes) VALUES ($1,$2,$3,$4) RETURNING id`, tid, id, body.BlockerType, body.Notes).Scan(&did)
	database.DB.Exec(`UPDATE vq_items SET blocker_type=$1, blocker_notes=$2, status='blocked', updated_at=NOW() WHERE id=$3 AND tenant_id=$4`, body.BlockerType, body.Notes, id, tid)
	c.JSON(http.StatusOK, gin.H{"id": did, "ok": true})
}

// POST /api/vq/ai
func PostVQAI(c *gin.Context) {
	var body struct {
		CVEID             string  `json:"cve_id"`
		AssetName         string  `json:"asset_name"`
		Priority          string  `json:"priority"`
		RiskScore         float64 `json:"risk_score"`
		AssignedTeam      string  `json:"assigned_team"`
		RemediationAction string  `json:"remediation_action"`
	}
	_ = c.ShouldBindJSON(&body)
	prompt := fmt.Sprintf(`You are a remediation advisor. Provide concise remediation steps for CVE: %s on asset: %s (priority: %s, risk: %.1f, team: %s). Respond with JSON: {"recommendation": string, "steps": [string], "estimated_effort": string, "risks_if_delayed": string, "alternative_mitigations": [string]}`, body.CVEID, body.AssetName, body.Priority, body.RiskScore, body.AssignedTeam)
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
		var parsed map[string]interface{}
		if json.Unmarshal([]byte(strings.TrimSpace(clean)), &parsed) == nil {
			parsed["cve_id"] = body.CVEID
			parsed["asset_name"] = body.AssetName
			c.JSON(http.StatusOK, parsed)
			return
		}
	}
	// Deterministic fallback — same shape the LLM is asked for, not a
	// separate set of fields the real response never fed into.
	c.JSON(http.StatusOK, gin.H{
		"recommendation": vqDeterministicAI(body.CVEID, body.Priority, body.AssignedTeam),
		"cve_id":         body.CVEID,
		"asset_name":     body.AssetName,
		"steps": []interface{}{
			"Download patch from vendor advisory page",
			"Schedule maintenance window with " + body.AssignedTeam,
			"Take a pre-patch snapshot or backup",
			"Apply the patch during the maintenance window",
			"Restart the affected service if required",
			"Run a verification scan to confirm resolution",
			"Update queue item to Awaiting Verification",
		},
		"estimated_effort":        "2–4 hours including maintenance window",
		"risks_if_delayed":        vqRiskIfDelayed(body.Priority),
		"alternative_mitigations": []interface{}{"Apply WAF rules to block known exploit patterns", "Restrict network access to the affected service", "Increase monitoring on the asset until patched"},
	})
}

func vqDeterministicAI(cve, priority, team string) string {
	urgency := "within 30 days"
	switch priority {
	case "critical":
		urgency = "immediately (within 24 hours)"
	case "high":
		urgency = "within 7 days"
	}
	return fmt.Sprintf("Remediate %s %s. Coordinate with %s to schedule patching during an approved maintenance window.", cve, urgency, team)
}

func vqRiskIfDelayed(priority string) string {
	switch priority {
	case "critical":
		return "Active exploitation likely within 24–72 hours. Immediate compromise of the affected system is a realistic scenario."
	case "high":
		return "Exploitation attempts expected within 7 days. Threat actors actively scan for this vulnerability class."
	default:
		return "Extended exposure increases likelihood of opportunistic exploitation. SLA breach may occur if not addressed within the defined window."
	}
}

// GET /api/vq/analytics
func GetVQAnalytics(c *gin.Context) {
	createVQTables()
	tid := tenantIDFromContext(c)
	row := database.DB.QueryRow(`SELECT COUNT(*), AVG(EXTRACT(EPOCH FROM (closed_at - created_at))/86400) FROM vq_items WHERE tenant_id=$1 AND status='closed' AND closed_at IS NOT NULL`, tid)
	var closedCount int
	var avgDays *float64
	_ = row.Scan(&closedCount, &avgDays)
	mttr := 0.0
	if avgDays != nil {
		mttr = *avgDays
	}

	var total, overdueCount int
	database.DB.QueryRow(`SELECT COUNT(*) FROM vq_items WHERE tenant_id=$1`, tid).Scan(&total)
	database.DB.QueryRow(`SELECT COUNT(*) FROM vq_items WHERE tenant_id=$1 AND due_date < NOW() AND status NOT IN ('closed','verified')`, tid).Scan(&overdueCount)
	slaCompliance := 100.0
	if total > 0 {
		slaCompliance = float64(total-overdueCount) / float64(total) * 100
	}

	type teamPerfRow struct {
		Team     string  `json:"team"`
		Assigned int     `json:"assigned"`
		Closed   int     `json:"closed"`
		Overdue  int     `json:"overdue"`
		AvgDays  float64 `json:"avg_days"`
	}
	teamPerf := []teamPerfRow{}
	tRows, _ := database.DB.Query(`
		SELECT COALESCE(NULLIF(assigned_team,''),'Unassigned'),
			COUNT(*),
			COUNT(*) FILTER (WHERE status='closed'),
			COUNT(*) FILTER (WHERE due_date < NOW() AND status NOT IN ('closed','verified')),
			COALESCE(AVG(EXTRACT(EPOCH FROM (closed_at-created_at))/86400) FILTER (WHERE status='closed' AND closed_at IS NOT NULL),0)
		FROM vq_items WHERE tenant_id=$1 AND status != 'unassigned' GROUP BY 1 ORDER BY COUNT(*) DESC`, tid)
	if tRows != nil {
		defer tRows.Close()
		for tRows.Next() {
			var r teamPerfRow
			if tRows.Scan(&r.Team, &r.Assigned, &r.Closed, &r.Overdue, &r.AvgDays) == nil {
				teamPerf = append(teamPerf, r)
			}
		}
	}

	type trendRow struct {
		Week   string `json:"week"`
		Opened int    `json:"opened"`
		Closed int    `json:"closed"`
	}
	trend := []trendRow{}
	for i := 3; i >= 0; i-- {
		weekStart := time.Now().AddDate(0, 0, -7*(i+1))
		weekEnd := time.Now().AddDate(0, 0, -7*i)
		_, isoWeek := weekEnd.ISOWeek()
		var opened, closedInWeek int
		database.DB.QueryRow(`SELECT COUNT(*) FROM vq_items WHERE tenant_id=$1 AND created_at>=$2 AND created_at<$3`, tid, weekStart, weekEnd).Scan(&opened)
		database.DB.QueryRow(`SELECT COUNT(*) FROM vq_items WHERE tenant_id=$1 AND closed_at>=$2 AND closed_at<$3`, tid, weekStart, weekEnd).Scan(&closedInWeek)
		trend = append(trend, trendRow{Week: fmt.Sprintf("W%d", isoWeek), Opened: opened, Closed: closedInWeek})
	}

	type delayedRow struct {
		Asset        string `json:"asset"`
		OverdueDays  int    `json:"overdue_days"`
		AssignedTeam string `json:"assigned_team"`
	}
	topDelayed := []delayedRow{}
	dRows, _ := database.DB.Query(`
		SELECT asset_name, EXTRACT(EPOCH FROM (NOW()-due_date))/86400, COALESCE(NULLIF(assigned_team,''),'Unassigned')
		FROM vq_items WHERE tenant_id=$1 AND due_date < NOW() AND status NOT IN ('closed','verified')
		ORDER BY due_date ASC LIMIT 5`, tid)
	if dRows != nil {
		defer dRows.Close()
		for dRows.Next() {
			var r delayedRow
			var days float64
			if dRows.Scan(&r.Asset, &days, &r.AssignedTeam) == nil {
				r.OverdueDays = int(days)
				topDelayed = append(topDelayed, r)
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"mttr_days":          mttr,
		"sla_compliance":     slaCompliance,
		"overdue_count":      overdueCount,
		"closed_count":       closedCount,
		"team_performance":   teamPerf,
		"remediation_trend":  trend,
		"top_delayed_assets": topDelayed,
	})
}

// GET /api/vq/sla
func GetVQSLA(c *gin.Context) {
	createVQTables()
	tid := tenantIDFromContext(c)
	currentCompliance := gin.H{}
	for _, p := range []string{"critical", "high", "medium", "low"} {
		var total, onTime int
		database.DB.QueryRow(`SELECT COUNT(*) FROM vq_items WHERE tenant_id=$1 AND priority=$2`, tid, p).Scan(&total)
		database.DB.QueryRow(`SELECT COUNT(*) FROM vq_items WHERE tenant_id=$1 AND priority=$2 AND (status IN ('closed','verified') OR due_date >= NOW())`, tid, p).Scan(&onTime)
		compliance := 100.0
		if total > 0 {
			compliance = float64(onTime) / float64(total) * 100
		}
		currentCompliance[p] = compliance
	}
	c.JSON(http.StatusOK, gin.H{
		"policies": []interface{}{
			map[string]interface{}{"priority": "critical", "time_to_assign_h": 2, "time_to_start_h": 4, "time_to_patch_h": 24, "time_to_verify_h": 48, "time_to_close_h": 72},
			map[string]interface{}{"priority": "high", "time_to_assign_h": 8, "time_to_start_h": 24, "time_to_patch_h": 168, "time_to_verify_h": 192, "time_to_close_h": 240},
			map[string]interface{}{"priority": "medium", "time_to_assign_h": 24, "time_to_start_h": 72, "time_to_patch_h": 720, "time_to_verify_h": 744, "time_to_close_h": 792},
			map[string]interface{}{"priority": "low", "time_to_assign_h": 72, "time_to_start_h": 168, "time_to_patch_h": 2160, "time_to_verify_h": 2184, "time_to_close_h": 2208},
		},
		"current_compliance": currentCompliance,
	})
}

// POST /api/vq/report
func PostVQReport(c *gin.Context) {
	createVQTables()
	tid := tenantIDFromContext(c)
	var body struct {
		ReportType string `json:"report_type"`
	}
	_ = c.ShouldBindJSON(&body)
	title := "Remediation Status Report"
	switch body.ReportType {
	case "sla":
		title = "SLA Compliance Report"
	case "overdue":
		title = "Overdue Findings Report"
	case "team":
		title = "Team Performance Report"
	case "executive":
		title = "Executive Remediation Summary"
	}

	var totalActive, overdue, closedThisPeriod int
	var slaCompliance, mttr float64
	database.DB.QueryRow(`SELECT COUNT(*) FROM vq_items WHERE tenant_id=$1 AND status != 'closed'`, tid).Scan(&totalActive)
	database.DB.QueryRow(`SELECT COUNT(*) FROM vq_items WHERE tenant_id=$1 AND due_date < NOW() AND status NOT IN ('closed','verified')`, tid).Scan(&overdue)
	database.DB.QueryRow(`SELECT COUNT(*) FROM vq_items WHERE tenant_id=$1 AND status='closed' AND closed_at > NOW()-INTERVAL '30 days'`, tid).Scan(&closedThisPeriod)
	database.DB.QueryRow(`SELECT COALESCE(AVG(EXTRACT(EPOCH FROM (closed_at-created_at))/86400),0) FROM vq_items WHERE tenant_id=$1 AND status='closed' AND closed_at IS NOT NULL`, tid).Scan(&mttr)
	if total := totalActive + closedThisPeriod; total > 0 {
		slaCompliance = float64(total-overdue) / float64(total) * 100
	} else {
		slaCompliance = 100
	}

	type overdueRow struct {
		QueueID     string `json:"queue_id"`
		CVE         string `json:"cve"`
		Asset       string `json:"asset"`
		Team        string `json:"team"`
		DaysOverdue int    `json:"days_overdue"`
	}
	overdueItems := []overdueRow{}
	oRows, _ := database.DB.Query(`
		SELECT queue_id, cve_id, asset_name, COALESCE(NULLIF(assigned_team,''),'Unassigned'), EXTRACT(EPOCH FROM (NOW()-due_date))/86400
		FROM vq_items WHERE tenant_id=$1 AND due_date < NOW() AND status NOT IN ('closed','verified') ORDER BY due_date ASC LIMIT 10`, tid)
	if oRows != nil {
		defer oRows.Close()
		for oRows.Next() {
			var r overdueRow
			var days float64
			if oRows.Scan(&r.QueueID, &r.CVE, &r.Asset, &r.Team, &days) == nil {
				r.DaysOverdue = int(days)
				overdueItems = append(overdueItems, r)
			}
		}
	}

	prompt := fmt.Sprintf(`You are a vulnerability remediation reporting assistant. Write a %s based on these REAL metrics: %d active remediation tasks, %d overdue, %d closed in the last 30 days, %.1f%% SLA compliance, %.1f-day average time to remediate. Overdue items: %v. Respond as a JSON object with fields: executive_summary (2-3 sentences grounded only in these numbers, no invented history or comparisons), recommendations (a JSON array of up to 4 short actionable strings based only on the real data given — if there isn't enough data, say so instead of inventing findings).`,
		title, totalActive, overdue, closedThisPeriod, slaCompliance, mttr, overdueItems)
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
		if totalActive == 0 {
			summary = "No active remediation tasks have been recorded for this tenant."
		} else {
			summary = fmt.Sprintf("%d active remediation tasks, %d overdue. SLA compliance is %.1f%% with a mean time to remediate of %.1f days.", totalActive, overdue, slaCompliance, mttr)
		}
		recommendations = []string{}
	}

	c.JSON(http.StatusOK, gin.H{
		"title":             title + " — " + time.Now().Format("January 2006"),
		"generated_at":      time.Now().Format(time.RFC3339),
		"classification":    "CONFIDENTIAL — INTERNAL",
		"executive_summary": summary,
		"key_metrics": gin.H{
			"total_active":       totalActive,
			"overdue":            overdue,
			"closed_this_period": closedThisPeriod,
			"sla_compliance":     fmt.Sprintf("%.1f%%", slaCompliance),
			"mttr_days":          mttr,
		},
		"overdue_items":   overdueItems,
		"recommendations": recommendations,
	})
}
