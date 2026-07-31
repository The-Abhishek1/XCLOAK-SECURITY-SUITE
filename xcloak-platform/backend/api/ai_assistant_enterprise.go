package api

import (
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"xcloak-platform/database"
	"xcloak-platform/services"
)

// ── helpers ───────────────────────────────────────────────────────────────────

func aiaID(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano()+int64(rand.Intn(9999)))
}

func aiaNullStr(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

func aiaAudit(tid int, action, objType, objID, actor, details string) {
	db := database.DB
	if db == nil {
		return
	}
	db.Exec(`INSERT INTO aia_audit (tenant_id,action,object_type,object_id,actor,details)
		VALUES ($1,$2,$3,$4,$5,$6)`,
		tid, action, objType, aiaNullStr(objID), actor, details)
}

// ── table init ────────────────────────────────────────────────────────────────

func InitAIATables() {
	db := database.DB
	if db == nil {
		return
	}
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS aia_sessions (
			id SERIAL PRIMARY KEY,
			tenant_id TEXT NOT NULL,
			session_id TEXT NOT NULL UNIQUE,
			title TEXT NOT NULL,
			mode TEXT NOT NULL DEFAULT 'chat',
			model TEXT DEFAULT 'claude-sonnet-4-6',
			context TEXT DEFAULT '{}',
			message_count INTEGER DEFAULT 0,
			bookmarked BOOLEAN DEFAULT FALSE,
			status TEXT NOT NULL DEFAULT 'active',
			created_by TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT NOW(),
			updated_at TIMESTAMP DEFAULT NOW())`,

		`CREATE TABLE IF NOT EXISTS aia_messages (
			id SERIAL PRIMARY KEY,
			tenant_id TEXT NOT NULL,
			session_id TEXT NOT NULL,
			role TEXT NOT NULL,
			content TEXT NOT NULL,
			model TEXT,
			tokens_used INTEGER DEFAULT 0,
			latency_ms INTEGER DEFAULT 0,
			actions_taken TEXT DEFAULT '[]',
			created_at TIMESTAMP DEFAULT NOW())`,

		`CREATE TABLE IF NOT EXISTS aia_prompts (
			id SERIAL PRIMARY KEY,
			tenant_id TEXT NOT NULL,
			prompt_id TEXT NOT NULL UNIQUE,
			title TEXT NOT NULL,
			content TEXT NOT NULL,
			category TEXT NOT NULL DEFAULT 'general',
			is_template BOOLEAN DEFAULT TRUE,
			variables TEXT DEFAULT '[]',
			usage_count INTEGER DEFAULT 0,
			created_by TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT NOW())`,

		`CREATE TABLE IF NOT EXISTS aia_recommendations (
			id SERIAL PRIMARY KEY,
			tenant_id TEXT NOT NULL,
			rec_id TEXT NOT NULL UNIQUE,
			title TEXT NOT NULL,
			description TEXT NOT NULL,
			category TEXT NOT NULL DEFAULT 'detection',
			priority TEXT NOT NULL DEFAULT 'medium',
			status TEXT NOT NULL DEFAULT 'open',
			impact TEXT,
			effort TEXT,
			source_session_id TEXT,
			accepted_by TEXT,
			accepted_at TIMESTAMP,
			created_at TIMESTAMP DEFAULT NOW())`,

		`CREATE TABLE IF NOT EXISTS aia_actions (
			id SERIAL PRIMARY KEY,
			tenant_id TEXT NOT NULL,
			action_id TEXT NOT NULL UNIQUE,
			action_type TEXT NOT NULL,
			description TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'pending_approval',
			requested_by TEXT NOT NULL,
			approved_by TEXT,
			executed_at TIMESTAMP,
			result TEXT,
			session_id TEXT,
			created_at TIMESTAMP DEFAULT NOW())`,

		`CREATE TABLE IF NOT EXISTS aia_reports (
			id SERIAL PRIMARY KEY,
			tenant_id TEXT NOT NULL,
			report_id TEXT NOT NULL UNIQUE,
			title TEXT NOT NULL,
			report_type TEXT NOT NULL,
			content TEXT,
			generated_by TEXT NOT NULL,
			format TEXT DEFAULT 'markdown',
			session_id TEXT,
			created_at TIMESTAMP DEFAULT NOW())`,

		`CREATE TABLE IF NOT EXISTS aia_audit (
			id SERIAL PRIMARY KEY,
			tenant_id TEXT NOT NULL,
			action TEXT NOT NULL,
			object_type TEXT NOT NULL,
			object_id TEXT,
			actor TEXT NOT NULL,
			details TEXT,
			created_at TIMESTAMP DEFAULT NOW())`,
	}
	for _, s := range stmts {
		db.Exec(s)
	}
}

// ── Dashboard ─────────────────────────────────────────────────────────────────

func GetAIADashboard(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)
	tidStr := fmt.Sprintf("%d", tid)

	var totalSessions, activeSessions, completedSessions, totalMessages, savedPrompts int
	var openRecs, openActions int
	db.QueryRow(`SELECT COUNT(*) FROM aia_sessions WHERE tenant_id=$1`, tidStr).Scan(&totalSessions)
	db.QueryRow(`SELECT COUNT(*) FROM aia_sessions WHERE tenant_id=$1 AND status='active'`, tidStr).Scan(&activeSessions)
	db.QueryRow(`SELECT COUNT(*) FROM aia_sessions WHERE tenant_id=$1 AND status='completed'`, tidStr).Scan(&completedSessions)
	db.QueryRow(`SELECT COUNT(*) FROM aia_messages WHERE tenant_id=$1`, tidStr).Scan(&totalMessages)
	db.QueryRow(`SELECT COUNT(*) FROM aia_prompts WHERE tenant_id=$1`, tidStr).Scan(&savedPrompts)
	db.QueryRow(`SELECT COUNT(*) FROM aia_recommendations WHERE tenant_id=$1 AND status='open'`, tidStr).Scan(&openRecs)
	db.QueryRow(`SELECT COUNT(*) FROM aia_actions WHERE tenant_id=$1 AND status='pending_approval'`, tidStr).Scan(&openActions)

	// recent sessions
	recent := []map[string]interface{}{}
	rows, _ := db.Query(`SELECT session_id,title,mode,model,message_count,status,created_by,updated_at
		FROM aia_sessions WHERE tenant_id=$1 ORDER BY updated_at DESC LIMIT 8`, tidStr)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var id, title, mode, model, by, st string
			var cnt int
			var ua *string
			if err := rows.Scan(&id, &title, &mode, &model, &cnt, &st, &by, &ua); err == nil {
				recent = append(recent, map[string]interface{}{
					"session_id": id, "title": title, "mode": mode, "model": model,
					"message_count": cnt, "status": st, "created_by": by, "updated_at": ua,
				})
			}
		}
	}

	// by mode
	modes := []map[string]interface{}{}
	mr, _ := db.Query(`SELECT mode, COUNT(*) FROM aia_sessions WHERE tenant_id=$1 GROUP BY mode ORDER BY COUNT(*) DESC`, tidStr)
	if mr != nil {
		defer mr.Close()
		for mr.Next() {
			var m string
			var cnt int
			mr.Scan(&m, &cnt)
			modes = append(modes, map[string]interface{}{"mode": m, "count": cnt})
		}
	}

	// top prompts
	topPrompts := []map[string]interface{}{}
	pr, _ := db.Query(`SELECT title, category, usage_count FROM aia_prompts WHERE tenant_id=$1 ORDER BY usage_count DESC LIMIT 5`, tidStr)
	if pr != nil {
		defer pr.Close()
		for pr.Next() {
			var title, cat string
			var cnt int
			pr.Scan(&title, &cat, &cnt)
			topPrompts = append(topPrompts, map[string]interface{}{"title": title, "category": cat, "usage_count": cnt})
		}
	}

	// connected data sources — real count of enrolled endpoint agents + configured log sources for this tenant
	var connectedSources int
	db.QueryRow(`SELECT
		(SELECT COUNT(*) FROM agents WHERE tenant_id=$1) +
		(SELECT COUNT(*) FROM log_sources WHERE tenant_id=$1 AND enabled=TRUE)`, tid).Scan(&connectedSources)

	// avg assistant response latency — real, from stored message latencies
	var avgLatency float64
	db.QueryRow(`SELECT COALESCE(AVG(latency_ms),0) FROM aia_messages WHERE tenant_id=$1 AND role='assistant'`, tidStr).Scan(&avgLatency)

	// queries today — real count of user messages sent today
	var queriesToday int
	db.QueryRow(`SELECT COUNT(*) FROM aia_messages WHERE tenant_id=$1 AND role='user' AND created_at::date=CURRENT_DATE`, tidStr).Scan(&queriesToday)

	// action approval/execution stats — real, from aia_actions
	var approvedActions, rejectedActions, executedActions int
	db.QueryRow(`SELECT COUNT(*) FROM aia_actions WHERE tenant_id=$1 AND status='approved'`, tidStr).Scan(&approvedActions)
	db.QueryRow(`SELECT COUNT(*) FROM aia_actions WHERE tenant_id=$1 AND status='rejected'`, tidStr).Scan(&rejectedActions)
	db.QueryRow(`SELECT COUNT(*) FROM aia_actions WHERE tenant_id=$1 AND executed_at IS NOT NULL`, tidStr).Scan(&executedActions)
	successRate := 100
	if approvedActions+rejectedActions > 0 {
		successRate = int(100 * float64(approvedActions) / float64(approvedActions+rejectedActions))
	}

	// health score — real, based on whether the configured LLM provider is reachable/configured
	healthScore := 0
	provider := strings.ToLower(os.Getenv("LLM_PROVIDER"))
	if provider == "ollama" {
		healthScore = 100 // ollama defaults to localhost:11434, treated as configured
	} else if os.Getenv("ANTHROPIC_API_KEY") != "" {
		healthScore = 100
	}

	c.JSON(http.StatusOK, gin.H{
		"total_sessions": totalSessions, "active_sessions": activeSessions,
		"completed_sessions": completedSessions, "total_messages": totalMessages,
		"saved_prompts": savedPrompts, "open_recommendations": openRecs,
		"pending_actions":   openActions,
		"connected_sources": connectedSources,
		"health_score":      healthScore,
		"recent_sessions":   recent, "by_mode": modes, "top_prompts": topPrompts,
		// automation_rate and analyst_hours_saved were dropped rather than
		// left hardcoded at 0 — no real formula or tracked signal exists
		// anywhere in this codebase for either.
		"stats": gin.H{
			"avg_response_ms": int(avgLatency),
			"queries_today":   queriesToday, "actions_executed": executedActions, "success_rate": successRate,
		},
	})
}

// ── Sessions ──────────────────────────────────────────────────────────────────

func GetAIASessions(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)
	tidStr := fmt.Sprintf("%d", tid)
	mode := c.Query("mode")
	limit := parseLimit(c, 50)

	where := []string{"tenant_id=$1"}
	args := []interface{}{tidStr}
	i := 2
	if mode != "" {
		where = append(where, fmt.Sprintf("mode=$%d", i))
		args = append(args, mode)
		i++
	}
	args = append(args, limit)

	var sessions []map[string]interface{}
	rows, _ := db.Query(fmt.Sprintf(`SELECT session_id,title,mode,model,message_count,bookmarked,status,created_by,created_at,updated_at
		FROM aia_sessions WHERE %s ORDER BY updated_at DESC LIMIT $%d`, strings.Join(where, " AND "), i), args...)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var id, title, mode2, model, by, st string
			var cnt int
			var bm bool
			var ca, ua *string
			if err := rows.Scan(&id, &title, &mode2, &model, &cnt, &bm, &st, &by, &ca, &ua); err == nil {
				sessions = append(sessions, map[string]interface{}{
					"session_id": id, "title": title, "mode": mode2, "model": model,
					"message_count": cnt, "bookmarked": bm, "status": st,
					"created_by": by, "created_at": ca, "updated_at": ua,
				})
			}
		}
	}
	if sessions == nil {
		sessions = []map[string]interface{}{}
	}
	c.JSON(http.StatusOK, sessions)
}

func PostAIASession(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)
	tidStr := fmt.Sprintf("%d", tid)
	actor := usernameFromContext(c)

	var body struct {
		Title string `json:"title"`
		Mode  string `json:"mode"`
		Model string `json:"model"`
	}
	c.BindJSON(&body)
	if body.Title == "" {
		body.Title = "New Session"
	}
	if body.Mode == "" {
		body.Mode = "chat"
	}
	if body.Model == "" {
		body.Model = "claude-sonnet-4-6"
	}
	id := aiaID("AIA-SES")
	db.Exec(`INSERT INTO aia_sessions (tenant_id,session_id,title,mode,model,created_by)
		VALUES ($1,$2,$3,$4,$5,$6)`, tidStr, id, body.Title, body.Mode, body.Model, actor)
	aiaAudit(tid, "session_created", "session", id, actor, fmt.Sprintf("mode:%s model:%s", body.Mode, body.Model))
	c.JSON(http.StatusOK, gin.H{"session_id": id, "title": body.Title})
}

func GetAIASessionMessages(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)
	tidStr := fmt.Sprintf("%d", tid)
	sessionID := c.Param("id")

	var msgs []map[string]interface{}
	rows, _ := db.Query(`SELECT role,content,model,tokens_used,latency_ms,created_at
		FROM aia_messages WHERE tenant_id=$1 AND session_id=$2
		ORDER BY created_at ASC`, tidStr, sessionID)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var role, content string
			var model *string
			var tokens, latency int
			var ca *string
			if err := rows.Scan(&role, &content, &model, &tokens, &latency, &ca); err == nil {
				msgs = append(msgs, map[string]interface{}{
					"role": role, "content": content, "model": model,
					"tokens_used": tokens, "latency_ms": latency, "created_at": ca,
				})
			}
		}
	}
	if msgs == nil {
		msgs = []map[string]interface{}{}
	}
	c.JSON(http.StatusOK, msgs)
}

func PatchAIASession(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)
	tidStr := fmt.Sprintf("%d", tid)
	sessionID := c.Param("id")

	var body struct {
		Title      string `json:"title"`
		Bookmarked *bool  `json:"bookmarked"`
		Status     string `json:"status"`
	}
	c.BindJSON(&body)
	if body.Title != "" {
		db.Exec(`UPDATE aia_sessions SET title=$1,updated_at=NOW() WHERE tenant_id=$2 AND session_id=$3`, body.Title, tidStr, sessionID)
	}
	if body.Bookmarked != nil {
		db.Exec(`UPDATE aia_sessions SET bookmarked=$1,updated_at=NOW() WHERE tenant_id=$2 AND session_id=$3`, *body.Bookmarked, tidStr, sessionID)
	}
	if body.Status != "" {
		db.Exec(`UPDATE aia_sessions SET status=$1,updated_at=NOW() WHERE tenant_id=$2 AND session_id=$3`, body.Status, tidStr, sessionID)
	}
	c.JSON(http.StatusOK, gin.H{"status": "updated"})
}

// ── Chat (enterprise) ─────────────────────────────────────────────────────────

func PostAIAChat(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)
	tidStr := fmt.Sprintf("%d", tid)
	actor := usernameFromContext(c)

	var body struct {
		SessionID string `json:"session_id"`
		Message   string `json:"message"`
		Mode      string `json:"mode"`
		Model     string `json:"model"`
	}
	if err := c.BindJSON(&body); err != nil || body.Message == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "message required"})
		return
	}
	if body.Model == "" {
		body.Model = "claude-sonnet-4-6"
	}
	if body.Mode == "" {
		body.Mode = "chat"
	}

	// create session if needed
	sessionID := body.SessionID
	if sessionID == "" {
		sessionID = aiaID("AIA-SES")
		title := body.Message
		if len(title) > 60 {
			title = title[:57] + "…"
		}
		db.Exec(`INSERT INTO aia_sessions (tenant_id,session_id,title,mode,model,created_by)
			VALUES ($1,$2,$3,$4,$5,$6)`, tidStr, sessionID, title, body.Mode, body.Model, actor)
	}

	// store user message
	db.Exec(`INSERT INTO aia_messages (tenant_id,session_id,role,content,model)
		VALUES ($1,$2,'user',$3,$4)`, tidStr, sessionID, body.Message, body.Model)

	// build a real prompt grounded in this tenant's live security data, then call the LLM
	prompt := aiaBuildPrompt(tid, body.Message, body.Mode)
	start := time.Now()
	response, err := services.CallLLM(prompt)
	latency := int(time.Since(start).Milliseconds())
	if err != nil {
		response = fmt.Sprintf("I couldn't reach the AI model to answer that: %s", err.Error())
	}
	// rough token estimate (~4 chars/token) — CallLLM doesn't expose provider usage counts
	tokens := (len(prompt) + len(response)) / 4

	// store assistant response
	db.Exec(`INSERT INTO aia_messages (tenant_id,session_id,role,content,model,tokens_used,latency_ms)
		VALUES ($1,$2,'assistant',$3,$4,$5,$6)`, tidStr, sessionID, response, body.Model, tokens, latency)

	// update session
	db.Exec(`UPDATE aia_sessions SET message_count=message_count+2,updated_at=NOW() WHERE tenant_id=$1 AND session_id=$2`, tidStr, sessionID)

	aiaAudit(tid, "message_sent", "session", sessionID, actor, fmt.Sprintf("mode:%s tokens:%d", body.Mode, tokens))

	c.JSON(http.StatusOK, gin.H{
		"session_id": sessionID, "response": response,
		"model": body.Model, "tokens_used": tokens, "latency_ms": latency,
	})
}

// aiaGatherContext collects real per-tenant security context (open alerts,
// incidents, agent/coverage counts) shared by both live chat prompts and
// report generation, so both stay grounded in the same real data.
func aiaGatherContext(tid int) string {
	db := database.DB
	var ctx strings.Builder

	var totalAlerts, openAlerts, criticalAlerts int
	db.QueryRow(`SELECT COUNT(*) FROM alerts WHERE tenant_id=$1`, tid).Scan(&totalAlerts)
	db.QueryRow(`SELECT COUNT(*) FROM alerts WHERE tenant_id=$1 AND status NOT IN ('closed','resolved')`, tid).Scan(&openAlerts)
	db.QueryRow(`SELECT COUNT(*) FROM alerts WHERE tenant_id=$1 AND severity='critical' AND status NOT IN ('closed','resolved')`, tid).Scan(&criticalAlerts)
	fmt.Fprintf(&ctx, "Alerts: %d total, %d open (%d critical)\n", totalAlerts, openAlerts, criticalAlerts)

	var openIncidents int
	db.QueryRow(`SELECT COUNT(*) FROM incidents WHERE tenant_id=$1 AND status NOT IN ('closed','resolved')`, tid).Scan(&openIncidents)
	fmt.Fprintf(&ctx, "Open incidents: %d\n", openIncidents)

	var totalAgents int
	db.QueryRow(`SELECT COUNT(*) FROM agents WHERE tenant_id=$1`, tid).Scan(&totalAgents)
	fmt.Fprintf(&ctx, "Enrolled endpoint agents: %d\n", totalAgents)

	irows, _ := db.Query(`SELECT title, severity, status FROM incidents WHERE tenant_id=$1
		AND status NOT IN ('closed','resolved') ORDER BY severity DESC LIMIT 5`, tid)
	if irows != nil {
		ctx.WriteString("Open incident details:\n")
		for irows.Next() {
			var title, sev, status string
			irows.Scan(&title, &sev, &status)
			fmt.Fprintf(&ctx, "- [%s] %s (%s)\n", sev, title, status)
		}
		irows.Close()
	}

	arows, _ := db.Query(`SELECT rule_name, severity, log_message FROM alerts WHERE tenant_id=$1
		AND status NOT IN ('closed','resolved') ORDER BY severity DESC, created_at DESC LIMIT 8`, tid)
	if arows != nil {
		ctx.WriteString("Recent open alerts:\n")
		for arows.Next() {
			var rule, sev, msg string
			arows.Scan(&rule, &sev, &msg)
			fmt.Fprintf(&ctx, "- [%s] %s — %s\n", sev, rule, msg)
		}
		arows.Close()
	}

	return ctx.String()
}

// aiaBuildPrompt combines the real per-tenant context above with the
// analyst's question so the LLM answers grounded in this tenant's actual
// environment rather than fabricating one.
func aiaBuildPrompt(tid int, message, mode string) string {
	ctxStr := aiaGatherContext(tid)

	var task string
	switch {
	case mode == "investigate":
		task = "You are assisting a SOC analyst with an incident investigation. Analyze the environment data below and answer their question with concrete findings, root-cause reasoning where possible, and recommended next steps."
	case mode == "hunt":
		task = "You are assisting with proactive threat hunting. Use the environment data below to answer the analyst's question, calling out any indicators worth pursuing."
	default:
		task = "You are XCloak's AI security assistant embedded in a SOC platform. Answer the analyst's question using the real environment data below. If the data doesn't contain enough information to answer confidently, say so plainly rather than inventing details."
	}

	return fmt.Sprintf("%s\n\nCurrent environment data for this tenant:\n%s\nAnalyst question: %s\n\nRespond in concise markdown.",
		task, ctxStr, message)
}

// ── Recommendations ───────────────────────────────────────────────────────────

func GetAIARecommendations(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)
	tidStr := fmt.Sprintf("%d", tid)

	var recs []map[string]interface{}
	rows, _ := db.Query(`SELECT rec_id,title,description,category,priority,status,impact,effort,created_at
		FROM aia_recommendations WHERE tenant_id=$1
		ORDER BY CASE priority WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END,
		CASE status WHEN 'open' THEN 1 WHEN 'accepted' THEN 2 ELSE 3 END,
		created_at DESC`, tidStr)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var id, title, desc, cat, pri, st, impact, effort string
			var ca *string
			if err := rows.Scan(&id, &title, &desc, &cat, &pri, &st, &impact, &effort, &ca); err == nil {
				recs = append(recs, map[string]interface{}{
					"rec_id": id, "title": title, "description": desc, "category": cat,
					"priority": pri, "status": st, "impact": impact, "effort": effort, "created_at": ca,
				})
			}
		}
	}
	if recs == nil {
		recs = []map[string]interface{}{}
	}
	c.JSON(http.StatusOK, recs)
}

func PatchAIARecommendation(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)
	tidStr := fmt.Sprintf("%d", tid)
	recID := c.Param("id")
	actor := usernameFromContext(c)

	var body struct {
		Status string `json:"status"`
	}
	c.BindJSON(&body)
	if body.Status == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "status required"})
		return
	}
	db.Exec(`UPDATE aia_recommendations SET status=$1,accepted_by=$2,accepted_at=NOW()
		WHERE tenant_id=$3 AND rec_id=$4`, body.Status, actor, tidStr, recID)
	aiaAudit(tid, "recommendation_updated", "recommendation", recID, actor, fmt.Sprintf("status→%s", body.Status))
	c.JSON(http.StatusOK, gin.H{"status": "updated"})
}

// ── AI Actions ────────────────────────────────────────────────────────────────

func GetAIAActions(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)
	tidStr := fmt.Sprintf("%d", tid)

	var actions []map[string]interface{}
	rows, _ := db.Query(`SELECT action_id,action_type,description,status,requested_by,approved_by,result,created_at
		FROM aia_actions WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT 50`, tidStr)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var id, atype, desc, st, by string
			var approvedBy, result, ca *string
			if err := rows.Scan(&id, &atype, &desc, &st, &by, &approvedBy, &result, &ca); err == nil {
				actions = append(actions, map[string]interface{}{
					"action_id": id, "action_type": atype, "description": desc,
					"status": st, "requested_by": by, "approved_by": approvedBy,
					"result": result, "created_at": ca,
				})
			}
		}
	}
	if actions == nil {
		actions = []map[string]interface{}{}
	}
	c.JSON(http.StatusOK, actions)
}

func PostAIAAction(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)
	tidStr := fmt.Sprintf("%d", tid)
	actor := usernameFromContext(c)

	var body struct {
		ActionType  string `json:"action_type"`
		Description string `json:"description"`
		SessionID   string `json:"session_id"`
	}
	c.BindJSON(&body)
	if body.ActionType == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "action_type required"})
		return
	}
	id := aiaID("AIA-ACT")
	db.Exec(`INSERT INTO aia_actions (tenant_id,action_id,action_type,description,requested_by,session_id)
		VALUES ($1,$2,$3,$4,$5,$6)`, tidStr, id, body.ActionType, body.Description, actor, aiaNullStr(body.SessionID))
	aiaAudit(tid, "action_requested", "action", id, actor, fmt.Sprintf("type:%s", body.ActionType))
	c.JSON(http.StatusOK, gin.H{"action_id": id, "status": "pending_approval"})
}

func PatchAIAActionApprove(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)
	tidStr := fmt.Sprintf("%d", tid)
	actionID := c.Param("id")
	actor := usernameFromContext(c)

	var body struct {
		Approve bool `json:"approve"`
	}
	c.BindJSON(&body)
	status := "rejected"
	if body.Approve {
		status = "approved"
	}
	db.Exec(`UPDATE aia_actions SET status=$1,approved_by=$2,executed_at=NOW() WHERE tenant_id=$3 AND action_id=$4`,
		status, actor, tidStr, actionID)
	aiaAudit(tid, "action_"+status, "action", actionID, actor, "")
	c.JSON(http.StatusOK, gin.H{"status": status})
}

// ── Prompt Library ────────────────────────────────────────────────────────────

func GetAIAPrompts(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)
	tidStr := fmt.Sprintf("%d", tid)
	category := c.Query("category")

	where := []string{"tenant_id=$1"}
	args := []interface{}{tidStr}
	i := 2
	if category != "" {
		where = append(where, fmt.Sprintf("category=$%d", i))
		args = append(args, category)
		i++
	}

	var prompts []map[string]interface{}
	rows, _ := db.Query(fmt.Sprintf(`SELECT prompt_id,title,content,category,is_template,variables,usage_count,created_by,created_at
		FROM aia_prompts WHERE %s ORDER BY usage_count DESC, created_at DESC`, strings.Join(where, " AND ")), args...)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var id, title, content, cat, by string
			var isTemplate bool
			var vars *string
			var usage int
			var ca *string
			if err := rows.Scan(&id, &title, &content, &cat, &isTemplate, &vars, &usage, &by, &ca); err == nil {
				prompts = append(prompts, map[string]interface{}{
					"prompt_id": id, "title": title, "content": content, "category": cat,
					"is_template": isTemplate, "variables": vars, "usage_count": usage,
					"created_by": by, "created_at": ca,
				})
			}
		}
	}
	if prompts == nil {
		prompts = []map[string]interface{}{}
	}
	c.JSON(http.StatusOK, prompts)
}

func PostAIAPrompt(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)
	tidStr := fmt.Sprintf("%d", tid)
	actor := usernameFromContext(c)

	var body struct {
		Title      string `json:"title"`
		Content    string `json:"content"`
		Category   string `json:"category"`
		IsTemplate bool   `json:"is_template"`
		Variables  string `json:"variables"`
	}
	if err := c.BindJSON(&body); err != nil || body.Title == "" || body.Content == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "title and content required"})
		return
	}
	if body.Category == "" {
		body.Category = "general"
	}
	vars := body.Variables
	if vars == "" {
		vars = "[]"
	}
	id := aiaID("AIA-PRM")
	db.Exec(`INSERT INTO aia_prompts (tenant_id,prompt_id,title,content,category,is_template,variables,created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, tidStr, id, body.Title, body.Content, body.Category, body.IsTemplate, vars, actor)
	c.JSON(http.StatusOK, gin.H{"prompt_id": id})
}

// ── Analytics ─────────────────────────────────────────────────────────────────

func GetAIAAnalytics(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)
	tidStr := fmt.Sprintf("%d", tid)

	// mode breakdown
	modes := []map[string]interface{}{}
	mr, _ := db.Query(`SELECT mode, COUNT(*) FROM aia_sessions WHERE tenant_id=$1 GROUP BY mode ORDER BY COUNT(*) DESC`, tidStr)
	if mr != nil {
		defer mr.Close()
		for mr.Next() {
			var m string
			var cnt int
			mr.Scan(&m, &cnt)
			modes = append(modes, map[string]interface{}{"mode": m, "count": cnt})
		}
	}

	// category breakdown for prompts
	cats := []map[string]interface{}{}
	cr, _ := db.Query(`SELECT category, COUNT(*) FROM aia_prompts WHERE tenant_id=$1 GROUP BY category ORDER BY COUNT(*) DESC`, tidStr)
	if cr != nil {
		defer cr.Close()
		for cr.Next() {
			var cat string
			var cnt int
			cr.Scan(&cat, &cnt)
			cats = append(cats, map[string]interface{}{"category": cat, "count": cnt})
		}
	}

	var totalSessions, totalMessages int
	db.QueryRow(`SELECT COUNT(*) FROM aia_sessions WHERE tenant_id=$1`, tidStr).Scan(&totalSessions)
	db.QueryRow(`SELECT COUNT(*) FROM aia_messages WHERE tenant_id=$1`, tidStr).Scan(&totalMessages)

	// usage_trend: real, bucketed by the last 7 real calendar days from
	// aia_sessions/aia_messages/aia_actions created_at.
	usageTrend := []map[string]interface{}{}
	for i := 6; i >= 0; i-- {
		dayStart := time.Now().AddDate(0, 0, -i).Truncate(24 * time.Hour)
		dayEnd := dayStart.Add(24 * time.Hour)
		var sessCnt, msgCnt, actCnt int
		db.QueryRow(`SELECT COUNT(*) FROM aia_sessions WHERE tenant_id=$1 AND created_at>=$2 AND created_at<$3`, tidStr, dayStart, dayEnd).Scan(&sessCnt)
		db.QueryRow(`SELECT COUNT(*) FROM aia_messages WHERE tenant_id=$1 AND created_at>=$2 AND created_at<$3`, tidStr, dayStart, dayEnd).Scan(&msgCnt)
		db.QueryRow(`SELECT COUNT(*) FROM aia_actions WHERE tenant_id=$1 AND created_at>=$2 AND created_at<$3`, tidStr, dayStart, dayEnd).Scan(&actCnt)
		usageTrend = append(usageTrend, map[string]interface{}{
			"date": dayStart.Format("Mon"), "sessions": sessCnt, "messages": msgCnt, "actions": actCnt,
		})
	}

	// response_quality: avg_latency_ms is real (same aia_messages.latency_ms
	// column Dashboard already averages). accuracy_rate/hallucination_rate/
	// user_rating_avg/correction_rate have no real source anywhere — no
	// message ever collects a user rating or correction flag — omitted
	// rather than faked.
	var avgLatency float64
	db.QueryRow(`SELECT COALESCE(AVG(latency_ms),0) FROM aia_messages WHERE tenant_id=$1 AND role='assistant'`, tidStr).Scan(&avgLatency)

	// top_analysts: real, from aia_sessions grouped by created_by (sessions,
	// messages via the real per-session message_count) left-joined against
	// aia_actions grouped by requested_by for a real executed-action count.
	topAnalysts := []map[string]interface{}{}
	tar, _ := db.Query(`SELECT s.created_by, COUNT(*), COALESCE(SUM(s.message_count),0),
		COALESCE((SELECT COUNT(*) FROM aia_actions a WHERE a.tenant_id=$1 AND a.requested_by=s.created_by AND a.executed_at IS NOT NULL),0)
		FROM aia_sessions s WHERE s.tenant_id=$1 GROUP BY s.created_by ORDER BY COUNT(*) DESC LIMIT 10`, tidStr)
	if tar != nil {
		defer tar.Close()
		for tar.Next() {
			var analyst string
			var sessCnt, msgCnt, actExec int
			tar.Scan(&analyst, &sessCnt, &msgCnt, &actExec)
			topAnalysts = append(topAnalysts, map[string]interface{}{
				"analyst": analyst, "sessions": sessCnt, "messages": msgCnt, "actions_executed": actExec,
			})
		}
	}

	// automation_stats: reports_generated is a real aia_reports count;
	// playbooks_generated and detection_rules_generated are real
	// aia_actions counts by action_type (sigma vs. yara can't be split —
	// both go through the same generic 'create_detection_rule' action
	// type, so they're combined rather than guessed at). scripts_generated/
	// queries_generated/analyst_hours_saved have no matching action_type
	// or formula anywhere and were dropped rather than faked.
	var reportsGenerated, playbooksGenerated, detectionRulesGenerated int
	db.QueryRow(`SELECT COUNT(*) FROM aia_reports WHERE tenant_id=$1`, tidStr).Scan(&reportsGenerated)
	db.QueryRow(`SELECT COUNT(*) FROM aia_actions WHERE tenant_id=$1 AND action_type='create_playbook'`, tidStr).Scan(&playbooksGenerated)
	db.QueryRow(`SELECT COUNT(*) FROM aia_actions WHERE tenant_id=$1 AND action_type='create_detection_rule'`, tidStr).Scan(&detectionRulesGenerated)

	c.JSON(http.StatusOK, gin.H{
		"total_sessions": totalSessions, "total_messages": totalMessages,
		"by_mode": modes, "prompt_categories": cats,
		"usage_trend": usageTrend,
		"response_quality": gin.H{
			"avg_latency_ms": int(avgLatency),
		},
		"top_analysts": topAnalysts,
		"automation_stats": gin.H{
			"reports_generated":         reportsGenerated,
			"playbooks_generated":       playbooksGenerated,
			"detection_rules_generated": detectionRulesGenerated,
		},
	})
}

// ── Reports ───────────────────────────────────────────────────────────────────

func GetAIAReports(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)
	tidStr := fmt.Sprintf("%d", tid)

	var reports []map[string]interface{}
	rows, _ := db.Query(`SELECT report_id,title,report_type,generated_by,format,session_id,created_at,COALESCE(content,'')
		FROM aia_reports WHERE tenant_id=$1 ORDER BY created_at DESC`, tidStr)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var id, title, rtype, by, format, content string
			var sid, ca *string
			if err := rows.Scan(&id, &title, &rtype, &by, &format, &sid, &ca, &content); err == nil {
				reports = append(reports, map[string]interface{}{
					"report_id": id, "title": title, "report_type": rtype,
					"generated_by": by, "format": format, "session_id": sid, "created_at": ca,
					"content": content,
				})
			}
		}
	}
	if reports == nil {
		reports = []map[string]interface{}{}
	}
	c.JSON(http.StatusOK, reports)
}

// generateAIAReportContent writes real report content grounded in this
// tenant's actual data: if a source session was given, it summarizes that
// real conversation; otherwise it grounds in the same real fleet-wide
// security context aiaBuildPrompt gathers for chat.
func generateAIAReportContent(tid int, title, reportType, sessionID string) string {
	db := database.DB
	var ctx strings.Builder
	if sessionID != "" {
		rows, _ := db.Query(`SELECT role, content FROM aia_messages WHERE tenant_id=$1 AND session_id=$2 ORDER BY created_at ASC`, tid, sessionID)
		if rows != nil {
			ctx.WriteString("Source conversation:\n")
			for rows.Next() {
				var role, content string
				rows.Scan(&role, &content)
				fmt.Fprintf(&ctx, "[%s]: %s\n", role, content)
			}
			rows.Close()
		}
	}
	if ctx.Len() == 0 {
		ctx.WriteString(aiaGatherContext(tid))
	}

	prompt := fmt.Sprintf(`Write a %s titled %q for a SOC platform's AI Assistant. Ground it strictly in the real data below — do not invent incidents, CVEs, or figures not present.

%s

Respond in concise markdown suitable for direct display.`, strings.ReplaceAll(reportType, "_", " "), title, ctx.String())

	if resp, err := services.CallLLM(prompt); err == nil && strings.TrimSpace(resp) != "" {
		return strings.TrimSpace(resp)
	}
	return fmt.Sprintf("# %s\n\nUnable to reach the AI model to generate this report's narrative. Real underlying data was gathered but could not be summarized.", title)
}

func PostAIAReport(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)
	tidStr := fmt.Sprintf("%d", tid)
	actor := usernameFromContext(c)

	var body struct {
		Title      string `json:"title"`
		ReportType string `json:"report_type"`
		Format     string `json:"format"`
		SessionID  string `json:"session_id"`
	}
	c.BindJSON(&body)
	if body.Format == "" {
		body.Format = "markdown"
	}
	id := aiaID("AIA-RPT")
	content := generateAIAReportContent(tid, body.Title, body.ReportType, body.SessionID)
	db.Exec(`INSERT INTO aia_reports (tenant_id,report_id,title,report_type,content,generated_by,format,session_id)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, tidStr, id, body.Title, body.ReportType, content, actor, body.Format, aiaNullStr(body.SessionID))
	aiaAudit(tid, "report_generated", "report", id, actor, fmt.Sprintf("type:%s", body.ReportType))
	c.JSON(http.StatusOK, gin.H{"report_id": id, "content": content})
}

// ── Audit ─────────────────────────────────────────────────────────────────────

func GetAIAAudit(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)
	tidStr := fmt.Sprintf("%d", tid)
	limit := parseLimit(c, 100)

	var entries []map[string]interface{}
	rows, _ := db.Query(`SELECT action,object_type,object_id,actor,details,created_at
		FROM aia_audit WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT $2`, tidStr, limit)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var action, otype, actor string
			var oid, details, ca *string
			if err := rows.Scan(&action, &otype, &oid, &actor, &details, &ca); err == nil {
				entries = append(entries, map[string]interface{}{
					"action": action, "object_type": otype, "object_id": oid,
					"actor": actor, "details": details, "created_at": ca,
				})
			}
		}
	}
	if entries == nil {
		entries = []map[string]interface{}{}
	}
	c.JSON(http.StatusOK, entries)
}
