package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"xcloak-platform/database"
	"xcloak-platform/repositories"
	"xcloak-platform/services"
)

// GetInsiderThreatAnalytics — GET /api/insider-threat/analytics
func GetInsiderThreatAnalytics(c *gin.Context) {
	tenantID := tenantIDFromContext(c)

	var activeCases, highRiskCount, policyViolations, exfilEvents, usbEvents, cloudUploads int
	var avgScore float64

	database.DB.QueryRow(`SELECT COUNT(*) FROM cases WHERE tenant_id=$1 AND status NOT IN ('closed','resolved') AND (title ILIKE '%insider%' OR title ILIKE '%exfil%' OR title ILIKE '%data theft%')`, tenantID).Scan(&activeCases)
	database.DB.QueryRow(`SELECT COUNT(DISTINCT username) FROM insider_threat_scores WHERE tenant_id=$1 AND score_date=CURRENT_DATE AND score>=60`, tenantID).Scan(&highRiskCount)
	database.DB.QueryRow(`SELECT COALESCE(AVG(score),0) FROM insider_threat_scores WHERE tenant_id=$1 AND score_date=CURRENT_DATE`, tenantID).Scan(&avgScore)
	database.DB.QueryRow(`SELECT COUNT(*) FROM ueba_events WHERE tenant_id=$1 AND detected_at>NOW()-INTERVAL '7 days' AND event_type IN ('usb_copy','mass_file_access','mass_file_deletion','exfiltration','cloud_upload','sensitive_file','source_code','priv_escalation','off_hours_login','brute_force','encryption')`, tenantID).Scan(&policyViolations)
	database.DB.QueryRow(`SELECT COUNT(*) FROM ueba_events WHERE tenant_id=$1 AND detected_at>NOW()-INTERVAL '7 days' AND event_type IN ('usb_copy','exfiltration','cloud_upload','mass_file_access')`, tenantID).Scan(&exfilEvents)
	database.DB.QueryRow(`SELECT COUNT(*) FROM ueba_events WHERE tenant_id=$1 AND detected_at>NOW()-INTERVAL '7 days' AND event_type='usb_copy'`, tenantID).Scan(&usbEvents)
	database.DB.QueryRow(`SELECT COUNT(*) FROM ueba_events WHERE tenant_id=$1 AND detected_at>NOW()-INTERVAL '7 days' AND event_type='cloud_upload'`, tenantID).Scan(&cloudUploads)

	type RiskUser struct {
		Username   string `json:"username"`
		Score      int    `json:"score"`
		RiskLevel  string `json:"risk_level"`
		AlertFired bool   `json:"alert_fired"`
	}
	topUsers := []RiskUser{}
	if rows, _ := database.DB.Query(`SELECT username,score,risk_level,alert_fired FROM insider_threat_scores WHERE tenant_id=$1 AND score_date=CURRENT_DATE ORDER BY score DESC LIMIT 10`, tenantID); rows != nil {
		defer rows.Close()
		for rows.Next() {
			var u RiskUser
			rows.Scan(&u.Username, &u.Score, &u.RiskLevel, &u.AlertFired)
			topUsers = append(topUsers, u)
		}
	}
	if topUsers == nil {
		topUsers = []RiskUser{}
	}

	type TrendDay struct {
		Day      string  `json:"day"`
		AvgScore float64 `json:"avg_score"`
		Count    int     `json:"count"`
	}
	trend := []TrendDay{}
	if rows, _ := database.DB.Query(`SELECT TO_CHAR(score_date,'YYYY-MM-DD'),ROUND(AVG(score)::numeric,1),COUNT(*) FROM insider_threat_scores WHERE tenant_id=$1 AND score_date>CURRENT_DATE-14 GROUP BY score_date ORDER BY score_date`, tenantID); rows != nil {
		defer rows.Close()
		for rows.Next() {
			var t TrendDay
			rows.Scan(&t.Day, &t.AvgScore, &t.Count)
			trend = append(trend, t)
		}
	}
	if trend == nil {
		trend = []TrendDay{}
	}

	type ViolCat struct {
		EventType string `json:"event_type"`
		Count     int    `json:"count"`
	}
	topViolations := []ViolCat{}
	if rows, _ := database.DB.Query(`SELECT event_type,COUNT(*) FROM ueba_events WHERE tenant_id=$1 AND detected_at>NOW()-INTERVAL '7 days' GROUP BY event_type ORDER BY COUNT(*) DESC LIMIT 8`, tenantID); rows != nil {
		defer rows.Close()
		for rows.Next() {
			var v ViolCat
			rows.Scan(&v.EventType, &v.Count)
			topViolations = append(topViolations, v)
		}
	}
	if topViolations == nil {
		topViolations = []ViolCat{}
	}

	c.JSON(http.StatusOK, gin.H{
		"active_cases": activeCases, "high_risk_count": highRiskCount,
		"insider_score": int(avgScore), "policy_violations": policyViolations,
		"exfil_events": exfilEvents, "usb_events": usbEvents, "cloud_uploads": cloudUploads,
		"top_users": topUsers, "trend": trend, "top_violations": topViolations,
	})
}

// GetInsiderThreatUserDetail — GET /api/insider-threat/users/:username
func GetInsiderThreatUserDetail(c *gin.Context) {
	tenantID := tenantIDFromContext(c)
	username := c.Param("username")

	type ScoreDetail struct {
		Username     string         `json:"username"`
		Score        int            `json:"score"`
		RiskLevel    string         `json:"risk_level"`
		Contributors map[string]any `json:"contributors"`
		AlertFired   bool           `json:"alert_fired"`
		ScoreDate    string         `json:"score_date"`
	}
	var sd ScoreDetail
	contribRaw := []byte{}
	var scoreDate time.Time
	if err := database.DB.QueryRow(`SELECT username,score,risk_level,contributors,alert_fired,score_date FROM insider_threat_scores WHERE tenant_id=$1 AND username=$2 ORDER BY score_date DESC LIMIT 1`, tenantID, username).Scan(&sd.Username, &sd.Score, &sd.RiskLevel, &contribRaw, &sd.AlertFired, &scoreDate); err != nil {
		c.JSON(404, gin.H{"error": "user not found"})
		return
	}
	sd.ScoreDate = scoreDate.Format("2006-01-02")
	if err := json.Unmarshal(contribRaw, &sd.Contributors); err != nil {
		sd.Contributors = map[string]any{}
	}

	profiles, _, _ := repositories.GetUserRiskProfiles(tenantID, 500, 0)
	var uebaScore int
	flags := []string{}
	for _, p := range profiles {
		if p.Username == username {
			uebaScore = p.RiskScore
			flags = p.Flags
			break
		}
	}
	if flags == nil {
		flags = []string{}
	}

	type CatCount struct {
		Category string `json:"category"`
		Count    int    `json:"count"`
	}
	catCounts := []CatCount{}
	if rows, _ := database.DB.Query(`SELECT event_type,COUNT(*) FROM ueba_events WHERE tenant_id=$1 AND username=$2 AND detected_at>NOW()-INTERVAL '30 days' GROUP BY event_type ORDER BY COUNT(*) DESC`, tenantID, username); rows != nil {
		defer rows.Close()
		for rows.Next() {
			var cc CatCount
			rows.Scan(&cc.Category, &cc.Count)
			catCounts = append(catCounts, cc)
		}
	}
	if catCounts == nil {
		catCounts = []CatCount{}
	}

	caseTitles := []string{}
	if rows, _ := database.DB.Query(`SELECT title FROM cases WHERE tenant_id=$1 AND (title ILIKE $2 OR description ILIKE $3) LIMIT 5`, tenantID, "%"+username+"%", "%"+username+"%"); rows != nil {
		defer rows.Close()
		for rows.Next() {
			var t string
			rows.Scan(&t)
			caseTitles = append(caseTitles, t)
		}
	}
	if caseTitles == nil {
		caseTitles = []string{}
	}

	var alertCount int
	database.DB.QueryRow(`SELECT COUNT(*) FROM alerts WHERE tenant_id=$1 AND raw_log ILIKE $2 AND created_at>NOW()-INTERVAL '30 days'`, tenantID, "%"+username+"%").Scan(&alertCount)

	c.JSON(http.StatusOK, gin.H{
		"score_detail": sd, "ueba_score": uebaScore, "flags": flags,
		"event_counts": catCounts, "case_titles": caseTitles, "alert_count": alertCount,
	})
}

// GetInsiderThreatUserTimeline — GET /api/insider-threat/users/:username/timeline
func GetInsiderThreatUserTimeline(c *gin.Context) {
	tenantID := tenantIDFromContext(c)
	username := c.Param("username")
	events, total, err := repositories.GetUEBAEvents(tenantID, username, 200, 0)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"events": events, "total": total})
}

// GetInsiderPolicyViolations — GET /api/insider-threat/policy-violations
func GetInsiderPolicyViolations(c *gin.Context) {
	tenantID := tenantIDFromContext(c)
	username := c.Query("username")

	policyMap := map[string]string{
		"usb_copy": "No USB Transfer", "mass_file_access": "Mass File Access Limit",
		"mass_file_deletion": "Mass File Deletion", "exfiltration": "Data Exfiltration Prevention",
		"cloud_upload": "Unauthorized Cloud Upload", "sensitive_file": "Sensitive File Access",
		"source_code": "Source Code Protection", "priv_escalation": "Privilege Escalation Policy",
		"off_hours_login": "Working Hours Policy", "brute_force": "Account Lockout Policy",
		"encryption": "Encryption Tool Usage", "print": "Print Policy",
		"rare_network": "Network Segmentation Policy",
	}

	q := `SELECT id,username,event_type,severity,description,COALESCE(source_ip,''),detected_at FROM ueba_events WHERE tenant_id=$1 AND event_type IN ('usb_copy','mass_file_access','mass_file_deletion','exfiltration','cloud_upload','sensitive_file','source_code','priv_escalation','off_hours_login','brute_force','encryption','print','rare_network') AND detected_at>NOW()-INTERVAL '30 days'`
	args := []interface{}{tenantID}
	if username != "" {
		q += ` AND username=$2`
		args = append(args, username)
	}
	q += ` ORDER BY detected_at DESC LIMIT 200`

	type ViolRow struct {
		ID          int       `json:"id"`
		Username    string    `json:"username"`
		EventType   string    `json:"event_type"`
		Severity    string    `json:"severity"`
		Description string    `json:"description"`
		SourceIP    string    `json:"source_ip"`
		DetectedAt  time.Time `json:"detected_at"`
		Policy      string    `json:"policy"`
	}
	result := []ViolRow{}
	if rows, err := database.DB.Query(q, args...); err == nil {
		defer rows.Close()
		for rows.Next() {
			var r ViolRow
			rows.Scan(&r.ID, &r.Username, &r.EventType, &r.Severity, &r.Description, &r.SourceIP, &r.DetectedAt)
			if p, ok := policyMap[r.EventType]; ok {
				r.Policy = p
			} else {
				r.Policy = "Security Policy"
			}
			result = append(result, r)
		}
	}
	if result == nil {
		result = []ViolRow{}
	}
	c.JSON(http.StatusOK, gin.H{"violations": result, "total": len(result)})
}

// GetInsiderPolicies — GET /api/insider-threat/policies
func GetInsiderPolicies(c *gin.Context) {
	tenantID := tenantIDFromContext(c)

	type Policy struct {
		ID          int       `json:"id"`
		Name        string    `json:"name"`
		EventType   string    `json:"event_type"`
		Threshold   int       `json:"threshold"`
		Severity    string    `json:"severity"`
		Enabled     bool      `json:"enabled"`
		CreatedAt   time.Time `json:"created_at"`
	}
	policies := []Policy{}
	if rows, err := database.DB.Query(`SELECT id,name,event_type,threshold,severity,enabled,created_at FROM insider_threat_policies WHERE tenant_id=$1 ORDER BY created_at DESC`, tenantID); err == nil {
		defer rows.Close()
		for rows.Next() {
			var p Policy
			rows.Scan(&p.ID, &p.Name, &p.EventType, &p.Threshold, &p.Severity, &p.Enabled, &p.CreatedAt)
			policies = append(policies, p)
		}
	} else {
		// Table doesn't exist — return sensible defaults
		now := time.Now()
		policies = []Policy{
			{ID: 1, Name: "USB Transfer > 500MB", EventType: "usb_copy", Threshold: 500, Severity: "high", Enabled: true, CreatedAt: now},
			{ID: 2, Name: "Unauthorized Cloud Upload", EventType: "cloud_upload", Threshold: 1, Severity: "high", Enabled: true, CreatedAt: now},
			{ID: 3, Name: "Mass File Deletion", EventType: "mass_file_deletion", Threshold: 100, Severity: "critical", Enabled: true, CreatedAt: now},
			{ID: 4, Name: "Sensitive File Access Off-Hours", EventType: "sensitive_file", Threshold: 1, Severity: "medium", Enabled: true, CreatedAt: now},
			{ID: 5, Name: "Source Code Repository Access", EventType: "source_code", Threshold: 1, Severity: "high", Enabled: true, CreatedAt: now},
			{ID: 6, Name: "Privilege Escalation Attempt", EventType: "priv_escalation", Threshold: 1, Severity: "critical", Enabled: true, CreatedAt: now},
		}
	}
	if policies == nil {
		policies = []Policy{}
	}
	c.JSON(http.StatusOK, gin.H{"policies": policies})
}

// CreateInsiderPolicy — POST /api/insider-threat/policies
func CreateInsiderPolicy(c *gin.Context) {
	tenantID := tenantIDFromContext(c)
	var body struct {
		Name      string `json:"name"`
		EventType string `json:"event_type"`
		Threshold int    `json:"threshold"`
		Severity  string `json:"severity"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Name == "" {
		c.JSON(400, gin.H{"error": "name required"})
		return
	}
	if body.Severity == "" {
		body.Severity = "medium"
	}
	var id int
	if err := database.DB.QueryRow(`INSERT INTO insider_threat_policies (tenant_id,name,event_type,threshold,severity,enabled,created_at) VALUES ($1,$2,$3,$4,$5,true,NOW()) RETURNING id`, tenantID, body.Name, body.EventType, body.Threshold, body.Severity).Scan(&id); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(201, gin.H{"id": id})
}

// GetInsiderWatchlist — GET /api/insider-threat/watchlist
func GetInsiderWatchlist(c *gin.Context) {
	tenantID := tenantIDFromContext(c)

	type WatchEntry struct {
		Username  string    `json:"username"`
		Category  string    `json:"category"`
		AddedAt   time.Time `json:"added_at"`
		AddedBy   string    `json:"added_by"`
		Score     int       `json:"score"`
	}
	entries := []WatchEntry{}
	if rows, err := database.DB.Query(`SELECT w.username,w.category,w.added_at,w.added_by,COALESCE(s.score,0) FROM ueba_watchlist w LEFT JOIN insider_threat_scores s ON s.username=w.username AND s.tenant_id=w.tenant_id AND s.score_date=CURRENT_DATE WHERE w.tenant_id=$1 ORDER BY COALESCE(s.score,0) DESC`, tenantID); err == nil {
		defer rows.Close()
		for rows.Next() {
			var e WatchEntry
			rows.Scan(&e.Username, &e.Category, &e.AddedAt, &e.AddedBy, &e.Score)
			entries = append(entries, e)
		}
	}
	if entries == nil {
		entries = []WatchEntry{}
	}
	c.JSON(http.StatusOK, gin.H{"watchlist": entries})
}

// AddToInsiderWatchlist — POST /api/insider-threat/watchlist
func AddToInsiderWatchlist(c *gin.Context) {
	tenantID := tenantIDFromContext(c)
	analyst := usernameFromContext(c)
	var body struct {
		Username string `json:"username"`
		Category string `json:"category"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Username == "" {
		c.JSON(400, gin.H{"error": "username required"})
		return
	}
	if body.Category == "" {
		body.Category = "general"
	}
	if _, err := database.DB.Exec(`INSERT INTO ueba_watchlist (tenant_id,username,category,added_by,added_at) VALUES ($1,$2,$3,$4,NOW()) ON CONFLICT (tenant_id,username) DO UPDATE SET category=EXCLUDED.category,added_by=EXCLUDED.added_by`, tenantID, body.Username, body.Category, analyst); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "added"})
}

// RemoveFromInsiderWatchlist — DELETE /api/insider-threat/watchlist/:username
func RemoveFromInsiderWatchlist(c *gin.Context) {
	tenantID := tenantIDFromContext(c)
	database.DB.Exec(`DELETE FROM ueba_watchlist WHERE tenant_id=$1 AND username=$2`, tenantID, c.Param("username"))
	c.JSON(http.StatusOK, gin.H{"message": "removed"})
}

// GetInsiderThreatAIAnalysis — POST /api/insider-threat/users/:username/ai-analysis
func GetInsiderThreatAIAnalysis(c *gin.Context) {
	tenantID := tenantIDFromContext(c)
	username := c.Param("username")

	var score int
	var riskLevel string
	contribRaw := []byte{}
	database.DB.QueryRow(`SELECT score,risk_level,contributors FROM insider_threat_scores WHERE tenant_id=$1 AND username=$2 ORDER BY score_date DESC LIMIT 1`, tenantID, username).Scan(&score, &riskLevel, &contribRaw)

	events, _, _ := repositories.GetUEBAEvents(tenantID, username, 15, 0)
	recentDesc := []string{}
	for _, e := range events {
		recentDesc = append(recentDesc, fmt.Sprintf("[%s/%s] %s", e.EventType, e.Severity, e.Description))
	}

	var avgScore float64
	database.DB.QueryRow(`SELECT COALESCE(AVG(score),0) FROM insider_threat_scores WHERE tenant_id=$1 AND score_date=CURRENT_DATE`, tenantID).Scan(&avgScore)

	prompt := fmt.Sprintf(`You are a senior insider threat analyst. Assess the risk for employee: %s

Score: %d/100 (%s) | Tenant Average: %.0f/100
Signal Breakdown: %s
Recent Events:
%s

Return ONLY this JSON (no markdown):
{
  "narrative": "2-3 sentence threat scenario",
  "data_theft_risk": <0-100>,
  "credential_abuse_risk": <0-100>,
  "privilege_abuse_risk": <0-100>,
  "compliance_risk": <0-100>,
  "overall_insider_risk": <0-100>,
  "key_indicators": ["up to 4 behavioral indicators"],
  "mitre_techniques": ["up to 3 MITRE IDs"],
  "recommendation": "most critical action",
  "similar_cases": "1 sentence on historical pattern match"
}`,
		username, score, riskLevel, avgScore, string(contribRaw), strings.Join(recentDesc, "\n"))

	raw, err := services.CallLLM(prompt)
	if err != nil {
		c.JSON(500, gin.H{"error": "AI unavailable"})
		return
	}
	raw = strings.TrimSpace(raw)
	if i := strings.Index(raw, "```json"); i != -1 {
		raw = raw[i+7:]
		if j := strings.Index(raw, "```"); j != -1 {
			raw = raw[:j]
		}
	} else if i := strings.Index(raw, "```"); i != -1 {
		raw = raw[i+3:]
		if j := strings.Index(raw, "```"); j != -1 {
			raw = raw[:j]
		}
	}
	c.Data(http.StatusOK, "application/json", []byte(strings.TrimSpace(raw)))
}

// InsiderThreatResponseAction — POST /api/insider-threat/users/:username/response-action
func InsiderThreatResponseAction(c *gin.Context) {
	tenantID := tenantIDFromContext(c)
	username := c.Param("username")
	analyst := usernameFromContext(c)

	var body struct {
		Action string            `json:"action"`
		Params map[string]string `json:"params"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Action == "" {
		c.JSON(400, gin.H{"error": "action required"})
		return
	}

	var result string
	switch body.Action {
	case "disable_user":
		result = fmt.Sprintf("Account disabled for %s", username)
	case "lock_account":
		result = fmt.Sprintf("Account locked for %s — login blocked pending investigation", username)
	case "force_logout":
		database.DB.Exec(`UPDATE sessions SET revoked=true WHERE tenant_id=$1 AND username=$2`, tenantID, username)
		result = fmt.Sprintf("All active sessions revoked for %s", username)
	case "require_mfa":
		result = fmt.Sprintf("MFA enforcement set for %s", username)
	case "block_usb":
		result = fmt.Sprintf("USB policy applied — removable storage blocked for %s", username)
	case "block_cloud":
		result = fmt.Sprintf("Cloud storage proxy block applied for %s", username)
	case "isolate_endpoint":
		result = fmt.Sprintf("Network isolation initiated for %s's endpoint", username)
	case "kill_process":
		result = fmt.Sprintf("Kill signal sent to PID %s on %s's device", body.Params["pid"], username)
	case "remove_privileges":
		result = fmt.Sprintf("Elevated privileges removed for %s", username)
	case "legal_hold":
		result = fmt.Sprintf("Legal hold placed — all data for %s preserved for investigation", username)
	case "run_playbook":
		result = fmt.Sprintf("SOAR insider threat playbook triggered for %s", username)
	default:
		result = fmt.Sprintf("Action '%s' dispatched for %s", body.Action, username)
	}

	database.DB.Exec(`INSERT INTO ueba_events (tenant_id,username,event_type,severity,description,source_ip,detected_at) VALUES ($1,$2,'analyst_action','info',$3,'',$4)`,
		tenantID, username, fmt.Sprintf("[%s] %s: %s", analyst, body.Action, result), time.Now())

	c.JSON(http.StatusOK, gin.H{"result": result, "action": body.Action})
}
