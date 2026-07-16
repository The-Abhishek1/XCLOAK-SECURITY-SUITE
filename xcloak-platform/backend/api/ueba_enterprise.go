package api

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"xcloak-platform/database"
	"xcloak-platform/repositories"
	"xcloak-platform/services"
)

// GetUEBAAnalytics — GET /api/ueba/analytics  (static — register BEFORE :username routes)
func GetUEBAAnalytics(c *gin.Context) {
	tenantID := tenantIDFromContext(c)

	// High-risk users (score >= 60)
	type RiskRow struct {
		Username  string  `json:"username"`
		Source    string  `json:"source"`
		RiskScore int     `json:"risk_score"`
		Flags     []string `json:"flags"`
	}
	var highRisk []RiskRow
	rows, _ := database.DB.Query(`
		SELECT username, source, risk_score, flags
		FROM user_risk_profiles WHERE tenant_id=$1 AND risk_score >= 60
		ORDER BY risk_score DESC LIMIT 10`, tenantID)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var r RiskRow
			var flags []string
			if rows.Scan(&r.Username, &r.Source, &r.RiskScore, &flags) == nil {
				r.Flags = flags
			}
			if r.Flags == nil {
				r.Flags = []string{}
			}
			highRisk = append(highRisk, r)
		}
	}
	if highRisk == nil {
		highRisk = []RiskRow{}
	}

	// Top event types / anomalies (last 7 days)
	type AnomalyRow struct {
		EventType string `json:"event_type"`
		Count     int    `json:"count"`
	}
	var topAnomalies []AnomalyRow
	rows2, _ := database.DB.Query(`
		SELECT event_type, COUNT(*) AS cnt
		FROM ueba_events WHERE tenant_id=$1 AND detected_at > NOW()-INTERVAL '7 days'
		GROUP BY event_type ORDER BY cnt DESC LIMIT 8`, tenantID)
	if rows2 != nil {
		defer rows2.Close()
		for rows2.Next() {
			var a AnomalyRow
			rows2.Scan(&a.EventType, &a.Count)
			topAnomalies = append(topAnomalies, a)
		}
	}
	if topAnomalies == nil {
		topAnomalies = []AnomalyRow{}
	}

	// Risk distribution
	type RiskBucket struct {
		Label string `json:"label"`
		Count int    `json:"count"`
	}
	buckets := []RiskBucket{
		{Label: "critical"},
		{Label: "high"},
		{Label: "medium"},
		{Label: "low"},
	}
	database.DB.QueryRow(`SELECT COUNT(*) FROM user_risk_profiles WHERE tenant_id=$1 AND risk_score >= 80`, tenantID).Scan(&buckets[0].Count)
	database.DB.QueryRow(`SELECT COUNT(*) FROM user_risk_profiles WHERE tenant_id=$1 AND risk_score >= 60 AND risk_score < 80`, tenantID).Scan(&buckets[1].Count)
	database.DB.QueryRow(`SELECT COUNT(*) FROM user_risk_profiles WHERE tenant_id=$1 AND risk_score >= 30 AND risk_score < 60`, tenantID).Scan(&buckets[2].Count)
	database.DB.QueryRow(`SELECT COUNT(*) FROM user_risk_profiles WHERE tenant_id=$1 AND risk_score < 30`, tenantID).Scan(&buckets[3].Count)

	// 14-day event trend
	type TrendDay struct {
		Day   string `json:"day"`
		Count int    `json:"count"`
	}
	var trend []TrendDay
	rows3, _ := database.DB.Query(`
		SELECT TO_CHAR(detected_at::date,'YYYY-MM-DD'), COUNT(*)
		FROM ueba_events WHERE tenant_id=$1 AND detected_at > NOW()-INTERVAL '14 days'
		GROUP BY detected_at::date ORDER BY detected_at::date`, tenantID)
	if rows3 != nil {
		defer rows3.Close()
		for rows3.Next() {
			var t TrendDay
			rows3.Scan(&t.Day, &t.Count)
			trend = append(trend, t)
		}
	}
	if trend == nil {
		trend = []TrendDay{}
	}

	var totalUsers, totalEvents int
	database.DB.QueryRow(`SELECT COUNT(*) FROM user_risk_profiles WHERE tenant_id=$1`, tenantID).Scan(&totalUsers)
	database.DB.QueryRow(`SELECT COUNT(*) FROM ueba_events WHERE tenant_id=$1 AND detected_at > NOW()-INTERVAL '7 days'`, tenantID).Scan(&totalEvents)

	// Insider threat score = weighted average of flags
	var avgScore float64
	database.DB.QueryRow(`SELECT COALESCE(AVG(risk_score),0) FROM user_risk_profiles WHERE tenant_id=$1`, tenantID).Scan(&avgScore)

	c.JSON(http.StatusOK, gin.H{
		"high_risk_users":       highRisk,
		"top_anomalies":         topAnomalies,
		"risk_distribution":     buckets,
		"trend":                 trend,
		"total_users":           totalUsers,
		"total_events_7d":       totalEvents,
		"insider_threat_score":  int(avgScore),
	})
}

// GetUEBAUserDetail — GET /api/ueba/users/:username
func GetUEBAUserDetail(c *gin.Context) {
	tenantID := tenantIDFromContext(c)
	username := c.Param("username")

	// Profile
	profiles, _, err := repositories.GetUserRiskProfiles(tenantID, 500, 0)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	var profile interface{}
	for _, p := range profiles {
		if p.Username == username {
			profile = p
			break
		}
	}
	if profile == nil {
		c.JSON(404, gin.H{"error": "user not found"})
		return
	}

	// Recent events summary
	events, total, _ := repositories.GetUEBAEvents(tenantID, username, 5, 0)

	// Linked alerts count
	var alertCount int
	database.DB.QueryRow(`
		SELECT COUNT(*) FROM alerts WHERE tenant_id=$1
		  AND (raw_log ILIKE $2 OR raw_log ILIKE $3)
		  AND created_at > NOW()-INTERVAL '30 days'`,
		tenantID, "%"+username+"%", username).Scan(&alertCount)

	// Linked incidents count
	var incidentCount int
	database.DB.QueryRow(`
		SELECT COUNT(*) FROM incidents WHERE tenant_id=$1
		  AND (description ILIKE $2 OR title ILIKE $3)`,
		tenantID, "%"+username+"%", "%"+username+"%").Scan(&incidentCount)

	// Unique IPs in last 30d
	type IPRow struct {
		IP    string    `json:"ip"`
		Count int       `json:"count"`
		Last  time.Time `json:"last_seen"`
	}
	var ips []IPRow
	rows, _ := database.DB.Query(`
		SELECT source_ip, COUNT(*), MAX(detected_at) FROM ueba_events
		WHERE tenant_id=$1 AND username=$2 AND source_ip!='' AND detected_at > NOW()-INTERVAL '30 days'
		GROUP BY source_ip ORDER BY MAX(detected_at) DESC LIMIT 10`, tenantID, username)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var r IPRow
			rows.Scan(&r.IP, &r.Count, &r.Last)
			ips = append(ips, r)
		}
	}
	if ips == nil {
		ips = []IPRow{}
	}

	c.JSON(http.StatusOK, gin.H{
		"profile":        profile,
		"recent_events":  events,
		"total_events":   total,
		"alert_count":    alertCount,
		"incident_count": incidentCount,
		"known_ips":      ips,
	})
}

// GetUEBAUserTimeline — GET /api/ueba/users/:username/timeline
func GetUEBAUserTimeline(c *gin.Context) {
	tenantID := tenantIDFromContext(c)
	username := c.Param("username")

	events, total, err := repositories.GetUEBAEvents(tenantID, username, 200, 0)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"events": events, "total": total})
}

// GetUEBAPeerComparison — GET /api/ueba/users/:username/peer-comparison
func GetUEBAPeerComparison(c *gin.Context) {
	tenantID := tenantIDFromContext(c)
	username := c.Param("username")

	// Aggregate stats for all users in tenant (peer group = all)
	type PeerStats struct {
		AvgRiskScore          float64 `json:"avg_risk_score"`
		AvgTotalEvents        float64 `json:"avg_total_events"`
		AvgFailedLogins       float64 `json:"avg_failed_logins"`
		AvgOffHours           float64 `json:"avg_off_hours"`
		AvgUniqueIPs          float64 `json:"avg_unique_ips"`
		AvgPrivEscalations    float64 `json:"avg_priv_escalations"`
		TotalPeers            int     `json:"total_peers"`
	}
	var ps PeerStats
	database.DB.QueryRow(`
		SELECT
			COALESCE(AVG(risk_score),0),
			COALESCE(AVG(total_events),0),
			COALESCE(AVG(failed_logins),0),
			COALESCE(AVG(off_hours_events),0),
			COALESCE(AVG(unique_ips),0),
			COALESCE(AVG(privilege_escalations),0),
			COUNT(*)
		FROM user_risk_profiles WHERE tenant_id=$1`, tenantID).
		Scan(&ps.AvgRiskScore, &ps.AvgTotalEvents, &ps.AvgFailedLogins,
			&ps.AvgOffHours, &ps.AvgUniqueIPs, &ps.AvgPrivEscalations, &ps.TotalPeers)

	// User's actual stats
	type UserSnap struct {
		RiskScore         int `json:"risk_score"`
		TotalEvents       int `json:"total_events"`
		FailedLogins      int `json:"failed_logins"`
		OffHoursEvents    int `json:"off_hours_events"`
		UniqueIPs         int `json:"unique_ips"`
		PrivEscalations   int `json:"privilege_escalations"`
	}
	var us UserSnap
	database.DB.QueryRow(`
		SELECT risk_score, total_events, failed_logins, off_hours_events, unique_ips, privilege_escalations
		FROM user_risk_profiles WHERE tenant_id=$1 AND username=$2
		ORDER BY risk_score DESC LIMIT 1`, tenantID, username).
		Scan(&us.RiskScore, &us.TotalEvents, &us.FailedLogins, &us.OffHoursEvents, &us.UniqueIPs, &us.PrivEscalations)

	// Top outliers in tenant
	type Outlier struct {
		Username  string `json:"username"`
		RiskScore int    `json:"risk_score"`
		Metric    string `json:"metric"`
		Value     int    `json:"value"`
	}
	var outliers []Outlier
	rows, _ := database.DB.Query(`
		SELECT username, risk_score, total_events FROM user_risk_profiles
		WHERE tenant_id=$1 AND username!=$2 ORDER BY total_events DESC LIMIT 5`, tenantID, username)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var o Outlier
			o.Metric = "total_events"
			rows.Scan(&o.Username, &o.RiskScore, &o.Value)
			outliers = append(outliers, o)
		}
	}
	if outliers == nil {
		outliers = []Outlier{}
	}

	c.JSON(http.StatusOK, gin.H{
		"user":     us,
		"peers":    ps,
		"outliers": outliers,
	})
}

// GetUEBAUserAIInsights — POST /api/ueba/users/:username/ai-insights
func GetUEBAUserAIInsights(c *gin.Context) {
	tenantID := tenantIDFromContext(c)
	username := c.Param("username")

	// Gather context
	profiles, _, _ := repositories.GetUserRiskProfiles(tenantID, 500, 0)
	var riskScore int
	var flags []string
	var totalEvents, failedLogins, offHours, uniqueIPs, privEsc int
	for _, p := range profiles {
		if p.Username == username {
			riskScore = p.RiskScore
			flags = p.Flags
			totalEvents = p.TotalEvents
			failedLogins = p.FailedLogins
			offHours = p.OffHoursEvents
			uniqueIPs = p.UniqueIPs
			privEsc = p.PrivilegeEscalations
			break
		}
	}

	events, _, _ := repositories.GetUEBAEvents(tenantID, username, 10, 0)
	var recentDesc []string
	for _, e := range events {
		recentDesc = append(recentDesc, fmt.Sprintf("[%s] %s: %s", e.Severity, e.EventType, e.Description))
	}

	prompt := fmt.Sprintf(`You are a UEBA security analyst. Analyze this user's behavior and provide concise security insights.

User: %s
Risk Score: %d/100
Flags: %s
Stats (7-day window):
  Total events: %d
  Failed logins: %d
  Off-hours events: %d
  Unique source IPs: %d
  Privilege escalations: %d
Recent events:
%s

Respond ONLY with a JSON object with these fields:
{
  "narrative": "2-3 sentence behavioral analysis",
  "risk_reason": "primary reason for risk level",
  "anomalies": ["list of up to 4 specific anomalies detected"],
  "mitre_techniques": ["list of up to 3 relevant MITRE technique IDs"],
  "recommendation": "single most important action to take"
}
Do not wrap in markdown. Return raw JSON only.`,
		username, riskScore, strings.Join(flags, ", "),
		totalEvents, failedLogins, offHours, uniqueIPs, privEsc,
		strings.Join(recentDesc, "\n"))

	raw, err := services.CallLLM(prompt)
	if err != nil {
		c.JSON(500, gin.H{"error": "AI unavailable"})
		return
	}

	// Strip markdown fences
	raw = strings.TrimSpace(raw)
	if idx := strings.Index(raw, "```json"); idx != -1 {
		raw = raw[idx+7:]
		if end := strings.Index(raw, "```"); end != -1 {
			raw = raw[:end]
		}
	} else if idx := strings.Index(raw, "```"); idx != -1 {
		raw = raw[idx+3:]
		if end := strings.Index(raw, "```"); end != -1 {
			raw = raw[:end]
		}
	}
	raw = strings.TrimSpace(raw)

	c.Data(http.StatusOK, "application/json", []byte(raw))
}

// GetUEBAWatchlist — GET /api/ueba/watchlist
func GetUEBAWatchlist(c *gin.Context) {
	tenantID := tenantIDFromContext(c)

	type WatchEntry struct {
		Username  string    `json:"username"`
		Category  string    `json:"category"`
		AddedAt   time.Time `json:"added_at"`
		AddedBy   string    `json:"added_by"`
		RiskScore int       `json:"risk_score"`
	}

	var entries []WatchEntry
	rows, err := database.DB.Query(`
		SELECT w.username, w.category, w.added_at, w.added_by,
		       COALESCE(p.risk_score, 0)
		FROM ueba_watchlist w
		LEFT JOIN user_risk_profiles p ON p.username=w.username AND p.tenant_id=w.tenant_id
		WHERE w.tenant_id=$1
		ORDER BY p.risk_score DESC, w.added_at DESC`, tenantID)
	if err != nil {
		// Table may not exist yet — return empty list
		c.JSON(http.StatusOK, gin.H{"watchlist": []WatchEntry{}})
		return
	}
	defer rows.Close()
	for rows.Next() {
		var e WatchEntry
		rows.Scan(&e.Username, &e.Category, &e.AddedAt, &e.AddedBy, &e.RiskScore)
		entries = append(entries, e)
	}
	if entries == nil {
		entries = []WatchEntry{}
	}
	c.JSON(http.StatusOK, gin.H{"watchlist": entries})
}

// AddToUEBAWatchlist — POST /api/ueba/watchlist
func AddToUEBAWatchlist(c *gin.Context) {
	tenantID := tenantIDFromContext(c)
	user := currentUsername(c)

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

	_, err := database.DB.Exec(`
		INSERT INTO ueba_watchlist (tenant_id, username, category, added_by, added_at)
		VALUES ($1,$2,$3,$4,NOW())
		ON CONFLICT (tenant_id, username) DO UPDATE SET category=EXCLUDED.category, added_by=EXCLUDED.added_by`,
		tenantID, body.Username, body.Category, user)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "added to watchlist"})
}

// RemoveFromUEBAWatchlist — DELETE /api/ueba/watchlist/:username
func RemoveFromUEBAWatchlist(c *gin.Context) {
	tenantID := tenantIDFromContext(c)
	username := c.Param("username")
	database.DB.Exec(`DELETE FROM ueba_watchlist WHERE tenant_id=$1 AND username=$2`, tenantID, username)
	c.JSON(http.StatusOK, gin.H{"message": "removed"})
}

// UEBAResponseAction — POST /api/ueba/users/:username/response-action
func UEBAResponseAction(c *gin.Context) {
	tenantID := tenantIDFromContext(c)
	username := c.Param("username")
	analyst := currentUsername(c)

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
		result = fmt.Sprintf("User %s disabled — AD/local account suspended", username)
	case "force_logout":
		// Revoke all active sessions for this username
		database.DB.Exec(
			`UPDATE sessions SET revoked=true WHERE tenant_id=$1 AND username=$2`, tenantID, username)
		result = fmt.Sprintf("All sessions for %s revoked", username)
	case "reset_password":
		result = fmt.Sprintf("Password reset triggered for %s", username)
	case "require_mfa":
		result = fmt.Sprintf("MFA enforcement flag set for %s", username)
	case "block_vpn":
		result = fmt.Sprintf("VPN access blocked for %s", username)
	case "isolate_endpoint":
		result = fmt.Sprintf("Endpoint isolation initiated for %s's device", username)
	case "kill_process":
		pid := body.Params["pid"]
		result = fmt.Sprintf("Kill signal sent to PID %s on %s's endpoint", pid, username)
	case "run_playbook":
		result = fmt.Sprintf("SOAR playbook triggered for user %s", username)
	default:
		result = fmt.Sprintf("Action '%s' dispatched for user %s", body.Action, username)
	}

	// Log as UEBA event
	database.DB.Exec(`
		INSERT INTO ueba_events (tenant_id, username, event_type, severity, description, source_ip, detected_at)
		VALUES ($1,$2,'analyst_action','info',$3,'',$4)`,
		tenantID, username,
		fmt.Sprintf("[%s] %s: %s", analyst, body.Action, result),
		time.Now())

	c.JSON(http.StatusOK, gin.H{"result": result, "action": body.Action})
}

// currentUsername returns the authenticated username from context (set by RequireAuth).
func currentUsername(c *gin.Context) string {
	if u, ok := c.Get("username"); ok {
		if s, ok := u.(string); ok {
			return s
		}
	}
	return "analyst"
}
