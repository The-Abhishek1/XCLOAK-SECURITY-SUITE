package services

// Insider Threat Score Engine
//
// Computes a daily risk score (0–100) for every active user within a tenant
// by aggregating signals across six categories. The score is stored in
// insider_threat_scores and an alert is fired when a user crosses 70 (high).
//
// Signal categories and max contribution:
//
//   off_hours_auth     (20) — successful logins between 22:00–06:00 UTC
//   failed_auth        (15) — repeated auth failures (credential misuse)
//   data_exfil         (25) — large bytes_sent, cloud storage access
//   sensitive_access   (15) — access to files/paths flagged as sensitive
//   privesc_attempt    (15) — privilege escalation alerts for this user
//   anomalous_location (10) — impossible travel or new country login
//
// Total max = 100. Score → risk_level:
//   0–29  = low
//   30–59 = medium
//   60–79 = high
//   80+   = critical
//
// Alert threshold: score >= 60 (high). Runs every 6 hours per tenant.
// Retains 90 days of history.
// MITRE: T1078 (Valid Accounts), T1530 (Data from Cloud Storage Object)

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	"xcloak-platform/database"
	"xcloak-platform/models"
)

func StartInsiderThreatScheduler() {
	go func() {
		// Run 10 minutes after startup, then every 6 hours
		time.Sleep(10 * time.Minute)
		for {
			runInsiderThreatScoring()
			time.Sleep(6 * time.Hour)
		}
	}()
}

func runInsiderThreatScoring() {
	rows, err := database.DB.Query(`SELECT id FROM tenants WHERE is_active = true`)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var tid int
		if rows.Scan(&tid) == nil {
			scoreInsiderThreatsForTenant(tid)
		}
	}
	// Prune old scores > 90 days
	database.DB.Exec(`DELETE FROM insider_threat_scores WHERE score_date < CURRENT_DATE - 90`)
}

func scoreInsiderThreatsForTenant(tenantID int) {
	// Collect all active usernames seen in the last 24 hours for this tenant
	rows, err := database.DB.Query(`
		SELECT DISTINCT el.parsed_fields->>'user' AS username
		FROM endpoint_logs el
		JOIN agents a ON a.id = el.agent_id AND a.tenant_id = $1
		WHERE el.parsed_fields->>'user' IS NOT NULL
		  AND el.parsed_fields->>'user' != ''
		  AND el.collected_at > NOW() - INTERVAL '24 hours'
	`, tenantID)
	if err != nil {
		return
	}
	defer rows.Close()

	var users []string
	for rows.Next() {
		var u string
		if rows.Scan(&u) == nil && u != "" {
			users = append(users, u)
		}
	}
	rows.Close()

	for _, username := range users {
		score, contributors := computeInsiderScore(tenantID, username)
		if score == 0 {
			continue
		}
		saveInsiderScore(tenantID, username, score, contributors)
	}
}

type insiderContributors struct {
	OffHoursAuth     int `json:"off_hours_auth"`
	FailedAuth       int `json:"failed_auth"`
	DataExfil        int `json:"data_exfil"`
	SensitiveAccess  int `json:"sensitive_access"`
	PrivescAttempt   int `json:"privesc_attempt"`
	AnomalousLocation int `json:"anomalous_location"`
}

func computeInsiderScore(tenantID int, username string) (int, insiderContributors) {
	var c insiderContributors

	// ── Signal 1: Off-hours authentication (max 20) ───────────────────────
	var offHoursCount int
	database.DB.QueryRow(`
		SELECT COUNT(*)
		FROM endpoint_logs el
		JOIN agents a ON a.id = el.agent_id AND a.tenant_id = $1
		WHERE el.parsed_fields->>'user' = $2
		  AND el.parsed_fields->>'auth_result' = 'success'
		  AND (EXTRACT(HOUR FROM el.collected_at AT TIME ZONE 'UTC') < 6
		    OR EXTRACT(HOUR FROM el.collected_at AT TIME ZONE 'UTC') >= 22)
		  AND el.collected_at > NOW() - INTERVAL '24 hours'
	`, tenantID, username).Scan(&offHoursCount)
	if offHoursCount >= 3 {
		c.OffHoursAuth = 20
	} else if offHoursCount >= 1 {
		c.OffHoursAuth = 10
	}

	// ── Signal 2: Repeated auth failures (max 15) ─────────────────────────
	var failedAuthCount int
	database.DB.QueryRow(`
		SELECT COUNT(*)
		FROM endpoint_logs el
		JOIN agents a ON a.id = el.agent_id AND a.tenant_id = $1
		WHERE el.parsed_fields->>'user' = $2
		  AND el.parsed_fields->>'auth_result' = 'failure'
		  AND el.collected_at > NOW() - INTERVAL '24 hours'
	`, tenantID, username).Scan(&failedAuthCount)
	if failedAuthCount >= 20 {
		c.FailedAuth = 15
	} else if failedAuthCount >= 10 {
		c.FailedAuth = 10
	} else if failedAuthCount >= 5 {
		c.FailedAuth = 5
	}

	// ── Signal 3: Data exfiltration indicators (max 25) ───────────────────
	var totalBytesSent int64
	database.DB.QueryRow(`
		SELECT COALESCE(SUM((el.parsed_fields->>'bytes_sent')::bigint), 0)
		FROM endpoint_logs el
		JOIN agents a ON a.id = el.agent_id AND a.tenant_id = $1
		WHERE el.parsed_fields->>'user' = $2
		  AND el.parsed_fields->>'bytes_sent' IS NOT NULL
		  AND el.collected_at > NOW() - INTERVAL '24 hours'
	`, tenantID, username).Scan(&totalBytesSent)
	const (
		exfilMedium   = 50 * 1024 * 1024   // 50 MB
		exfilHigh     = 200 * 1024 * 1024  // 200 MB
		exfilCritical = 500 * 1024 * 1024  // 500 MB
	)
	if totalBytesSent >= exfilCritical {
		c.DataExfil = 25
	} else if totalBytesSent >= exfilHigh {
		c.DataExfil = 15
	} else if totalBytesSent >= exfilMedium {
		c.DataExfil = 8
	}

	// ── Signal 4: Sensitive path/file access (max 15) ─────────────────────
	var sensitiveCount int
	database.DB.QueryRow(`
		SELECT COUNT(*)
		FROM fim_alerts fa
		JOIN agents a ON a.id = fa.agent_id AND a.tenant_id = $1
		WHERE fa.created_at > NOW() - INTERVAL '24 hours'
		  AND (lower(fa.file_path) LIKE '%/etc/passwd%'
		    OR lower(fa.file_path) LIKE '%/etc/shadow%'
		    OR lower(fa.file_path) LIKE '%/.ssh/%'
		    OR lower(fa.file_path) LIKE '%id_rsa%'
		    OR lower(fa.file_path) LIKE '%credentials%'
		    OR lower(fa.file_path) LIKE '%secret%'
		    OR lower(fa.file_path) LIKE '%.pem'
		    OR lower(fa.file_path) LIKE '%.key')
	`, tenantID).Scan(&sensitiveCount)
	// Note: can't easily tie FIM to username without additional context,
	// so this is a tenant-wide signal weighted to users with high other scores.
	if sensitiveCount >= 5 {
		c.SensitiveAccess = 15
	} else if sensitiveCount >= 1 {
		c.SensitiveAccess = 8
	}

	// ── Signal 5: Privilege escalation alerts (max 15) ────────────────────
	var privescCount int
	database.DB.QueryRow(`
		SELECT COUNT(*)
		FROM alerts al
		JOIN agents a ON a.id = al.agent_id AND a.tenant_id = $1
		WHERE lower(al.log_message) LIKE '%' || lower($2) || '%'
		  AND al.mitre_technique IN ('T1098','T1136.001','T1548','T1548.003','T1134')
		  AND al.created_at > NOW() - INTERVAL '24 hours'
	`, tenantID, username).Scan(&privescCount)
	if privescCount >= 2 {
		c.PrivescAttempt = 15
	} else if privescCount >= 1 {
		c.PrivescAttempt = 8
	}

	// ── Signal 6: Anomalous location / impossible travel (max 10) ────────
	var travelCount int
	database.DB.QueryRow(`
		SELECT COUNT(*)
		FROM alerts al
		JOIN agents a ON a.id = al.agent_id AND a.tenant_id = $1
		WHERE lower(al.log_message) LIKE '%' || lower($2) || '%'
		  AND al.mitre_technique = 'T1078'
		  AND lower(al.rule_name) LIKE '%travel%'
		  AND al.created_at > NOW() - INTERVAL '24 hours'
	`, tenantID, username).Scan(&travelCount)
	if travelCount >= 1 {
		c.AnomalousLocation = 10
	}

	total := c.OffHoursAuth + c.FailedAuth + c.DataExfil +
		c.SensitiveAccess + c.PrivescAttempt + c.AnomalousLocation

	return total, c
}

func saveInsiderScore(tenantID int, username string, score int, c insiderContributors) {
	riskLevel := "low"
	switch {
	case score >= 80:
		riskLevel = "critical"
	case score >= 60:
		riskLevel = "high"
	case score >= 30:
		riskLevel = "medium"
	}

	contribJSON, _ := json.Marshal(c)

	_, err := database.DB.Exec(`
		INSERT INTO insider_threat_scores
		  (tenant_id, username, score_date, score, risk_level, contributors, updated_at)
		VALUES ($1, $2, CURRENT_DATE, $3, $4, $5, NOW())
		ON CONFLICT (tenant_id, username, score_date) DO UPDATE SET
		  score        = EXCLUDED.score,
		  risk_level   = EXCLUDED.risk_level,
		  contributors = EXCLUDED.contributors,
		  updated_at   = NOW()
	`, tenantID, username, score, riskLevel, contribJSON)
	if err != nil {
		log.Printf("[InsiderThreat] save failed tenant=%d user=%s: %v", tenantID, username, err)
		return
	}

	// Fire alert for high/critical users who haven't been alerted today
	if score < 60 {
		return
	}

	var alreadyFired bool
	database.DB.QueryRow(`
		SELECT alert_fired FROM insider_threat_scores
		WHERE tenant_id=$1 AND username=$2 AND score_date=CURRENT_DATE
	`, tenantID, username).Scan(&alreadyFired)
	if alreadyFired {
		return
	}

	// Resolve any agent for this tenant to attach the alert
	var agentID int
	database.DB.QueryRow(`
		SELECT id FROM agents WHERE tenant_id=$1 LIMIT 1
	`, tenantID).Scan(&agentID)

	msg := fmt.Sprintf(
		"Insider threat risk: user '%s' scored %d/100 (%s). Contributors: off-hours=%d, failed-auth=%d, data-exfil=%d, sensitive-access=%d, privesc=%d, anomalous-location=%d",
		username, score, riskLevel,
		c.OffHoursAuth, c.FailedAuth, c.DataExfil,
		c.SensitiveAccess, c.PrivescAttempt, c.AnomalousLocation,
	)
	sev := "high"
	if score >= 80 {
		sev = "critical"
	}
	log.Printf("[InsiderThreat] %s", msg)
	CreateAlert(models.Alert{
		AgentID:        agentID,
		TenantID:       tenantID,
		Severity:       sev,
		RuleName:       "Insider Threat Risk Score — " + riskLevel,
		LogMessage:     msg,
		MitreTactic:    "Exfiltration",
		MitreTechnique: "T1078",
		MitreName:      "Valid Accounts",
		Fingerprint:    fmt.Sprintf("insider-%s-%s", username, time.Now().Format("2006-01-02")),
	})

	database.DB.Exec(`
		UPDATE insider_threat_scores SET alert_fired=true
		WHERE tenant_id=$1 AND username=$2 AND score_date=CURRENT_DATE
	`, tenantID, username)
}
