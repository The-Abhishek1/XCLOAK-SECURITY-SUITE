package services

// Credential Attack Detector
//
// Detects four patterns that the per-agent brute_force_service misses
// because it only counts per-agent failure totals:
//
//  1. SSH/RDP brute force   — ≥ 20 failures from same src_ip to same agent in 5 min (T1110.001)
//  2. Password spray        — same src_ip, ≥ 5 distinct usernames with failures in 5 min (T1110.003)
//  3. Credential stuffing   — same username targeted by ≥ 5 distinct src_ips in 10 min (T1110.004)
//  4. Brute-force success   — src_ip had failures then a successful auth in the same window (T1110)
//
// Runs on a 5-minute scheduler per tenant. Uses parsed_fields JSONB columns
// for auth_result, src_ip, and user — populated by the log normaliser for
// CEF, LEEF, JSON, and syslog formats.

import (
	"fmt"
	"log"
	"time"

	"xcloak-platform/database"
	"xcloak-platform/models"
)

const (
	credBruteThreshold    = 20  // failures from one src_ip per agent per window
	credSprayThreshold    = 5   // distinct usernames from one src_ip per window
	credStuffThreshold    = 5   // distinct src_ips hitting same username per window
	credBruteWindow       = "5 minutes"
	credStuffWindow       = "10 minutes"
	credAlertCooldown     = 30 * time.Minute
)

// credDedup prevents re-alerting on the same pattern within cooldown.
// key: "tenantID:pattern:subject"  value: last alert time
var credDedup = newTTLMap(credAlertCooldown)

func StartCredentialAttackScheduler() {
	go func() {
		time.Sleep(2 * time.Minute)
		for {
			runCredentialAttackDetection()
			time.Sleep(5 * time.Minute)
		}
	}()
}

func runCredentialAttackDetection() {
	rows, err := database.DB.Query(`SELECT id FROM tenants WHERE is_active = true`)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var tid int
		if rows.Scan(&tid) == nil {
			detectBruteForcePerIP(tid)
			detectPasswordSpray(tid)
			detectCredentialStuffing(tid)
			detectBruteForceSuccess(tid)
		}
	}
}

// ── 1. SSH/RDP brute force — many failures from same src_ip to same agent ──

func detectBruteForcePerIP(tenantID int) {
	rows, err := database.DB.Query(`
		SELECT el.agent_id,
		       el.parsed_fields->>'src_ip' AS src_ip,
		       COUNT(*)                    AS fail_count
		FROM endpoint_logs el
		JOIN agents a ON a.id = el.agent_id AND a.tenant_id = $1
		WHERE el.parsed_fields->>'auth_result' = 'failure'
		  AND el.created_at > NOW() - INTERVAL '`+credBruteWindow+`'
		GROUP BY el.agent_id, src_ip
		HAVING COUNT(*) >= $2
	`, tenantID, credBruteThreshold)
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var agentID, failCount int
		var srcIP string
		if rows.Scan(&agentID, &srcIP, &failCount) != nil {
			continue
		}
		key := fmt.Sprintf("%d:bruteforce:%s:%d", tenantID, srcIP, agentID)
		if credDedup.touched(key) {
			continue
		}
		credDedup.touch(key)
		msg := fmt.Sprintf("Brute force detected: %d auth failures from %s to agent %d in %s",
			failCount, srcIP, agentID, credBruteWindow)
		log.Printf("[CredAttack] %s", msg)
		CreateAlert(models.Alert{
			AgentID:        agentID,
			TenantID:       tenantID,
			Severity:       "high",
			RuleName:       "Brute Force Attack — Source IP",
			LogMessage:     msg,
			MitreTactic:    "Credential Access",
			MitreTechnique: "T1110.001",
			MitreName:      "Password Guessing",
			Fingerprint:    fmt.Sprintf("cred-bruteforce-%d-%s", agentID, srcIP),
		})
	}
}

// ── 2. Password spray — one src_ip tries many distinct usernames ─────────────

func detectPasswordSpray(tenantID int) {
	rows, err := database.DB.Query(`
		SELECT el.agent_id,
		       el.parsed_fields->>'src_ip'   AS src_ip,
		       COUNT(DISTINCT el.parsed_fields->>'user') AS user_count
		FROM endpoint_logs el
		JOIN agents a ON a.id = el.agent_id AND a.tenant_id = $1
		WHERE el.parsed_fields->>'auth_result' = 'failure'
		  AND el.parsed_fields->>'user'     IS NOT NULL
		  AND el.parsed_fields->>'src_ip'   IS NOT NULL
		  AND el.created_at > NOW() - INTERVAL '`+credBruteWindow+`'
		GROUP BY el.agent_id, src_ip
		HAVING COUNT(DISTINCT el.parsed_fields->>'user') >= $2
	`, tenantID, credSprayThreshold)
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var agentID, userCount int
		var srcIP string
		if rows.Scan(&agentID, &srcIP, &userCount) != nil {
			continue
		}
		key := fmt.Sprintf("%d:spray:%s", tenantID, srcIP)
		if credDedup.touched(key) {
			continue
		}
		credDedup.touch(key)
		msg := fmt.Sprintf("Password spray detected: %s tried %d distinct usernames with failures in %s",
			srcIP, userCount, credBruteWindow)
		log.Printf("[CredAttack] %s", msg)
		CreateAlert(models.Alert{
			AgentID:        agentID,
			TenantID:       tenantID,
			Severity:       "high",
			RuleName:       "Password Spray Attack",
			LogMessage:     msg,
			MitreTactic:    "Credential Access",
			MitreTechnique: "T1110.003",
			MitreName:      "Password Spraying",
			Fingerprint:    fmt.Sprintf("cred-spray-%s", srcIP),
		})
	}
}

// ── 3. Credential stuffing — one username targeted by many distinct IPs ──────

func detectCredentialStuffing(tenantID int) {
	rows, err := database.DB.Query(`
		SELECT el.agent_id,
		       el.parsed_fields->>'user'    AS username,
		       COUNT(DISTINCT el.parsed_fields->>'src_ip') AS ip_count
		FROM endpoint_logs el
		JOIN agents a ON a.id = el.agent_id AND a.tenant_id = $1
		WHERE el.parsed_fields->>'auth_result' = 'failure'
		  AND el.parsed_fields->>'user'     IS NOT NULL
		  AND el.parsed_fields->>'src_ip'   IS NOT NULL
		  AND el.created_at > NOW() - INTERVAL '`+credStuffWindow+`'
		GROUP BY el.agent_id, username
		HAVING COUNT(DISTINCT el.parsed_fields->>'src_ip') >= $2
	`, tenantID, credStuffThreshold)
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var agentID, ipCount int
		var username string
		if rows.Scan(&agentID, &username, &ipCount) != nil {
			continue
		}
		key := fmt.Sprintf("%d:stuffing:%s", tenantID, username)
		if credDedup.touched(key) {
			continue
		}
		credDedup.touch(key)
		msg := fmt.Sprintf("Credential stuffing detected: account '%s' targeted from %d distinct IPs in %s",
			username, ipCount, credStuffWindow)
		log.Printf("[CredAttack] %s", msg)
		CreateAlert(models.Alert{
			AgentID:        agentID,
			TenantID:       tenantID,
			Severity:       "high",
			RuleName:       "Credential Stuffing",
			LogMessage:     msg,
			MitreTactic:    "Credential Access",
			MitreTechnique: "T1110.004",
			MitreName:      "Credential Stuffing",
			Fingerprint:    fmt.Sprintf("cred-stuffing-%s", username),
		})
	}
}

// ── 4. Brute-force success — src_ip had failures then a success ───────────────

func detectBruteForceSuccess(tenantID int) {
	// Find src_ips that had both failures AND a success in the same window.
	rows, err := database.DB.Query(`
		WITH auth_events AS (
			SELECT el.agent_id,
			       el.parsed_fields->>'src_ip'      AS src_ip,
			       el.parsed_fields->>'auth_result' AS result,
			       el.parsed_fields->>'user'        AS username
			FROM endpoint_logs el
			JOIN agents a ON a.id = el.agent_id AND a.tenant_id = $1
			WHERE el.parsed_fields->>'auth_result' IN ('failure','success')
			  AND el.parsed_fields->>'src_ip' IS NOT NULL
			  AND el.created_at > NOW() - INTERVAL '`+credBruteWindow+`'
		)
		SELECT agent_id, src_ip,
		       MAX(CASE WHEN result='success' THEN username END) AS succ_user,
		       SUM(CASE WHEN result='failure' THEN 1 ELSE 0 END) AS fail_count
		FROM auth_events
		GROUP BY agent_id, src_ip
		HAVING SUM(CASE WHEN result='failure' THEN 1 ELSE 0 END) >= 3
		   AND SUM(CASE WHEN result='success' THEN 1 ELSE 0 END) >= 1
	`, tenantID)
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var agentID, failCount int
		var srcIP string
		var succUser *string
		if rows.Scan(&agentID, &srcIP, &succUser, &failCount) != nil {
			continue
		}
		key := fmt.Sprintf("%d:brutesucc:%s", tenantID, srcIP)
		if credDedup.touched(key) {
			continue
		}
		credDedup.touch(key)
		user := ""
		if succUser != nil {
			user = " as user '" + *succUser + "'"
		}
		msg := fmt.Sprintf("Possible successful brute force: %s authenticated%s after %d failures in %s",
			srcIP, user, failCount, credBruteWindow)
		log.Printf("[CredAttack] %s", msg)
		CreateAlert(models.Alert{
			AgentID:        agentID,
			TenantID:       tenantID,
			Severity:       "critical",
			RuleName:       "Successful Brute Force",
			LogMessage:     msg,
			MitreTactic:    "Credential Access",
			MitreTechnique: "T1110",
			MitreName:      "Brute Force",
			Fingerprint:    fmt.Sprintf("cred-brutesucc-%s", srcIP),
		})
	}
}
