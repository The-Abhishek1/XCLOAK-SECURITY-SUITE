package services

// Identity Threat Detection & Response (ITDR) — closes the gap vs
// CrowdStrike Identity Protection, SentinelOne Singularity Identity, and
// Microsoft Entra ID Protection.
//
// Seven detection categories run every 15 minutes per tenant:
//
//  1. stale_account       — endpoint user seen >90 days ago, still logging in recently
//  2. dormant_admin       — XCloak portal admin with no login in >30 days
//  3. mfa_gap             — admin/analyst portal user with TOTP disabled
//  4. shadow_admin        — account added to privileged AD group (event IDs 4728/4732/4756)
//  5. password_spray      — single source IP hitting ≥5 distinct accounts in 30 min
//  6. mfa_fatigue         — same portal user receiving ≥5 failed TOTP attempts in 1 hour
//  7. lateral_movement_id — same account authenticating to ≥4 distinct hosts in 5 min
//
// All findings are deduplicated via itdr_findings.dedup_key so the same
// condition does not generate duplicate open findings within a 24-hour window.

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"xcloak-platform/database"
)

// Finding types — keep in sync with the frontend filter list.
const (
	ITDRStaleAccount      = "stale_account"
	ITDRDormantAdmin      = "dormant_admin"
	ITDRMFAGap            = "mfa_gap"
	ITDRShadowAdmin       = "shadow_admin"
	ITDRPasswordSpray     = "password_spray"
	ITDRMFAFatigue        = "mfa_fatigue"
	ITDRLateralMovementID = "lateral_movement_id"
)

// itdrFinding is the internal representation before DB insertion.
type itdrFinding struct {
	findingType    string
	severity       string
	identity       string
	identityType   string
	sourceIP       string
	description    string
	evidence       map[string]any
	mitreTechnique string
	agentID        *int
	dedupKey       string
}

// RunITDRAnalysis runs all detections for one tenant and upserts findings.
func RunITDRAnalysis(tenantID int) {
	findings := []itdrFinding{}

	findings = append(findings, itdrPasswordSpray(tenantID)...)
	findings = append(findings, detectShadowAdmins(tenantID)...)
	findings = append(findings, detectLateralMovementID(tenantID)...)
	findings = append(findings, detectStaleAccounts(tenantID)...)
	findings = append(findings, detectDormantAdmins(tenantID)...)
	findings = append(findings, detectMFAGaps(tenantID)...)
	findings = append(findings, detectMFAFatigue(tenantID)...)

	for _, f := range findings {
		if err := upsertITDRFinding(tenantID, f); err != nil {
			log.Printf("[itdr] tenant %d upsert error (%s / %s): %v",
				tenantID, f.findingType, f.identity, err)
		}
	}
}

// upsertITDRFinding inserts a finding unless an open finding with the same
// dedup_key already exists for this tenant.
func upsertITDRFinding(tenantID int, f itdrFinding) error {
	evidenceJSON, err := json.Marshal(f.evidence)
	if err != nil {
		evidenceJSON = []byte("{}")
	}

	sourceIP := f.sourceIP
	_, err = database.DB.Exec(`
		INSERT INTO itdr_findings
			(tenant_id, finding_type, severity, identity, identity_type,
			 source_ip, description, evidence, mitre_technique,
			 status, agent_id, dedup_key)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'open',$10,$11)
		ON CONFLICT (tenant_id, dedup_key)
			WHERE status NOT IN ('resolved','false_positive')
		DO NOTHING
	`,
		tenantID, f.findingType, f.severity, f.identity, f.identityType,
		nilIfEmpty(sourceIP), f.description, evidenceJSON, nilIfEmpty(f.mitreTechnique),
		f.agentID, f.dedupKey,
	)
	return err
}

func nilIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// ── 1. Password spray ─────────────────────────────────────────────────────────
// Same source IP hits ≥5 distinct user accounts with auth failures in 30 min.
// MITRE T1110.003 — Password Spraying

func itdrPasswordSpray(tenantID int) []itdrFinding {
	rows, err := database.RDB().Query(`
		SELECT
			el.parsed_fields->>'src_ip'       AS src_ip,
			COUNT(DISTINCT lower(el.parsed_fields->>'user')) AS distinct_users,
			COUNT(*)                           AS total_failures,
			array_agg(DISTINCT lower(el.parsed_fields->>'user')) AS accounts
		FROM endpoint_logs el
		JOIN agents a ON a.id = el.agent_id AND a.tenant_id = $1
		WHERE el.created_at > NOW() - INTERVAL '30 minutes'
		  AND el.parsed_fields->>'src_ip' IS NOT NULL
		  AND el.parsed_fields->>'src_ip' != ''
		  AND (
		      el.event_id = '4625'
		   OR lower(el.parsed_fields->>'event_type') = 'auth_failure'
		   OR lower(el.parsed_fields->>'event_type') = 'authentication_failure'
		  )
		  AND lower(COALESCE(el.parsed_fields->>'user','')) NOT IN
		      ('', 'unknown', 'system', 'local service', 'network service')
		GROUP BY src_ip
		HAVING COUNT(DISTINCT lower(el.parsed_fields->>'user')) >= 5
	`, tenantID)
	if err != nil {
		return nil
	}
	defer rows.Close()

	findings := []itdrFinding{}
	for rows.Next() {
		var srcIP string
		var distinctUsers, totalFailures int
		accountsJSON := []byte{}
		if err := rows.Scan(&srcIP, &distinctUsers, &totalFailures, &accountsJSON); err != nil {
			continue
		}
		sev := "high"
		if distinctUsers >= 20 {
			sev = "critical"
		}
		findings = append(findings, itdrFinding{
			findingType:    ITDRPasswordSpray,
			severity:       sev,
			identity:       srcIP,
			identityType:   "endpoint",
			sourceIP:       srcIP,
			description:    fmt.Sprintf("Password spray: %d failed auth attempts against %d distinct accounts from %s in 30 min", totalFailures, distinctUsers, srcIP),
			evidence:       map[string]any{"distinct_users": distinctUsers, "total_failures": totalFailures, "src_ip": srcIP},
			mitreTechnique: "T1110.003",
			dedupKey:       fmt.Sprintf("spray:%s", srcIP),
		})
	}
	return findings
}

// ── 2. Shadow admin ───────────────────────────────────────────────────────────
// Account added to a privileged group (domain/enterprise/schema admins).
// MITRE T1098 — Account Manipulation

var privilegedGroupKeywords = []string{
	"domain admin", "domain admins",
	"enterprise admin", "enterprise admins",
	"schema admin", "schema admins",
	"administrators",
	"account operators",
	"backup operators",
}

func detectShadowAdmins(tenantID int) []itdrFinding {
	rows, err := database.RDB().Query(`
		SELECT
			lower(el.parsed_fields->>'target_user') AS target_user,
			el.parsed_fields->>'group_name'          AS group_name,
			el.parsed_fields->>'subject_user'        AS added_by,
			el.agent_id,
			el.created_at
		FROM endpoint_logs el
		JOIN agents a ON a.id = el.agent_id AND a.tenant_id = $1
		WHERE el.event_id IN ('4728','4732','4756')
		  AND el.created_at > NOW() - INTERVAL '24 hours'
		  AND (
		      lower(el.parsed_fields->>'group_name') LIKE '%admin%'
		   OR lower(el.parsed_fields->>'group_name') LIKE '%operator%'
		  )
	`, tenantID)
	if err != nil {
		return nil
	}
	defer rows.Close()

	findings := []itdrFinding{}
	for rows.Next() {
		var targetUser, groupName, addedBy string
		var agentID int
		var createdAt time.Time
		if err := rows.Scan(&targetUser, &groupName, &addedBy, &agentID, &createdAt); err != nil {
			continue
		}
		if !isPrivilegedGroup(groupName) {
			continue
		}
		findings = append(findings, itdrFinding{
			findingType:    ITDRShadowAdmin,
			severity:       "high",
			identity:       targetUser,
			identityType:   "endpoint",
			description:    fmt.Sprintf("Account '%s' was added to privileged group '%s' by '%s'", targetUser, groupName, addedBy),
			evidence:       map[string]any{"group_name": groupName, "added_by": addedBy, "event_time": createdAt},
			mitreTechnique: "T1098",
			agentID:        &agentID,
			dedupKey:       fmt.Sprintf("shadow:%s:%s", targetUser, strings.ToLower(groupName)),
		})
	}
	return findings
}

func isPrivilegedGroup(name string) bool {
	n := strings.ToLower(name)
	for _, kw := range privilegedGroupKeywords {
		if strings.Contains(n, kw) {
			return true
		}
	}
	return false
}

// ── 3. Lateral movement via identity ─────────────────────────────────────────
// Same account authenticates to ≥4 distinct hosts within 5 minutes.
// MITRE T1550 — Use Alternate Authentication Material

func detectLateralMovementID(tenantID int) []itdrFinding {
	rows, err := database.RDB().Query(`
		SELECT
			lower(el.parsed_fields->>'user')      AS username,
			COUNT(DISTINCT el.agent_id)           AS distinct_hosts,
			MIN(el.created_at)                    AS first_seen,
			MAX(el.created_at)                    AS last_seen
		FROM endpoint_logs el
		JOIN agents a ON a.id = el.agent_id AND a.tenant_id = $1
		WHERE el.event_id IN ('4624','4648')
		  AND el.created_at > NOW() - INTERVAL '5 minutes'
		  AND lower(COALESCE(el.parsed_fields->>'user',''))
		      NOT IN ('','system','local service','network service','anonymous logon')
		GROUP BY username
		HAVING COUNT(DISTINCT el.agent_id) >= 4
	`, tenantID)
	if err != nil {
		return nil
	}
	defer rows.Close()

	findings := []itdrFinding{}
	for rows.Next() {
		var username string
		var distinctHosts int
		var firstSeen, lastSeen time.Time
		if err := rows.Scan(&username, &distinctHosts, &firstSeen, &lastSeen); err != nil {
			continue
		}
		sev := "high"
		if distinctHosts >= 8 {
			sev = "critical"
		}
		findings = append(findings, itdrFinding{
			findingType:    ITDRLateralMovementID,
			severity:       sev,
			identity:       username,
			identityType:   "endpoint",
			description:    fmt.Sprintf("Account '%s' authenticated to %d distinct hosts in under 5 minutes — possible lateral movement", username, distinctHosts),
			evidence:       map[string]any{"distinct_hosts": distinctHosts, "window_start": firstSeen, "window_end": lastSeen},
			mitreTechnique: "T1550",
			dedupKey:       fmt.Sprintf("lateral:%s", username),
		})
	}
	return findings
}

// ── 4. Stale accounts ─────────────────────────────────────────────────────────
// Endpoint user accounts that were active 90–365 days ago but have had zero
// logon events since. Stale enabled accounts are a dwell-time gift for attackers.
// MITRE T1078 — Valid Accounts

func detectStaleAccounts(tenantID int) []itdrFinding {
	rows, err := database.RDB().Query(`
		SELECT
			lower(el.parsed_fields->>'user') AS username,
			MAX(el.created_at)               AS last_seen,
			COUNT(DISTINCT el.agent_id)      AS host_count
		FROM endpoint_logs el
		JOIN agents a ON a.id = el.agent_id AND a.tenant_id = $1
		WHERE el.event_id IN ('4624','4648')
		  AND lower(COALESCE(el.parsed_fields->>'user',''))
		      NOT IN ('','system','local service','network service','anonymous logon')
		GROUP BY username
		HAVING MAX(el.created_at) < NOW() - INTERVAL '90 days'
		   AND MAX(el.created_at) > NOW() - INTERVAL '365 days'
		LIMIT 100
	`, tenantID)
	if err != nil {
		return nil
	}
	defer rows.Close()

	findings := []itdrFinding{}
	for rows.Next() {
		var username string
		var lastSeen time.Time
		var hostCount int
		if err := rows.Scan(&username, &lastSeen, &hostCount); err != nil {
			continue
		}
		daysSince := int(time.Since(lastSeen).Hours() / 24)
		sev := "low"
		if daysSince > 180 {
			sev = "medium"
		}
		findings = append(findings, itdrFinding{
			findingType:    ITDRStaleAccount,
			severity:       sev,
			identity:       username,
			identityType:   "endpoint",
			description:    fmt.Sprintf("Account '%s' has not logged on in %d days (last seen %s) — stale account is an unnecessary attack surface", username, daysSince, lastSeen.Format("2006-01-02")),
			evidence:       map[string]any{"last_seen": lastSeen, "days_inactive": daysSince, "host_count": hostCount},
			mitreTechnique: "T1078",
			dedupKey:       fmt.Sprintf("stale:%s", username),
		})
	}
	return findings
}

// ── 5. Dormant portal admins ──────────────────────────────────────────────────
// XCloak admin/super_admin users who haven't logged into the portal in >30 days.
// Dormant admin accounts should be disabled or rotated promptly.
// MITRE T1078 — Valid Accounts

func detectDormantAdmins(tenantID int) []itdrFinding {
	rows, err := database.RDB().Query(`
		SELECT username, email, role, last_login
		FROM users
		WHERE tenant_id = $1
		  AND role IN ('admin','super_admin')
		  AND is_active = TRUE
		  AND last_login IS NOT NULL
		  AND last_login < NOW() - INTERVAL '30 days'
	`, tenantID)
	if err != nil {
		return nil
	}
	defer rows.Close()

	findings := []itdrFinding{}
	for rows.Next() {
		var username, email, role string
		var lastLogin time.Time
		if err := rows.Scan(&username, &email, &role, &lastLogin); err != nil {
			continue
		}
		daysSince := int(time.Since(lastLogin).Hours() / 24)
		sev := "medium"
		if daysSince >= 90 {
			sev = "high"
		}
		findings = append(findings, itdrFinding{
			findingType:    ITDRDormantAdmin,
			severity:       sev,
			identity:       email,
			identityType:   "portal",
			description:    fmt.Sprintf("Portal admin '%s' (%s) has not logged in for %d days — dormant privileged accounts should be disabled or rotated", username, role, daysSince),
			evidence:       map[string]any{"username": username, "role": role, "last_login": lastLogin, "days_inactive": daysSince},
			mitreTechnique: "T1078",
			dedupKey:       fmt.Sprintf("dormant-admin:%s", email),
		})
	}
	return findings
}

// ── 6. MFA gaps ───────────────────────────────────────────────────────────────
// XCloak admin/analyst users who have not enrolled TOTP.
// Privileged portal accounts without MFA are a critical exposure.

func detectMFAGaps(tenantID int) []itdrFinding {
	rows, err := database.RDB().Query(`
		SELECT username, email, role
		FROM users
		WHERE tenant_id = $1
		  AND role IN ('admin','super_admin','analyst')
		  AND is_active = TRUE
		  AND (totp_enabled = FALSE OR totp_verified = FALSE)
	`, tenantID)
	if err != nil {
		return nil
	}
	defer rows.Close()

	findings := []itdrFinding{}
	for rows.Next() {
		var username, email, role string
		if err := rows.Scan(&username, &email, &role); err != nil {
			continue
		}
		sev := "medium"
		if role == "admin" || role == "super_admin" {
			sev = "high"
		}
		findings = append(findings, itdrFinding{
			findingType:    ITDRMFAGap,
			severity:       sev,
			identity:       email,
			identityType:   "portal",
			description:    fmt.Sprintf("Portal user '%s' (%s) has not enrolled MFA — privileged accounts without MFA are high-risk", username, role),
			evidence:       map[string]any{"username": username, "role": role},
			mitreTechnique: "T1078",
			dedupKey:       fmt.Sprintf("mfa-gap:%s", email),
		})
	}
	return findings
}

// ── 7. MFA fatigue ────────────────────────────────────────────────────────────
// Same portal user receives ≥5 failed TOTP verification attempts in 1 hour.
// Attackers use MFA fatigue / push bombing to wear down targets.
// MITRE T1621 — Multi-Factor Authentication Request Generation

func detectMFAFatigue(tenantID int) []itdrFinding {
	rows, err := database.RDB().Query(`
		SELECT
			lower(al.details->>'email')  AS email,
			COUNT(*)                     AS failed_attempts,
			MIN(al.created_at)           AS first_attempt,
			MAX(al.created_at)           AS last_attempt
		FROM audit_logs al
		WHERE al.tenant_id = $1
		  AND al.action     = 'TOTP_VERIFY_FAIL'
		  AND al.created_at > NOW() - INTERVAL '1 hour'
		  AND al.details->>'email' IS NOT NULL
		GROUP BY email
		HAVING COUNT(*) >= 5
	`, tenantID)
	if err != nil {
		return nil
	}
	defer rows.Close()

	findings := []itdrFinding{}
	for rows.Next() {
		var email string
		var failedAttempts int
		var firstAttempt, lastAttempt time.Time
		if err := rows.Scan(&email, &failedAttempts, &firstAttempt, &lastAttempt); err != nil {
			continue
		}
		sev := "high"
		if failedAttempts >= 15 {
			sev = "critical"
		}
		findings = append(findings, itdrFinding{
			findingType:    ITDRMFAFatigue,
			severity:       sev,
			identity:       email,
			identityType:   "portal",
			description:    fmt.Sprintf("MFA fatigue attack: %d failed TOTP attempts for '%s' in 1 hour — possible push bombing", failedAttempts, email),
			evidence:       map[string]any{"failed_attempts": failedAttempts, "first_attempt": firstAttempt, "last_attempt": lastAttempt},
			mitreTechnique: "T1621",
			dedupKey:       fmt.Sprintf("mfa-fatigue:%s", email),
		})
	}
	return findings
}
