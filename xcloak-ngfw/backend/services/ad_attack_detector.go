package services

// Active Directory Attack Detector
//
// Analyses Windows Security event logs to detect Active Directory-specific
// attacks. These are among the most critical to detect because AD compromise
// is the primary lateral movement path in ransomware and nation-state attacks.
//
// Detection coverage:
//
//  Kerberoasting       (T1558.003) — EventID 4769 with RC4/NTLM (0x17) encryption type;
//                                    attackers request TGS for service accounts offline-crack
//  AS-REP Roasting     (T1558.004) — EventID 4768 with PreAuthType=0; accounts that don't
//                                    require Kerberos pre-auth, attackable without credentials
//  DCSync              (T1003.006) — EventID 4662 containing DS-Replication GUIDs from
//                                    non-DC source; mimikatz/secretsdump replication attack
//  Pass-the-Hash       (T1550.002) — EventID 4624 LogonType=3 NTLM from multiple distinct
//                                    source IPs for the same account in 5 minutes
//  Pass-the-Ticket     (T1550.003) — EventID 4768/4769 without a corresponding 4771;
//                                    pattern: RC4 ticket used for non-Kerberos auth
//  BloodHound / AD Enum (T1087.002) — EventID 4688 with SharpHound/BloodHound process name,
//                                    or mass 4662 LDAP enumeration burst
//  Golden/Silver Ticket (T1558.001) — EventID 4769 with non-existent or expired account
//                                    (ticket sourced from forged PAC)
//  SID History injection (T1134.005) — EventID 4765 (SID History added to account)
//  AdminSDHolder abuse  (T1484.001) — EventID 5136 modifying the AdminSDHolder object
//  Skeleton Key         (T1556.001) — EventID 4657/4673 modifying LSASS / Kerberos provider
//  LDAP Enumeration     (T1018)     — EventID 1644 (expensive LDAP query) or mass 4662 burst
//  Kerberos Brute Force (T1110.001) — EventID 4771 (Kerberos pre-auth failures) ≥20 in 5 min
//
// Runs every 5 minutes. Dedup TTL: 30 minutes per (tenant, rule, target user).

import (
	"fmt"
	"log"
	"strings"
	"time"

	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
)

var adDedup = newTTLMap(30 * time.Minute)

func StartADAttackScheduler() {
	go func() {
		time.Sleep(90 * time.Second)
		for {
			runADAttackDetection()
			time.Sleep(5 * time.Minute)
		}
	}()
}

func runADAttackDetection() {
	rows, err := database.DB.Query(`SELECT id FROM tenants WHERE is_active = true`)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var tid int
		if rows.Scan(&tid) == nil {
			detectKerberoasting(tid)
			detectASREPRoasting(tid)
			detectDCSync(tid)
			detectPassTheHash(tid)
			detectBloodHound(tid)
			detectSIDHistoryInjection(tid)
			detectAdminSDHolderAbuse(tid)
			detectKerberosBruteForce(tid)
			detectLDAPEnumeration(tid)
		}
	}
}

// detectKerberoasting — EventID 4769 with RC4 (0x17) encryption, non-machine account.
func detectKerberoasting(tenantID int) {
	rows, err := database.DB.Query(`
		SELECT el.agent_id,
		       coalesce(el.parsed_fields->>'user','') AS target_user,
		       coalesce(el.parsed_fields->>'src_ip','') AS src_ip,
		       el.log_message
		FROM endpoint_logs el
		JOIN agents a ON a.id = el.agent_id AND a.tenant_id = $1
		WHERE el.parsed_fields->>'event_id' = '4769'
		  AND el.created_at > NOW() - INTERVAL '5 minutes'
		  AND (
		       el.log_message ILIKE '%0x17%'
		    OR el.log_message ILIKE '%0x18%'
		    OR el.log_message ILIKE '%rc4%'
		    OR el.log_message ILIKE '%arcfour%'
		  )
		  AND el.log_message NOT ILIKE '%$@%'
		LIMIT 200
	`, tenantID)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var agentID int
		var user, srcIP, msg string
		if rows.Scan(&agentID, &user, &srcIP, &msg) != nil {
			continue
		}
		// Exclude machine accounts (end with $)
		if strings.HasSuffix(strings.TrimSpace(user), "$") {
			continue
		}
		key := fmt.Sprintf("%d:kerberoast:%s:%s", tenantID, user, srcIP)
		if adDedup.touched(key) {
			continue
		}
		adDedup.touch(key)
		m := fmt.Sprintf("Kerberoasting Detected — TGS requested with RC4 encryption for user='%s' src_ip='%s' (potential offline cracking attack)", user, srcIP)
		log.Printf("[AD] %s", m)
		createADAlert(agentID, tenantID, "high", "Kerberoasting — RC4 TGS Request", m, "T1558.003", "Steal or Forge Kerberos Tickets", "Credential Access")
	}
}

// detectASREPRoasting — EventID 4768 with PreAuthType=0.
func detectASREPRoasting(tenantID int) {
	rows, err := database.DB.Query(`
		SELECT el.agent_id,
		       coalesce(el.parsed_fields->>'user','') AS user,
		       coalesce(el.parsed_fields->>'src_ip','') AS src_ip,
		       el.log_message
		FROM endpoint_logs el
		JOIN agents a ON a.id = el.agent_id AND a.tenant_id = $1
		WHERE el.parsed_fields->>'event_id' = '4768'
		  AND el.created_at > NOW() - INTERVAL '5 minutes'
		  AND (
		       el.log_message ILIKE '%pre-authentication type:%0%'
		    OR el.log_message ILIKE '%preauthtype%0%'
		    OR el.log_message ILIKE '%pre_auth_type: 0%'
		  )
		LIMIT 100
	`, tenantID)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var agentID int
		var user, srcIP, msg string
		if rows.Scan(&agentID, &user, &srcIP, &msg) != nil {
			continue
		}
		key := fmt.Sprintf("%d:asrep:%s", tenantID, user)
		if adDedup.touched(key) {
			continue
		}
		adDedup.touch(key)
		m := fmt.Sprintf("AS-REP Roasting — Account without Kerberos pre-auth requirement: user='%s' src_ip='%s'", user, srcIP)
		log.Printf("[AD] %s", m)
		createADAlert(agentID, tenantID, "high", "AS-REP Roasting — Pre-Auth Not Required", m, "T1558.004", "AS-REP Roasting", "Credential Access")
	}
}

// detectDCSync — EventID 4662 with DS-Replication GUIDs from non-DC.
// The GUIDs 1131f6aa and 1131f6ad are for DS-Replication-Get-Changes and -All.
func detectDCSync(tenantID int) {
	rows, err := database.DB.Query(`
		SELECT el.agent_id,
		       coalesce(el.parsed_fields->>'user','') AS user,
		       coalesce(el.parsed_fields->>'src_ip','') AS src_ip,
		       el.log_message
		FROM endpoint_logs el
		JOIN agents a ON a.id = el.agent_id AND a.tenant_id = $1
		WHERE el.parsed_fields->>'event_id' = '4662'
		  AND el.created_at > NOW() - INTERVAL '5 minutes'
		  AND (
		       el.log_message ILIKE '%1131f6aa%'
		    OR el.log_message ILIKE '%1131f6ad%'
		    OR el.log_message ILIKE '%1131f6ac%'
		    OR el.log_message ILIKE '%ds-replication%'
		    OR el.log_message ILIKE '%replicating-directory-changes%'
		  )
		LIMIT 100
	`, tenantID)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var agentID int
		var user, srcIP, msg string
		if rows.Scan(&agentID, &user, &srcIP, &msg) != nil {
			continue
		}
		key := fmt.Sprintf("%d:dcsync:%s:%s", tenantID, user, srcIP)
		if adDedup.touched(key) {
			continue
		}
		adDedup.touch(key)
		m := fmt.Sprintf("DCSync Attack — Replication rights exercised by user='%s' src_ip='%s' (possible mimikatz/secretsdump NTDS credential dump)", user, srcIP)
		log.Printf("[AD] %s", m)
		createADAlert(agentID, tenantID, "critical", "DCSync — Directory Replication by Non-DC", m, "T1003.006", "DCSync", "Credential Access")
	}
}

// detectPassTheHash — EventID 4624 LogonType=3 NTLM from ≥3 distinct IPs for same account.
func detectPassTheHash(tenantID int) {
	rows, err := database.DB.Query(`
		SELECT el.agent_id,
		       el.parsed_fields->>'user' AS target_user,
		       COUNT(DISTINCT el.parsed_fields->>'src_ip') AS ip_count,
		       string_agg(DISTINCT el.parsed_fields->>'src_ip', ', ') AS src_ips
		FROM endpoint_logs el
		JOIN agents a ON a.id = el.agent_id AND a.tenant_id = $1
		WHERE el.parsed_fields->>'event_id' = '4624'
		  AND el.created_at > NOW() - INTERVAL '5 minutes'
		  AND el.parsed_fields->>'user' IS NOT NULL
		  AND (
		       el.log_message ILIKE '%logon type:%3%'
		    OR el.log_message ILIKE '%logontype%3%'
		    OR el.log_message ILIKE '%network logon%'
		  )
		  AND (
		       el.log_message ILIKE '%ntlm%'
		    OR el.log_message ILIKE '%ntlmssp%'
		  )
		GROUP BY el.agent_id, el.parsed_fields->>'user'
		HAVING COUNT(DISTINCT el.parsed_fields->>'src_ip') >= 3
	`, tenantID)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var agentID int
		var user, srcIPs string
		var ipCount int
		if rows.Scan(&agentID, &user, &ipCount, &srcIPs) != nil {
			continue
		}
		if strings.HasSuffix(strings.TrimSpace(user), "$") {
			continue
		}
		key := fmt.Sprintf("%d:pth:%s", tenantID, user)
		if adDedup.touched(key) {
			continue
		}
		adDedup.touch(key)
		m := fmt.Sprintf("Pass-the-Hash — NTLM network logon for user='%s' from %d distinct IPs (%s) in 5 min", user, ipCount, truncateLog(srcIPs, 120))
		log.Printf("[AD] %s", m)
		createADAlert(agentID, tenantID, "critical", "Pass-the-Hash — NTLM Lateral Movement", m, "T1550.002", "Pass the Hash", "Lateral Movement")
	}
}

// detectBloodHound — EventID 4688 with SharpHound/BloodHound tool names in command line.
func detectBloodHound(tenantID int) {
	tools := []string{
		"sharphound", "bloodhound", "adfind", "ldapdomaindump",
		"powerview", "get-aduser", "get-adgroup", "get-adcomputer",
		"invoke-bloodhound", "collectionmethod",
	}
	for _, tool := range tools {
		rows, err := database.DB.Query(`
			SELECT el.agent_id,
			       coalesce(el.parsed_fields->>'user','') AS user,
			       coalesce(el.parsed_fields->>'src_ip','') AS src_ip,
			       el.log_message
			FROM endpoint_logs el
			JOIN agents a ON a.id = el.agent_id AND a.tenant_id = $1
			WHERE el.parsed_fields->>'event_id' = '4688'
			  AND el.created_at > NOW() - INTERVAL '5 minutes'
			  AND el.log_message ILIKE $2
			LIMIT 20
		`, tenantID, "%"+tool+"%")
		if err != nil {
			continue
		}
		for rows.Next() {
			var agentID int
			var user, srcIP, msg string
			if rows.Scan(&agentID, &user, &srcIP, &msg) != nil {
				continue
			}
			key := fmt.Sprintf("%d:bh:%s:%s", tenantID, tool, user)
			if adDedup.touched(key) {
				break
			}
			adDedup.touch(key)
			m := fmt.Sprintf("AD Enumeration Tool — tool='%s' user='%s' src_ip='%s' context='%s'", tool, user, srcIP, truncateLog(msg, 150))
			log.Printf("[AD] %s", m)
			createADAlert(agentID, tenantID, "high", "BloodHound / AD Enumeration Tool Detected", m, "T1087.002", "Domain Account", "Discovery")
		}
		rows.Close()
	}
}

// detectSIDHistoryInjection — EventID 4765 (SID History added to account).
func detectSIDHistoryInjection(tenantID int) {
	rows, err := database.DB.Query(`
		SELECT el.agent_id,
		       coalesce(el.parsed_fields->>'user','') AS user,
		       el.log_message
		FROM endpoint_logs el
		JOIN agents a ON a.id = el.agent_id AND a.tenant_id = $1
		WHERE el.parsed_fields->>'event_id' IN ('4765','4766')
		  AND el.created_at > NOW() - INTERVAL '5 minutes'
		LIMIT 50
	`, tenantID)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var agentID int
		var user, msg string
		if rows.Scan(&agentID, &user, &msg) != nil {
			continue
		}
		key := fmt.Sprintf("%d:sidhistory:%s", tenantID, user)
		if adDedup.touched(key) {
			continue
		}
		adDedup.touch(key)
		m := fmt.Sprintf("SID History Injection — SID history added to account='%s' (T1134.005)", user)
		log.Printf("[AD] %s", m)
		createADAlert(agentID, tenantID, "critical", "SID History Injection Detected", m, "T1134.005", "SID-History Injection", "Privilege Escalation")
	}
}

// detectAdminSDHolderAbuse — EventID 5136 modifying the AdminSDHolder container.
func detectAdminSDHolderAbuse(tenantID int) {
	rows, err := database.DB.Query(`
		SELECT el.agent_id,
		       coalesce(el.parsed_fields->>'user','') AS user,
		       el.log_message
		FROM endpoint_logs el
		JOIN agents a ON a.id = el.agent_id AND a.tenant_id = $1
		WHERE el.parsed_fields->>'event_id' = '5136'
		  AND el.created_at > NOW() - INTERVAL '5 minutes'
		  AND el.log_message ILIKE '%adminsdholder%'
		LIMIT 20
	`, tenantID)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var agentID int
		var user, msg string
		if rows.Scan(&agentID, &user, &msg) != nil {
			continue
		}
		key := fmt.Sprintf("%d:adminsdholder:%s", tenantID, user)
		if adDedup.touched(key) {
			continue
		}
		adDedup.touch(key)
		m := fmt.Sprintf("AdminSDHolder Modified — user='%s' modified AdminSDHolder object; persistence via protected group membership", user)
		log.Printf("[AD] %s", m)
		createADAlert(agentID, tenantID, "critical", "AdminSDHolder Abuse — Persistent Privilege", m, "T1484.001", "Group Policy Modification", "Privilege Escalation")
	}
}

// detectKerberosBruteForce — EventID 4771 failures ≥20 in 5 min per source IP.
func detectKerberosBruteForce(tenantID int) {
	rows, err := database.DB.Query(`
		SELECT el.agent_id,
		       el.parsed_fields->>'src_ip' AS src_ip,
		       COUNT(*) AS fail_count,
		       COUNT(DISTINCT el.parsed_fields->>'user') AS user_count
		FROM endpoint_logs el
		JOIN agents a ON a.id = el.agent_id AND a.tenant_id = $1
		WHERE el.parsed_fields->>'event_id' = '4771'
		  AND el.created_at > NOW() - INTERVAL '5 minutes'
		GROUP BY el.agent_id, el.parsed_fields->>'src_ip'
		HAVING COUNT(*) >= 20
	`, tenantID)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var agentID int
		var srcIP string
		var failCount, userCount int
		if rows.Scan(&agentID, &srcIP, &failCount, &userCount) != nil {
			continue
		}
		key := fmt.Sprintf("%d:kerb-brute:%s", tenantID, srcIP)
		if adDedup.touched(key) {
			continue
		}
		adDedup.touch(key)
		tactic := "Credential Access"
		rule := "Kerberos Brute Force — Pre-Auth Failures"
		if userCount >= 5 {
			rule = "Kerberos Password Spray — Multiple Accounts"
			tactic = "Credential Access"
		}
		m := fmt.Sprintf("%s — src_ip='%s' failures=%d distinct_users=%d in 5 min", rule, srcIP, failCount, userCount)
		log.Printf("[AD] %s", m)
		createADAlert(agentID, tenantID, "high", rule, m, "T1110.001", "Password Guessing", tactic)
	}
}

// detectLDAPEnumeration — EventID 1644 (expensive LDAP query logged by DCs when enabled)
// or mass 4662 directory object access burst from a single account.
func detectLDAPEnumeration(tenantID int) {
	// Path 1: EventID 1644 (expensive LDAP query logged by domain controllers when
	// HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics\15 Field Engineering ≥5)
	rows, err := database.DB.Query(`
		SELECT el.agent_id,
		       coalesce(el.parsed_fields->>'src_ip','') AS src_ip,
		       COUNT(*) AS query_count
		FROM endpoint_logs el
		JOIN agents a ON a.id = el.agent_id AND a.tenant_id = $1
		WHERE el.parsed_fields->>'event_id' = '1644'
		  AND el.created_at > NOW() - INTERVAL '5 minutes'
		GROUP BY el.agent_id, el.parsed_fields->>'src_ip'
		HAVING COUNT(*) >= 5
	`, tenantID)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var agentID int
			var srcIP string
			var cnt int
			if rows.Scan(&agentID, &srcIP, &cnt) != nil {
				continue
			}
			key := fmt.Sprintf("%d:ldapenum:%s", tenantID, srcIP)
			if adDedup.touched(key) {
				continue
			}
			adDedup.touch(key)
			m := fmt.Sprintf("LDAP Enumeration — %d expensive LDAP queries from src_ip='%s' in 5 min (possible BloodHound/ADExplorer)", cnt, srcIP)
			log.Printf("[AD] %s", m)
			createADAlert(agentID, tenantID, "medium", "LDAP Enumeration — Expensive Query Burst", m, "T1018", "Remote System Discovery", "Discovery")
		}
	}

	// Path 2: Mass EventID 4662 (directory object access) burst from same user in 5 min
	rows2, err := database.DB.Query(`
		SELECT el.agent_id,
		       el.parsed_fields->>'user' AS actor,
		       COUNT(*) AS access_count
		FROM endpoint_logs el
		JOIN agents a ON a.id = el.agent_id AND a.tenant_id = $1
		WHERE el.parsed_fields->>'event_id' = '4662'
		  AND el.created_at > NOW() - INTERVAL '5 minutes'
		  AND el.parsed_fields->>'user' IS NOT NULL
		GROUP BY el.agent_id, el.parsed_fields->>'user'
		HAVING COUNT(*) >= 50
	`, tenantID)
	if err != nil {
		return
	}
	defer rows2.Close()
	for rows2.Next() {
		var agentID int
		var actor string
		var cnt int
		if rows2.Scan(&agentID, &actor, &cnt) != nil {
			continue
		}
		key := fmt.Sprintf("%d:ldapenum2:%s", tenantID, actor)
		if adDedup.touched(key) {
			continue
		}
		adDedup.touch(key)
		m := fmt.Sprintf("AD Object Enumeration — user='%s' accessed %d directory objects in 5 min (possible ADExplorer/LDAP scan)", actor, cnt)
		log.Printf("[AD] %s", m)
		createADAlert(agentID, tenantID, "medium", "AD Object Enumeration Burst", m, "T1087.002", "Domain Account", "Discovery")
	}
}

func createADAlert(agentID, tenantID int, severity, rule, msg, mitre, mitreName, tactic string) {
	CreateAlert(models.Alert{
		AgentID:        agentID,
		TenantID:       tenantID,
		Severity:       severity,
		RuleName:       rule,
		LogMessage:     msg,
		MitreTactic:    tactic,
		MitreTechnique: mitre,
		MitreName:      mitreName,
		Fingerprint:    fmt.Sprintf("ad-%s-%d", mitre, tenantID),
	})
}
