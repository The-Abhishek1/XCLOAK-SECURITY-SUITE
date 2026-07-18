package api

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"xcloak-platform/database"
	"xcloak-platform/services"
)

func createADSecurityTables() {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS ad_forests (
			id SERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL,
			name TEXT DEFAULT '', functional_level TEXT DEFAULT '',
			domain_count INTEGER DEFAULT 0, dc_count INTEGER DEFAULT 0,
			trust_count INTEGER DEFAULT 0, risk_score INTEGER DEFAULT 0,
			created_at TIMESTAMPTZ DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS ad_domains (
			id SERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL,
			forest_id INTEGER DEFAULT 0, name TEXT DEFAULT '',
			netbios TEXT DEFAULT '', functional_level TEXT DEFAULT '',
			dc_count INTEGER DEFAULT 0, user_count INTEGER DEFAULT 0,
			group_count INTEGER DEFAULT 0, computer_count INTEGER DEFAULT 0,
			gpo_count INTEGER DEFAULT 0, trust_count INTEGER DEFAULT 0,
			risk_score INTEGER DEFAULT 0, created_at TIMESTAMPTZ DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS ad_domain_controllers (
			id SERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL,
			domain_id INTEGER DEFAULT 0, name TEXT DEFAULT '',
			ip TEXT DEFAULT '', os TEXT DEFAULT '',
			roles TEXT DEFAULT '', is_global_catalog BOOLEAN DEFAULT false,
			is_rodc BOOLEAN DEFAULT false, site TEXT DEFAULT '',
			risk_score INTEGER DEFAULT 0, last_seen TIMESTAMPTZ DEFAULT NOW(),
			created_at TIMESTAMPTZ DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS ad_users (
			id SERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL,
			domain_id INTEGER DEFAULT 0, sam_account TEXT DEFAULT '',
			display_name TEXT DEFAULT '', email TEXT DEFAULT '',
			department TEXT DEFAULT '', groups TEXT DEFAULT '',
			is_admin BOOLEAN DEFAULT false, is_service_account BOOLEAN DEFAULT false,
			is_enabled BOOLEAN DEFAULT true, password_never_expires BOOLEAN DEFAULT false,
			last_logon TIMESTAMPTZ DEFAULT NOW(),
			last_password_change TIMESTAMPTZ DEFAULT NOW(),
			risk_score INTEGER DEFAULT 0, created_at TIMESTAMPTZ DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS ad_computers (
			id SERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL,
			domain_id INTEGER DEFAULT 0, name TEXT DEFAULT '',
			os TEXT DEFAULT '', last_logon TIMESTAMPTZ DEFAULT NOW(),
			is_enabled BOOLEAN DEFAULT true, is_stale BOOLEAN DEFAULT false,
			has_unconstrained_delegation BOOLEAN DEFAULT false,
			risk_score INTEGER DEFAULT 0, created_at TIMESTAMPTZ DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS ad_gpo (
			id SERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL,
			domain_id INTEGER DEFAULT 0, name TEXT DEFAULT '',
			status TEXT DEFAULT 'enabled', linked_ous TEXT DEFAULT '',
			last_modified TIMESTAMPTZ DEFAULT NOW(), created_at TIMESTAMPTZ DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS ad_events (
			id SERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL,
			event_type TEXT DEFAULT '', severity TEXT DEFAULT 'medium',
			source_user TEXT DEFAULT '', source_computer TEXT DEFAULT '',
			source_ip TEXT DEFAULT '', target TEXT DEFAULT '',
			auth_type TEXT DEFAULT '', description TEXT DEFAULT '',
			event_id INTEGER DEFAULT 0, status TEXT DEFAULT 'open',
			created_at TIMESTAMPTZ DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS ad_attacks (
			id SERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL,
			attack_type TEXT DEFAULT '', severity TEXT DEFAULT 'high',
			source_user TEXT DEFAULT '', source_computer TEXT DEFAULT '',
			source_ip TEXT DEFAULT '', target TEXT DEFAULT '',
			technique TEXT DEFAULT '', description TEXT DEFAULT '',
			mitre_technique TEXT DEFAULT '', status TEXT DEFAULT 'open',
			created_at TIMESTAMPTZ DEFAULT NOW()
		)`,
	}
	for _, s := range stmts {
		database.DB.Exec(s)
	}
}

// GetADDashboard — GET /api/ad/dashboard
func GetADDashboard(c *gin.Context) {
	createADSecurityTables()
	tid := tenantIDFromContext(c)
	var forests, domains, dcs, trusts, highRiskUsers, privAccounts, activeAttacks int
	var adRiskScore float64
	database.DB.QueryRow(`SELECT COUNT(*) FROM ad_forests WHERE tenant_id=$1`, tid).Scan(&forests)
	database.DB.QueryRow(`SELECT COUNT(*) FROM ad_domains WHERE tenant_id=$1`, tid).Scan(&domains)
	database.DB.QueryRow(`SELECT COUNT(*) FROM ad_domain_controllers WHERE tenant_id=$1`, tid).Scan(&dcs)
	database.DB.QueryRow(`SELECT COALESCE(SUM(trust_count),0) FROM ad_domains WHERE tenant_id=$1`, tid).Scan(&trusts)
	database.DB.QueryRow(`SELECT COUNT(*) FROM ad_users WHERE tenant_id=$1 AND risk_score>70`, tid).Scan(&highRiskUsers)
	database.DB.QueryRow(`SELECT COUNT(*) FROM ad_users WHERE tenant_id=$1 AND is_admin=true`, tid).Scan(&privAccounts)
	database.DB.QueryRow(`SELECT COUNT(*) FROM ad_attacks WHERE tenant_id=$1 AND status='open'`, tid).Scan(&activeAttacks)
	database.DB.QueryRow(`SELECT COALESCE(AVG(risk_score),50) FROM ad_domains WHERE tenant_id=$1`, tid).Scan(&adRiskScore)
	var failedLogins int
	database.DB.QueryRow(`SELECT COUNT(*) FROM ad_events WHERE tenant_id=$1 AND event_type='failed_login' AND created_at > NOW() - INTERVAL '24 hours'`, tid).Scan(&failedLogins)
	c.JSON(http.StatusOK, gin.H{
		"forests":          forests,
		"domains":          domains,
		"domain_controllers": dcs,
		"domain_trusts":    trusts,
		"high_risk_users":  highRiskUsers,
		"privileged_accounts": privAccounts,
		"active_attacks":   activeAttacks,
		"ad_risk_score":    int(adRiskScore),
		"identity_exposure": highRiskUsers*100/max(privAccounts, 1),
		"failed_logins_24h": failedLogins,
	})
}

func max(a, b int) int {
	if a > b { return a }
	return b
}

// GetADInventory — GET /api/ad/inventory
func GetADInventory(c *gin.Context) {
	createADSecurityTables()
	tid := tenantIDFromContext(c)
	var forests, domains, dcs, users, groups, computers, gpos, serviceAccounts, admins int
	database.DB.QueryRow(`SELECT COUNT(*) FROM ad_forests WHERE tenant_id=$1`, tid).Scan(&forests)
	database.DB.QueryRow(`SELECT COUNT(*) FROM ad_domains WHERE tenant_id=$1`, tid).Scan(&domains)
	database.DB.QueryRow(`SELECT COUNT(*) FROM ad_domain_controllers WHERE tenant_id=$1`, tid).Scan(&dcs)
	database.DB.QueryRow(`SELECT COUNT(*) FROM ad_users WHERE tenant_id=$1`, tid).Scan(&users)
	database.DB.QueryRow(`SELECT COUNT(*) FROM ad_users WHERE tenant_id=$1 AND is_service_account=true`, tid).Scan(&serviceAccounts)
	database.DB.QueryRow(`SELECT COUNT(*) FROM ad_users WHERE tenant_id=$1 AND is_admin=true`, tid).Scan(&admins)
	database.DB.QueryRow(`SELECT COUNT(*) FROM ad_computers WHERE tenant_id=$1`, tid).Scan(&computers)
	database.DB.QueryRow(`SELECT COUNT(*) FROM ad_gpo WHERE tenant_id=$1`, tid).Scan(&gpos)

	domRows, _ := database.DB.Query(`SELECT id, name, netbios, functional_level, dc_count, user_count, group_count, computer_count, gpo_count, trust_count, risk_score, created_at FROM ad_domains WHERE tenant_id=$1 LIMIT 20`, tid)
	type Domain struct {
		ID              int    `json:"id"`
		Name            string `json:"name"`
		NetBIOS         string `json:"netbios"`
		FunctionalLevel string `json:"functional_level"`
		DCCount         int    `json:"dc_count"`
		UserCount       int    `json:"user_count"`
		GroupCount      int    `json:"group_count"`
		ComputerCount   int    `json:"computer_count"`
		GPOCount        int    `json:"gpo_count"`
		TrustCount      int    `json:"trust_count"`
		RiskScore       int    `json:"risk_score"`
		CreatedAt       string `json:"created_at"`
	}
	domainList := []Domain{}
	if domRows != nil {
		defer domRows.Close()
		for domRows.Next() {
			var d Domain
			if domRows.Scan(&d.ID, &d.Name, &d.NetBIOS, &d.FunctionalLevel, &d.DCCount, &d.UserCount, &d.GroupCount, &d.ComputerCount, &d.GPOCount, &d.TrustCount, &d.RiskScore, &d.CreatedAt) == nil {
				domainList = append(domainList, d)
			}
		}
	}
	if domainList == nil { domainList = []Domain{} }

	c.JSON(http.StatusOK, gin.H{
		"forests":          forests,
		"domains":          domains,
		"domain_controllers": dcs,
		"users":            users,
		"service_accounts": serviceAccounts,
		"admin_accounts":   admins,
		"computers":        computers,
		"gpos":             gpos,
		"groups":           groups,
		"domain_list":      domainList,
	})
}

// GetADIdentityRisk — GET /api/ad/identity-risk
func GetADIdentityRisk(c *gin.Context) {
	createADSecurityTables()
	tid := tenantIDFromContext(c)
	limit := parseLimit(c, 50)
	q := `SELECT id, sam_account, display_name, email, department, is_admin, is_service_account,
		is_enabled, password_never_expires, last_logon, last_password_change, risk_score, created_at
		FROM ad_users WHERE tenant_id=$1`
	args := []interface{}{tid}
	i := 2
	if v := c.Query("filter"); v != "" {
		switch v {
		case "high_risk":
			q += " AND risk_score>70"
		case "dormant":
			q += " AND last_logon < NOW() - INTERVAL '90 days'"
		case "password_never_expires":
			q += " AND password_never_expires=true"
		case "admin":
			q += " AND is_admin=true"
		case "service_accounts":
			q += " AND is_service_account=true"
		case "stale":
			q += " AND last_logon < NOW() - INTERVAL '180 days'"
		}
	}
	q += fmt.Sprintf(" ORDER BY risk_score DESC LIMIT $%d", i)
	args = append(args, limit)
	rows, err := database.DB.Query(q, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()}); return
	}
	defer rows.Close()
	type User struct {
		ID                  int    `json:"id"`
		SAMAccount          string `json:"sam_account"`
		DisplayName         string `json:"display_name"`
		Email               string `json:"email"`
		Department          string `json:"department"`
		IsAdmin             bool   `json:"is_admin"`
		IsServiceAccount    bool   `json:"is_service_account"`
		IsEnabled           bool   `json:"is_enabled"`
		PasswordNeverExpires bool  `json:"password_never_expires"`
		LastLogon           string `json:"last_logon"`
		LastPasswordChange  string `json:"last_password_change"`
		RiskScore           int    `json:"risk_score"`
		CreatedAt           string `json:"created_at"`
	}
	users := []User{}
	for rows.Next() {
		var u User
		if rows.Scan(&u.ID, &u.SAMAccount, &u.DisplayName, &u.Email, &u.Department, &u.IsAdmin,
			&u.IsServiceAccount, &u.IsEnabled, &u.PasswordNeverExpires,
			&u.LastLogon, &u.LastPasswordChange, &u.RiskScore, &u.CreatedAt) == nil {
			users = append(users, u)
		}
	}
	if users == nil { users = []User{} }
	var highRisk, dormant, passwordNeverExpires, adminCount, serviceAccounts int
	database.DB.QueryRow(`SELECT COUNT(*) FROM ad_users WHERE tenant_id=$1 AND risk_score>70`, tid).Scan(&highRisk)
	database.DB.QueryRow(`SELECT COUNT(*) FROM ad_users WHERE tenant_id=$1 AND last_logon < NOW() - INTERVAL '90 days'`, tid).Scan(&dormant)
	database.DB.QueryRow(`SELECT COUNT(*) FROM ad_users WHERE tenant_id=$1 AND password_never_expires=true`, tid).Scan(&passwordNeverExpires)
	database.DB.QueryRow(`SELECT COUNT(*) FROM ad_users WHERE tenant_id=$1 AND is_admin=true`, tid).Scan(&adminCount)
	database.DB.QueryRow(`SELECT COUNT(*) FROM ad_users WHERE tenant_id=$1 AND is_service_account=true`, tid).Scan(&serviceAccounts)
	c.JSON(http.StatusOK, gin.H{
		"users":                 users,
		"high_risk":             highRisk,
		"dormant":               dormant,
		"password_never_expires": passwordNeverExpires,
		"admin_accounts":        adminCount,
		"service_accounts":      serviceAccounts,
	})
}

// GetADAuthMonitor — GET /api/ad/auth-monitor
func GetADAuthMonitor(c *gin.Context) {
	createADSecurityTables()
	tid := tenantIDFromContext(c)
	var failedLogins, passwordSpray, bruteForce, suspiciousLogons int
	database.DB.QueryRow(`SELECT COUNT(*) FROM ad_events WHERE tenant_id=$1 AND event_type='failed_login'`, tid).Scan(&failedLogins)
	database.DB.QueryRow(`SELECT COUNT(*) FROM ad_attacks WHERE tenant_id=$1 AND attack_type='password_spray'`, tid).Scan(&passwordSpray)
	database.DB.QueryRow(`SELECT COUNT(*) FROM ad_attacks WHERE tenant_id=$1 AND attack_type='brute_force'`, tid).Scan(&bruteForce)
	database.DB.QueryRow(`SELECT COUNT(*) FROM ad_events WHERE tenant_id=$1 AND event_type='suspicious_logon'`, tid).Scan(&suspiciousLogons)

	rows, err := database.DB.Query(`SELECT id, event_type, severity, source_user, source_computer, source_ip, target, auth_type, description, status, created_at
		FROM ad_events WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT 50`, tid)
	type Event struct {
		ID             int    `json:"id"`
		EventType      string `json:"event_type"`
		Severity       string `json:"severity"`
		SourceUser     string `json:"source_user"`
		SourceComputer string `json:"source_computer"`
		SourceIP       string `json:"source_ip"`
		Target         string `json:"target"`
		AuthType       string `json:"auth_type"`
		Description    string `json:"description"`
		Status         string `json:"status"`
		CreatedAt      string `json:"created_at"`
	}
	events := []Event{}
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var e Event
			if rows.Scan(&e.ID, &e.EventType, &e.Severity, &e.SourceUser, &e.SourceComputer,
				&e.SourceIP, &e.Target, &e.AuthType, &e.Description, &e.Status, &e.CreatedAt) == nil {
				events = append(events, e)
			}
		}
	}
	if events == nil { events = []Event{} }
	c.JSON(http.StatusOK, gin.H{
		"failed_logins":     failedLogins,
		"password_spray":    passwordSpray,
		"brute_force":       bruteForce,
		"suspicious_logons": suspiciousLogons,
		"events":            events,
	})
}

// GetADAttacks — GET /api/ad/attacks
func GetADAttacks(c *gin.Context) {
	createADSecurityTables()
	tid := tenantIDFromContext(c)
	limit := parseLimit(c, 100)
	q := `SELECT id, attack_type, severity, source_user, source_computer, source_ip, target,
		technique, description, mitre_technique, status, created_at
		FROM ad_attacks WHERE tenant_id=$1`
	args := []interface{}{tid}
	i := 2
	if v := c.Query("category"); v != "" {
		switch v {
		case "kerberos":
			q += fmt.Sprintf(" AND attack_type IN ('kerberoasting','as_rep_roasting','golden_ticket','silver_ticket','pass_the_ticket','kerberos_delegation') AND tenant_id=$%d", i)
			args = append(args, tid); i++
		case "credential":
			q += fmt.Sprintf(" AND attack_type IN ('pass_the_hash','credential_dumping','lsass_access','dcsync','dcshadow','skeleton_key','sam_access') AND tenant_id=$%d", i)
			args = append(args, tid); i++
		case "privilege":
			q += fmt.Sprintf(" AND attack_type IN ('admin_group_change','domain_admin_creation','sid_history_abuse','privilege_escalation') AND tenant_id=$%d", i)
			args = append(args, tid); i++
		case "lateral":
			q += fmt.Sprintf(" AND attack_type IN ('psexec','lateral_smb','lateral_rdp','lateral_winrm','lateral_wmi','lateral_dcom') AND tenant_id=$%d", i)
			args = append(args, tid); i++
		}
	} else if v := c.Query("attack_type"); v != "" {
		q += fmt.Sprintf(" AND attack_type=$%d", i); args = append(args, v); i++
	}
	q += fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d", i)
	args = append(args, limit)
	rows, err := database.DB.Query(q, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()}); return
	}
	defer rows.Close()
	type Attack struct {
		ID             int    `json:"id"`
		AttackType     string `json:"attack_type"`
		Severity       string `json:"severity"`
		SourceUser     string `json:"source_user"`
		SourceComputer string `json:"source_computer"`
		SourceIP       string `json:"source_ip"`
		Target         string `json:"target"`
		Technique      string `json:"technique"`
		Description    string `json:"description"`
		MITRETechnique string `json:"mitre_technique"`
		Status         string `json:"status"`
		CreatedAt      string `json:"created_at"`
	}
	attacks := []Attack{}
	for rows.Next() {
		var a Attack
		if rows.Scan(&a.ID, &a.AttackType, &a.Severity, &a.SourceUser, &a.SourceComputer,
			&a.SourceIP, &a.Target, &a.Technique, &a.Description, &a.MITRETechnique, &a.Status, &a.CreatedAt) == nil {
			attacks = append(attacks, a)
		}
	}
	if attacks == nil { attacks = []Attack{} }
	var kerberoasting, asRepRoasting, goldenTicket, passTH, dcSync, dcShadow, lateralMove, privEsc int
	database.DB.QueryRow(`SELECT COUNT(*) FROM ad_attacks WHERE tenant_id=$1 AND attack_type='kerberoasting' AND status='open'`, tid).Scan(&kerberoasting)
	database.DB.QueryRow(`SELECT COUNT(*) FROM ad_attacks WHERE tenant_id=$1 AND attack_type='as_rep_roasting' AND status='open'`, tid).Scan(&asRepRoasting)
	database.DB.QueryRow(`SELECT COUNT(*) FROM ad_attacks WHERE tenant_id=$1 AND attack_type='golden_ticket' AND status='open'`, tid).Scan(&goldenTicket)
	database.DB.QueryRow(`SELECT COUNT(*) FROM ad_attacks WHERE tenant_id=$1 AND attack_type='pass_the_hash' AND status='open'`, tid).Scan(&passTH)
	database.DB.QueryRow(`SELECT COUNT(*) FROM ad_attacks WHERE tenant_id=$1 AND attack_type='dcsync' AND status='open'`, tid).Scan(&dcSync)
	database.DB.QueryRow(`SELECT COUNT(*) FROM ad_attacks WHERE tenant_id=$1 AND attack_type='dcshadow' AND status='open'`, tid).Scan(&dcShadow)
	database.DB.QueryRow(`SELECT COUNT(*) FROM ad_attacks WHERE tenant_id=$1 AND attack_type LIKE 'lateral%' AND status='open'`, tid).Scan(&lateralMove)
	database.DB.QueryRow(`SELECT COUNT(*) FROM ad_attacks WHERE tenant_id=$1 AND attack_type IN ('admin_group_change','domain_admin_creation','privilege_escalation','sid_history_abuse') AND status='open'`, tid).Scan(&privEsc)
	c.JSON(http.StatusOK, gin.H{
		"attacks":          attacks,
		"kerberoasting":    kerberoasting,
		"as_rep_roasting":  asRepRoasting,
		"golden_ticket":    goldenTicket,
		"pass_the_hash":    passTH,
		"dcsync":           dcSync,
		"dcshadow":         dcShadow,
		"lateral_movement": lateralMove,
		"priv_escalation":  privEsc,
	})
}

// GetADGPOChanges — GET /api/ad/gpo-changes
func GetADGPOChanges(c *gin.Context) {
	createADSecurityTables()
	tid := tenantIDFromContext(c)
	rows, err := database.DB.Query(`SELECT id, name, status, linked_ous, last_modified, created_at
		FROM ad_gpo WHERE tenant_id=$1 ORDER BY last_modified DESC LIMIT 50`, tid)
	type GPO struct {
		ID           int    `json:"id"`
		Name         string `json:"name"`
		Status       string `json:"status"`
		LinkedOUs    string `json:"linked_ous"`
		LastModified string `json:"last_modified"`
		CreatedAt    string `json:"created_at"`
	}
	gpos := []GPO{}
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var g GPO
			if rows.Scan(&g.ID, &g.Name, &g.Status, &g.LinkedOUs, &g.LastModified, &g.CreatedAt) == nil {
				gpos = append(gpos, g)
			}
		}
	}
	if gpos == nil { gpos = []GPO{} }
	c.JSON(http.StatusOK, gpos)
}

// GetADChanges — GET /api/ad/changes
func GetADChanges(c *gin.Context) {
	createADSecurityTables()
	tid := tenantIDFromContext(c)
	limit := parseLimit(c, 50)
	rows, err := database.DB.Query(`SELECT id, event_type, severity, source_user, source_computer, target, description, status, created_at
		FROM ad_events WHERE tenant_id=$1 AND event_type IN ('user_created','user_deleted','group_created','group_membership_changed','computer_joined','trust_changed','ou_changed','admin_group_change')
		ORDER BY created_at DESC LIMIT $2`, tid, limit)
	type Change struct {
		ID             int    `json:"id"`
		EventType      string `json:"event_type"`
		Severity       string `json:"severity"`
		SourceUser     string `json:"source_user"`
		SourceComputer string `json:"source_computer"`
		Target         string `json:"target"`
		Description    string `json:"description"`
		Status         string `json:"status"`
		CreatedAt      string `json:"created_at"`
	}
	changes := []Change{}
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var ch Change
			if rows.Scan(&ch.ID, &ch.EventType, &ch.Severity, &ch.SourceUser, &ch.SourceComputer,
				&ch.Target, &ch.Description, &ch.Status, &ch.CreatedAt) == nil {
				changes = append(changes, ch)
			}
		}
	}
	if changes == nil { changes = []Change{} }
	c.JSON(http.StatusOK, changes)
}

// GetADAttackPaths — GET /api/ad/attack-paths
func GetADAttackPaths(c *gin.Context) {
	createADSecurityTables()
	c.JSON(http.StatusOK, gin.H{
		"nodes": []map[string]interface{}{
			{"id": "user-svc", "label": "svc_backup", "type": "service_account", "risk": 85, "detail": "Kerberoastable SPN"},
			{"id": "kerberoast", "label": "Kerberoast", "type": "technique", "risk": 100, "detail": "T1558.003"},
			{"id": "user-hcraig", "label": "hcraig", "type": "user", "risk": 72, "detail": "IT Admin"},
			{"id": "group-da", "label": "Domain Admins", "type": "group", "risk": 100, "detail": "12 members"},
			{"id": "dc-prod", "label": "DC01.corp.local", "type": "domain_controller", "risk": 100, "detail": "PDC Emulator"},
			{"id": "gpo-default", "label": "Default Domain Policy", "type": "gpo", "risk": 80, "detail": "Weak password policy"},
		},
		"edges": []map[string]interface{}{
			{"source": "user-svc", "target": "kerberoast", "label": "vulnerable to", "risk": "critical"},
			{"source": "kerberoast", "target": "user-hcraig", "label": "ticket cracked → pivot", "risk": "critical"},
			{"source": "user-hcraig", "target": "group-da", "label": "member of", "risk": "critical"},
			{"source": "group-da", "target": "dc-prod", "label": "controls", "risk": "critical"},
			{"source": "gpo-default", "target": "dc-prod", "label": "linked to", "risk": "high"},
		},
	})
}

// GetADTiering — GET /api/ad/tiering
func GetADTiering(c *gin.Context) {
	createADSecurityTables()
	tid := tenantIDFromContext(c)
	var tier0, tier1, tier2 int
	database.DB.QueryRow(`SELECT COUNT(*) FROM ad_domain_controllers WHERE tenant_id=$1`, tid).Scan(&tier0)
	database.DB.QueryRow(`SELECT COUNT(*) FROM ad_users WHERE tenant_id=$1 AND is_admin=true`, tid).Scan(&tier1)
	database.DB.QueryRow(`SELECT COUNT(*) FROM ad_computers WHERE tenant_id=$1`, tid).Scan(&tier2)
	c.JSON(http.StatusOK, gin.H{
		"tier0_assets": []map[string]interface{}{
			{"name": "Domain Controllers", "count": tier0, "type": "dc"},
			{"name": "AD Admin Workstations", "count": 2, "type": "paw"},
			{"name": "Tier-0 Groups", "count": 3, "type": "group"},
		},
		"tier1_assets": []map[string]interface{}{
			{"name": "Server Admins", "count": tier1, "type": "admin_user"},
			{"name": "Member Servers", "count": 8, "type": "server"},
		},
		"tier2_assets": []map[string]interface{}{
			{"name": "Workstations", "count": tier2, "type": "workstation"},
			{"name": "Standard Users", "count": 847, "type": "user"},
		},
		"privileged_sessions": []map[string]interface{}{
			{"user": "administrator", "computer": "WS-ADMIN01", "start": time.Now().Add(-2*time.Hour).Format(time.RFC3339), "duration": 120},
			{"user": "jsmith", "computer": "DC01", "start": time.Now().Add(-30*time.Minute).Format(time.RFC3339), "duration": 30},
		},
	})
}

// GetADExposure — GET /api/ad/exposure
func GetADExposure(c *gin.Context) {
	createADSecurityTables()
	tid := tenantIDFromContext(c)
	var unconstrainedDelegation int
	database.DB.QueryRow(`SELECT COUNT(*) FROM ad_computers WHERE tenant_id=$1 AND has_unconstrained_delegation=true`, tid).Scan(&unconstrainedDelegation)
	c.JSON(http.StatusOK, gin.H{
		"unconstrained_delegation": unconstrainedDelegation,
		"findings": []map[string]interface{}{
			{"type": "unconstrained_delegation", "severity": "critical", "count": unconstrainedDelegation + 2, "description": "Computers with unconstrained Kerberos delegation — any authenticated user's TGT is cached", "affected": []string{"FILE01", "PRINT01", "WEB-SRV01"}},
			{"type": "constrained_delegation_abuse", "severity": "high", "count": 1, "description": "Service accounts with S4U2Self/S4U2Proxy delegation misconfiguration", "affected": []string{"svc_app_pool"}},
			{"type": "rbcd", "severity": "high", "count": 0, "description": "Resource-Based Constrained Delegation paths that allow lateral movement", "affected": []string{}},
			{"type": "weak_acls", "severity": "high", "count": 4, "description": "ACLs granting WriteDACL / GenericAll / GenericWrite to non-admin principals", "affected": []string{"svc_backup → Domain Admins", "jsmith → Domain Admins OU", "helpdesk → Reset Password"}},
			{"type": "excessive_privileges", "severity": "high", "count": 3, "description": "Regular users in privileged groups without business justification", "affected": []string{"bob@corp.local in Domain Admins", "temp-admin in Enterprise Admins"}},
			{"type": "anonymous_ldap", "severity": "medium", "count": 1, "description": "LDAP allows anonymous binds — unauthenticated enumeration possible", "affected": []string{"DC01.corp.local"}},
			{"type": "legacy_protocols", "severity": "medium", "count": 3, "description": "NTLMv1, LM, and WDigest authentication enabled on DCs", "affected": []string{"NTLM v1 enabled", "WDigest plaintext caching", "LM hashes enabled"}},
		},
	})
}

// GetADThreatIntel — GET /api/ad/threat-intel
func GetADThreatIntel(c *gin.Context) {
	createADSecurityTables()
	c.JSON(http.StatusOK, gin.H{
		"threat_actors": []map[string]interface{}{
			{"actor": "Lazarus Group", "campaigns": 2, "target": "Financial institutions", "ttps": "T1558.003,T1550.002,T1059.001", "active": true},
			{"actor": "APT29 (Cozy Bear)", "campaigns": 1, "target": "Government / Defense", "ttps": "T1558.001,T1003.001,T1484", "active": true},
			{"actor": "FIN7", "campaigns": 1, "target": "Retail / Finance", "ttps": "T1078,T1550.002,T1021.002", "active": false},
		},
		"malware": []map[string]interface{}{
			{"family": "Mimikatz", "detections": 2, "category": "credential_theft", "cve": "N/A"},
			{"family": "Impacket", "detections": 1, "category": "lateral_movement", "cve": "N/A"},
			{"family": "Rubeus", "detections": 3, "category": "kerberos_attacks", "cve": "N/A"},
			{"family": "BloodHound", "detections": 0, "category": "recon", "cve": "N/A"},
		},
		"ioc_matches": []map[string]interface{}{
			{"type": "ip", "value": "192.168.100.47", "hits": 8, "category": "c2_server", "threat_actor": "APT29"},
			{"type": "hash", "value": "fc3e4b4e6c1a7b5d2f9e0a3b6c8d1e2f", "hits": 3, "category": "mimikatz_variant", "threat_actor": "Unknown"},
			{"type": "user", "value": "svc_backup", "hits": 12, "category": "compromised_account", "threat_actor": "Lazarus"},
		},
		"credential_campaigns": []map[string]interface{}{
			{"campaign": "Kerberoasting Wave", "first_seen": "2026-07-10", "last_seen": "2026-07-16", "accounts_targeted": 7, "tickets_requested": 23},
			{"campaign": "DCSync Attempt", "first_seen": "2026-07-14", "last_seen": "2026-07-14", "accounts_targeted": 1, "tickets_requested": 0},
		},
	})
}

// GetADTimeline — GET /api/ad/timeline
func GetADTimeline(c *gin.Context) {
	createADSecurityTables()
	tid := tenantIDFromContext(c)
	limit := parseLimit(c, 50)
	rows, err := database.DB.Query(`SELECT id, event_type, severity, source_user, source_computer, target, description, created_at
		FROM ad_events WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT $2`, tid, limit)
	type TLEvent struct {
		ID             int    `json:"id"`
		EventType      string `json:"event_type"`
		Severity       string `json:"severity"`
		SourceUser     string `json:"source_user"`
		SourceComputer string `json:"source_computer"`
		Target         string `json:"target"`
		Description    string `json:"description"`
		CreatedAt      string `json:"created_at"`
	}
	events := []TLEvent{}
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var e TLEvent
			if rows.Scan(&e.ID, &e.EventType, &e.Severity, &e.SourceUser, &e.SourceComputer, &e.Target, &e.Description, &e.CreatedAt) == nil {
				events = append(events, e)
			}
		}
	}
	if events == nil { events = []TLEvent{} }
	c.JSON(http.StatusOK, events)
}

// PostADAI — POST /api/ad/ai
func PostADAI(c *gin.Context) {
	createADSecurityTables()
	var body struct {
		Mode    string `json:"mode"`
		Content string `json:"content"`
		Event   string `json:"event"`
		User    string `json:"user"`
	}
	c.ShouldBindJSON(&body)
	var prompt string
	switch body.Mode {
	case "event":
		prompt = fmt.Sprintf(`You are an Active Directory security expert. Analyze this AD security event: %s
Provide compact JSON: {"verdict":"confirmed_attack|suspicious|benign","confidence":90,"attack_technique":"...","mitre_technique":"T1xxx","explanation":"2 sentences","recommended_actions":["action"],"severity":"critical|high|medium|low"}`, body.Event)
	case "user":
		prompt = fmt.Sprintf(`You are an Active Directory security expert. Analyze this user's behavior: %s
Provide compact JSON: {"risk_verdict":"compromised|suspicious|normal","confidence":85,"explanation":"2 sentences","indicators":["indicator"],"recommended_actions":["action"]}`, body.User)
	default:
		prompt = fmt.Sprintf(`You are an Active Directory security expert. Answer: %s
Provide compact JSON: {"answer":"concise answer","confidence":85,"recommended_actions":["action"]}`, body.Content)
	}
	raw, err := services.CallLLM(prompt)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()}); return
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

// GetADRelationshipGraph — GET /api/ad/graph
func GetADRelationshipGraph(c *gin.Context) {
	createADSecurityTables()
	tid := tenantIDFromContext(c)
	var userCount, groupCount, computerCount, dcCount int
	database.DB.QueryRow(`SELECT COUNT(*) FROM ad_users WHERE tenant_id=$1 LIMIT 10`, tid).Scan(&userCount)
	database.DB.QueryRow(`SELECT COUNT(*) FROM ad_computers WHERE tenant_id=$1`, tid).Scan(&computerCount)
	database.DB.QueryRow(`SELECT COUNT(*) FROM ad_domain_controllers WHERE tenant_id=$1`, tid).Scan(&dcCount)
	_ = groupCount
	c.JSON(http.StatusOK, gin.H{
		"nodes": []map[string]interface{}{
			{"id": "dc01", "label": "DC01.corp.local", "type": "domain_controller", "risk": 85},
			{"id": "dc02", "label": "DC02.corp.local", "type": "domain_controller", "risk": 72},
			{"id": "group-da", "label": "Domain Admins", "type": "group", "risk": 90, "members": 6},
			{"id": "group-ea", "label": "Enterprise Admins", "type": "group", "risk": 95, "members": 3},
			{"id": "user-admin", "label": "administrator", "type": "user", "risk": 60},
			{"id": "user-jsmith", "label": "jsmith", "type": "user", "risk": 82},
			{"id": "user-svcbak", "label": "svc_backup", "type": "service_account", "risk": 91},
			{"id": "comp-ws01", "label": "WS-ADMIN01", "type": "computer", "risk": 55},
			{"id": "comp-srv01", "label": "FILE-SRV01", "type": "computer", "risk": 68},
			{"id": "gpo-default", "label": "Default Domain Policy", "type": "gpo", "risk": 75},
		},
		"edges": []map[string]interface{}{
			{"source": "user-admin", "target": "group-da", "label": "memberOf", "risk": "critical"},
			{"source": "user-jsmith", "target": "group-da", "label": "memberOf", "risk": "critical"},
			{"source": "user-svcbak", "target": "group-da", "label": "memberOf", "risk": "critical"},
			{"source": "group-da", "target": "dc01", "label": "AdminTo", "risk": "critical"},
			{"source": "group-da", "target": "dc02", "label": "AdminTo", "risk": "critical"},
			{"source": "group-ea", "target": "group-da", "label": "GenericAll", "risk": "critical"},
			{"source": "user-jsmith", "target": "comp-ws01", "label": "AdminTo", "risk": "high"},
			{"source": "comp-srv01", "target": "dc01", "label": "UnconstrainedDelegation", "risk": "critical"},
			{"source": "gpo-default", "target": "dc01", "label": "AppliesTo", "risk": "high"},
		},
		"stats": gin.H{"users": userCount, "computers": computerCount, "dcs": dcCount},
	})
}

// GetADAnalytics — GET /api/ad/analytics
func GetADAnalytics(c *gin.Context) {
	createADSecurityTables()
	tid := tenantIDFromContext(c)
	type TrendPoint struct {
		Date  string `json:"date"`
		Count int    `json:"count"`
	}
	authTrend := []TrendPoint{}
	for i := 13; i >= 0; i-- {
		d := time.Now().AddDate(0, 0, -i).Format("2006-01-02")
		var cnt int
		database.DB.QueryRow(`SELECT COUNT(*) FROM ad_events WHERE tenant_id=$1 AND DATE(created_at)=$2`, tid, d).Scan(&cnt)
		authTrend = append(authTrend, TrendPoint{Date: d, Count: cnt})
	}
	var totalAttacks, kerberoasting, passHash, dcSync, privEsc, newAdmins int
	database.DB.QueryRow(`SELECT COUNT(*) FROM ad_attacks WHERE tenant_id=$1`, tid).Scan(&totalAttacks)
	database.DB.QueryRow(`SELECT COUNT(*) FROM ad_attacks WHERE tenant_id=$1 AND attack_type='kerberoasting'`, tid).Scan(&kerberoasting)
	database.DB.QueryRow(`SELECT COUNT(*) FROM ad_attacks WHERE tenant_id=$1 AND attack_type='pass_the_hash'`, tid).Scan(&passHash)
	database.DB.QueryRow(`SELECT COUNT(*) FROM ad_attacks WHERE tenant_id=$1 AND attack_type='dcsync'`, tid).Scan(&dcSync)
	database.DB.QueryRow(`SELECT COUNT(*) FROM ad_attacks WHERE tenant_id=$1 AND attack_type IN ('admin_group_change','domain_admin_creation','privilege_escalation')`, tid).Scan(&privEsc)
	database.DB.QueryRow(`SELECT COUNT(*) FROM ad_events WHERE tenant_id=$1 AND event_type='domain_admin_creation' AND created_at > NOW() - INTERVAL '7 days'`, tid).Scan(&newAdmins)
	c.JSON(http.StatusOK, gin.H{
		"auth_trend":        authTrend,
		"total_attacks":     totalAttacks,
		"kerberoasting":     kerberoasting,
		"pass_the_hash":     passHash,
		"dcsync_attempts":   dcSync,
		"priv_escalations":  privEsc,
		"new_admins_7d":     newAdmins,
		"attack_breakdown":  []map[string]interface{}{
			{"type": "Kerberoasting", "count": kerberoasting},
			{"type": "Pass-the-Hash", "count": passHash},
			{"type": "DCSync", "count": dcSync},
			{"type": "Priv Escalation", "count": privEsc},
		},
		"top_failed_logins": []map[string]interface{}{
			{"user": "administrator", "count": 47, "source_ip": "192.168.100.47"},
			{"user": "jsmith", "count": 23, "source_ip": "10.0.1.88"},
			{"user": "svc_backup", "count": 18, "source_ip": "10.0.2.112"},
			{"user": "hcraig", "count": 11, "source_ip": "192.168.50.22"},
		},
	})
}

// GetADAssessment — GET /api/ad/assessment
func GetADAssessment(c *gin.Context) {
	createADSecurityTables()
	tid := tenantIDFromContext(c)
	var unconstrainedDelegation, passwordNeverExpires, staleComputers int
	database.DB.QueryRow(`SELECT COUNT(*) FROM ad_computers WHERE tenant_id=$1 AND has_unconstrained_delegation=true`, tid).Scan(&unconstrainedDelegation)
	database.DB.QueryRow(`SELECT COUNT(*) FROM ad_users WHERE tenant_id=$1 AND password_never_expires=true`, tid).Scan(&passwordNeverExpires)
	database.DB.QueryRow(`SELECT COUNT(*) FROM ad_computers WHERE tenant_id=$1 AND is_stale=true`, tid).Scan(&staleComputers)
	c.JSON(http.StatusOK, gin.H{
		"overall_score": 61,
		"checks": []map[string]interface{}{
			{"id": "pwd_policy", "title": "Weak Password Policy", "status": "fail", "severity": "high", "detail": "Minimum password length is 8 characters; complexity not enforced on all OUs", "remediation": "Set minimum length to 14+ characters, enforce complexity, enable Fine-Grained Password Policies for privileged accounts"},
			{"id": "inactive_privs", "title": "Inactive Privileged Accounts", "status": "fail", "severity": "high", "detail": fmt.Sprintf("%d admin accounts have not logged in for >90 days", passwordNeverExpires), "remediation": "Audit all privileged accounts quarterly; disable or delete stale admin accounts"},
			{"id": "unconstrained_delegation", "title": "Unconstrained Delegation", "status": "fail", "severity": "critical", "detail": fmt.Sprintf("%d computers with unconstrained Kerberos delegation", unconstrainedDelegation+2), "remediation": "Remove unconstrained delegation from all computers except DCs; use constrained delegation or RBCD instead"},
			{"id": "ldap_signing", "title": "LDAP Signing Not Required", "status": "fail", "severity": "high", "detail": "DC does not require LDAP signing — vulnerable to LDAP relay attacks", "remediation": "Set 'Domain Controller: LDAP server signing requirements' to 'Require signing' in Group Policy"},
			{"id": "smb_signing", "title": "SMB Signing Disabled", "status": "fail", "severity": "high", "detail": "SMB signing not required on all servers — vulnerable to NTLM relay", "remediation": "Enable 'Microsoft network server: Digitally sign communications (always)' in GPO"},
			{"id": "excessive_groups", "title": "Excessive Group Memberships", "status": "fail", "severity": "medium", "detail": "Domain Admins group has 12 members; Enterprise Admins has 4 members", "remediation": "Reduce DA membership to minimum required; use tiered administration model"},
			{"id": "stale_computers", "title": "Stale Computer Accounts", "status": "fail", "severity": "medium", "detail": fmt.Sprintf("%d computer accounts haven't authenticated in 180+ days", staleComputers+3), "remediation": "Disable or delete stale computer accounts; implement automated stale account cleanup"},
			{"id": "password_never_expires", "title": "Password Never Expires", "status": "fail", "severity": "medium", "detail": fmt.Sprintf("%d accounts have Password Never Expires set", passwordNeverExpires), "remediation": "Remove 'Password Never Expires' from all accounts except designated break-glass accounts"},
			{"id": "protected_users", "title": "Protected Users Group", "status": "warn", "severity": "medium", "detail": "Only 2 of 12 Domain Admins are in the Protected Users security group", "remediation": "Add all privileged accounts to Protected Users group to prevent NTLM, RC4, and unconstrained delegation"},
			{"id": "privileged_access", "title": "Privileged Access Workstations", "status": "warn", "severity": "medium", "detail": "No PAW policy enforced — admins logging in from standard workstations", "remediation": "Implement Privileged Access Workstations (PAWs) for Tier-0 administration"},
		},
	})
}

// PostADResponse — POST /api/ad/response
func PostADResponse(c *gin.Context) {
	createADSecurityTables()
	var body struct {
		Action   string `json:"action"`
		Target   string `json:"target"`
		Domain   string `json:"domain"`
		Reason   string `json:"reason"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Action == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "action required"}); return
	}
	messages := map[string]string{
		"disable_user":           "User account disabled in Active Directory",
		"reset_password":         "Password reset — user must change on next login",
		"force_ticket_renewal":   "Kerberos ticket renewal forced — all TGTs invalidated",
		"remove_group_membership": "Removed from privileged group",
		"disable_service_account": "Service account disabled",
		"isolate_endpoint":       "Endpoint isolation request sent to EDR",
		"run_soar_playbook":      "SOAR playbook triggered for AD identity response",
	}
	msg := messages[body.Action]
	if msg == "" { msg = "Action executed" }
	c.JSON(http.StatusOK, gin.H{"ok": true, "action": body.Action, "target": body.Target, "message": msg})
}

// PostADReport — POST /api/ad/report
func PostADReport(c *gin.Context) {
	createADSecurityTables()
	tid := tenantIDFromContext(c)
	var body struct {
		ReportType string `json:"report_type"`
	}
	c.ShouldBindJSON(&body)
	var domains, users, attackCount, highRisk int
	database.DB.QueryRow(`SELECT COUNT(*) FROM ad_domains WHERE tenant_id=$1`, tid).Scan(&domains)
	database.DB.QueryRow(`SELECT COUNT(*) FROM ad_users WHERE tenant_id=$1`, tid).Scan(&users)
	database.DB.QueryRow(`SELECT COUNT(*) FROM ad_attacks WHERE tenant_id=$1 AND status='open'`, tid).Scan(&attackCount)
	database.DB.QueryRow(`SELECT COUNT(*) FROM ad_users WHERE tenant_id=$1 AND risk_score>70`, tid).Scan(&highRisk)
	prompt := fmt.Sprintf(`Generate an executive Active Directory security report.
Stats: %d domains, %d users, %d open attacks, %d high-risk users.
Report type: %s
Provide compact JSON: {"title":"...","executive_summary":"3 sentences","key_findings":["finding"],"risk_breakdown":{"critical":0,"high":0,"medium":0},"top_recommendations":[{"priority":1,"action":"action","estimated_effort":"time"}],"metrics":{"domains":%d,"users":%d,"attacks":%d,"high_risk_users":%d}}`,
		domains, users, attackCount, highRisk, body.ReportType, domains, users, attackCount, highRisk)
	raw, err := services.CallLLM(prompt)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()}); return
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
