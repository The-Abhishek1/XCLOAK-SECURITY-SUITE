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
		"forests":             forests,
		"domains":             domains,
		"domain_controllers":  dcs,
		"domain_trusts":       trusts,
		"high_risk_users":     highRiskUsers,
		"privileged_accounts": privAccounts,
		"active_attacks":      activeAttacks,
		"ad_risk_score":       int(adRiskScore),
		"identity_exposure":   highRiskUsers * 100 / max(privAccounts, 1),
		"failed_logins_24h":   failedLogins,
	})
}

func max(a, b int) int {
	if a > b {
		return a
	}
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
	if domainList == nil {
		domainList = []Domain{}
	}

	c.JSON(http.StatusOK, gin.H{
		"forests":            forests,
		"domains":            domains,
		"domain_controllers": dcs,
		"users":              users,
		"service_accounts":   serviceAccounts,
		"admin_accounts":     admins,
		"computers":          computers,
		"gpos":               gpos,
		"groups":             groups,
		"domain_list":        domainList,
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
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()
	type User struct {
		ID                   int    `json:"id"`
		SAMAccount           string `json:"sam_account"`
		DisplayName          string `json:"display_name"`
		Email                string `json:"email"`
		Department           string `json:"department"`
		IsAdmin              bool   `json:"is_admin"`
		IsServiceAccount     bool   `json:"is_service_account"`
		IsEnabled            bool   `json:"is_enabled"`
		PasswordNeverExpires bool   `json:"password_never_expires"`
		LastLogon            string `json:"last_logon"`
		LastPasswordChange   string `json:"last_password_change"`
		RiskScore            int    `json:"risk_score"`
		CreatedAt            string `json:"created_at"`
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
	if users == nil {
		users = []User{}
	}
	var highRisk, dormant, passwordNeverExpires, adminCount, serviceAccounts int
	database.DB.QueryRow(`SELECT COUNT(*) FROM ad_users WHERE tenant_id=$1 AND risk_score>70`, tid).Scan(&highRisk)
	database.DB.QueryRow(`SELECT COUNT(*) FROM ad_users WHERE tenant_id=$1 AND last_logon < NOW() - INTERVAL '90 days'`, tid).Scan(&dormant)
	database.DB.QueryRow(`SELECT COUNT(*) FROM ad_users WHERE tenant_id=$1 AND password_never_expires=true`, tid).Scan(&passwordNeverExpires)
	database.DB.QueryRow(`SELECT COUNT(*) FROM ad_users WHERE tenant_id=$1 AND is_admin=true`, tid).Scan(&adminCount)
	database.DB.QueryRow(`SELECT COUNT(*) FROM ad_users WHERE tenant_id=$1 AND is_service_account=true`, tid).Scan(&serviceAccounts)
	c.JSON(http.StatusOK, gin.H{
		"users":                  users,
		"high_risk":              highRisk,
		"dormant":                dormant,
		"password_never_expires": passwordNeverExpires,
		"admin_accounts":         adminCount,
		"service_accounts":       serviceAccounts,
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
	if events == nil {
		events = []Event{}
	}
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
			args = append(args, tid)
			i++
		case "credential":
			q += fmt.Sprintf(" AND attack_type IN ('pass_the_hash','credential_dumping','lsass_access','dcsync','dcshadow','skeleton_key','sam_access') AND tenant_id=$%d", i)
			args = append(args, tid)
			i++
		case "privilege":
			q += fmt.Sprintf(" AND attack_type IN ('admin_group_change','domain_admin_creation','sid_history_abuse','privilege_escalation') AND tenant_id=$%d", i)
			args = append(args, tid)
			i++
		case "lateral":
			q += fmt.Sprintf(" AND attack_type IN ('psexec','lateral_smb','lateral_rdp','lateral_winrm','lateral_wmi','lateral_dcom') AND tenant_id=$%d", i)
			args = append(args, tid)
			i++
		}
	} else if v := c.Query("attack_type"); v != "" {
		q += fmt.Sprintf(" AND attack_type=$%d", i)
		args = append(args, v)
		i++
	}
	q += fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d", i)
	args = append(args, limit)
	rows, err := database.DB.Query(q, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
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
	if attacks == nil {
		attacks = []Attack{}
	}
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
	if gpos == nil {
		gpos = []GPO{}
	}
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
	if changes == nil {
		changes = []Change{}
	}
	c.JSON(http.StatusOK, changes)
}

// GetADAttackPaths — GET /api/ad/attack-paths
func GetADAttackPaths(c *gin.Context) {
	createADSecurityTables()
	tid := tenantIDFromContext(c)

	riskIdentities := []map[string]interface{}{}
	idRows, err := database.DB.Query(`
		SELECT sam_account, display_name, is_admin, is_service_account, risk_score
		FROM ad_users WHERE tenant_id=$1 AND (is_admin=true OR is_service_account=true)
		ORDER BY risk_score DESC LIMIT 5`, tid)
	if err == nil {
		defer idRows.Close()
		for idRows.Next() {
			var sam, display string
			var admin, svc bool
			var risk int
			if idRows.Scan(&sam, &display, &admin, &svc, &risk) == nil {
				riskIdentities = append(riskIdentities, map[string]interface{}{
					"sam_account": sam, "display_name": display,
					"is_admin": admin, "is_service_account": svc, "risk_score": risk,
				})
			}
		}
	}

	riskComputers := []map[string]interface{}{}
	compRows, err := database.DB.Query(`
		SELECT name, has_unconstrained_delegation, risk_score
		FROM ad_computers WHERE tenant_id=$1 AND has_unconstrained_delegation=true
		ORDER BY risk_score DESC LIMIT 5`, tid)
	if err == nil {
		defer compRows.Close()
		for compRows.Next() {
			var name string
			var delegation bool
			var risk int
			if compRows.Scan(&name, &delegation, &risk) == nil {
				riskComputers = append(riskComputers, map[string]interface{}{
					"name": name, "has_unconstrained_delegation": delegation, "risk_score": risk,
				})
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"risk_identities": riskIdentities,
		"risk_computers":  riskComputers,
	})
}

// GetADTiering — GET /api/ad/tiering
func GetADTiering(c *gin.Context) {
	createADSecurityTables()
	tid := tenantIDFromContext(c)
	var tier0, tier1, tier2, standardUsers int
	database.DB.QueryRow(`SELECT COUNT(*) FROM ad_domain_controllers WHERE tenant_id=$1`, tid).Scan(&tier0)
	database.DB.QueryRow(`SELECT COUNT(*) FROM ad_users WHERE tenant_id=$1 AND is_admin=true`, tid).Scan(&tier1)
	database.DB.QueryRow(`SELECT COUNT(*) FROM ad_computers WHERE tenant_id=$1`, tid).Scan(&tier2)
	database.DB.QueryRow(`SELECT COUNT(*) FROM ad_users WHERE tenant_id=$1 AND is_admin=false AND is_service_account=false`, tid).Scan(&standardUsers)
	c.JSON(http.StatusOK, gin.H{
		"tier0_assets": []map[string]interface{}{
			{"name": "Domain Controllers", "count": tier0, "type": "dc"},
		},
		"tier1_assets": []map[string]interface{}{
			{"name": "Server Admins", "count": tier1, "type": "admin_user"},
		},
		"tier2_assets": []map[string]interface{}{
			{"name": "Workstations", "count": tier2, "type": "workstation"},
			{"name": "Standard Users", "count": standardUsers, "type": "user"},
		},
	})
}

// GetADExposure — GET /api/ad/exposure
func GetADExposure(c *gin.Context) {
	createADSecurityTables()
	tid := tenantIDFromContext(c)
	var unconstrainedDelegation int
	database.DB.QueryRow(`SELECT COUNT(*) FROM ad_computers WHERE tenant_id=$1 AND has_unconstrained_delegation=true`, tid).Scan(&unconstrainedDelegation)

	affected := []string{}
	rows, err := database.DB.Query(`SELECT name FROM ad_computers WHERE tenant_id=$1 AND has_unconstrained_delegation=true LIMIT 10`, tid)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var name string
			if rows.Scan(&name) == nil {
				affected = append(affected, name)
			}
		}
	}

	findings := []map[string]interface{}{}
	if unconstrainedDelegation > 0 {
		findings = append(findings, map[string]interface{}{
			"type": "unconstrained_delegation", "severity": "critical", "count": unconstrainedDelegation,
			"description": "Computers with unconstrained Kerberos delegation — any authenticated user's TGT is cached",
			"affected":    affected,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"unconstrained_delegation": unconstrainedDelegation,
		"findings":                 findings,
	})
}

// GetADThreatIntel — GET /api/ad/threat-intel
func GetADThreatIntel(c *gin.Context) {
	createADSecurityTables()
	tid := tenantIDFromContext(c)

	iocMatches := []map[string]interface{}{}
	rows, err := database.DB.Query(`
		SELECT indicator, type, hit_count FROM iocs
		WHERE tenant_id=$1 AND enabled=true AND type IN ('ip','hash','sha256','md5')
		ORDER BY hit_count DESC LIMIT 10`, tid)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var indicator, itype string
			var hits int
			if rows.Scan(&indicator, &itype, &hits) == nil {
				iocMatches = append(iocMatches, map[string]interface{}{
					"type": itype, "value": indicator, "hits": hits,
				})
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"ioc_matches": iocMatches,
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
	if events == nil {
		events = []TLEvent{}
	}
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
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
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
	var userCount, computerCount, dcCount, adminCount int
	database.DB.QueryRow(`SELECT COUNT(*) FROM ad_users WHERE tenant_id=$1`, tid).Scan(&userCount)
	database.DB.QueryRow(`SELECT COUNT(*) FROM ad_computers WHERE tenant_id=$1`, tid).Scan(&computerCount)
	database.DB.QueryRow(`SELECT COUNT(*) FROM ad_domain_controllers WHERE tenant_id=$1`, tid).Scan(&dcCount)
	database.DB.QueryRow(`SELECT COUNT(*) FROM ad_users WHERE tenant_id=$1 AND is_admin=true`, tid).Scan(&adminCount)

	nodes := []map[string]interface{}{}
	edges := []map[string]interface{}{}

	type dc struct{ id, name string }
	dcs := []dc{}
	dcRows, err := database.DB.Query(`SELECT id, name, risk_score FROM ad_domain_controllers WHERE tenant_id=$1 LIMIT 3`, tid)
	if err == nil {
		defer dcRows.Close()
		for dcRows.Next() {
			var id, name string
			var risk int
			if dcRows.Scan(&id, &name, &risk) == nil {
				nodeID := "dc-" + id
				nodes = append(nodes, map[string]interface{}{"id": nodeID, "label": name, "type": "domain_controller", "risk": risk})
				dcs = append(dcs, dc{id: nodeID, name: name})
			}
		}
	}

	if adminCount > 0 {
		nodes = append(nodes, map[string]interface{}{"id": "group-domain-admins", "label": "Domain Admins", "type": "group", "risk": 100, "members": adminCount})
		for _, d := range dcs {
			edges = append(edges, map[string]interface{}{"source": "group-domain-admins", "target": d.id, "label": "AdminTo", "risk": "critical"})
		}
	}

	userRows, err := database.DB.Query(`
		SELECT id, sam_account, is_admin, is_service_account, risk_score
		FROM ad_users WHERE tenant_id=$1 AND (is_admin=true OR is_service_account=true)
		ORDER BY risk_score DESC LIMIT 6`, tid)
	if err == nil {
		defer userRows.Close()
		for userRows.Next() {
			var id, sam string
			var admin, svc bool
			var risk int
			if userRows.Scan(&id, &sam, &admin, &svc, &risk) == nil {
				nodeID := "user-" + id
				ntype := "service_account"
				if admin {
					ntype = "user"
				}
				nodes = append(nodes, map[string]interface{}{"id": nodeID, "label": sam, "type": ntype, "risk": risk})
				if admin {
					edges = append(edges, map[string]interface{}{"source": nodeID, "target": "group-domain-admins", "label": "memberOf", "risk": "critical"})
				}
			}
		}
	}

	compRows, err := database.DB.Query(`
		SELECT id, name, risk_score FROM ad_computers
		WHERE tenant_id=$1 AND has_unconstrained_delegation=true LIMIT 5`, tid)
	if err == nil {
		defer compRows.Close()
		for compRows.Next() {
			var id, name string
			var risk int
			if compRows.Scan(&id, &name, &risk) == nil {
				nodeID := "comp-" + id
				nodes = append(nodes, map[string]interface{}{"id": nodeID, "label": name, "type": "computer", "risk": risk})
				if len(dcs) > 0 {
					edges = append(edges, map[string]interface{}{"source": nodeID, "target": dcs[0].id, "label": "UnconstrainedDelegation", "risk": "critical"})
				}
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"nodes": nodes,
		"edges": edges,
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

	topFailedLogins := []map[string]interface{}{}
	flRows, err := database.DB.Query(`
		SELECT source_user, COUNT(*) AS cnt, MAX(source_ip) AS ip
		FROM ad_events WHERE tenant_id=$1 AND event_type='failed_login' AND source_user != ''
		GROUP BY source_user ORDER BY cnt DESC LIMIT 5`, tid)
	if err == nil {
		defer flRows.Close()
		for flRows.Next() {
			var user, ip string
			var cnt int
			if flRows.Scan(&user, &cnt, &ip) == nil {
				topFailedLogins = append(topFailedLogins, map[string]interface{}{
					"user": user, "count": cnt, "source_ip": ip,
				})
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"auth_trend":       authTrend,
		"total_attacks":    totalAttacks,
		"kerberoasting":    kerberoasting,
		"pass_the_hash":    passHash,
		"dcsync_attempts":  dcSync,
		"priv_escalations": privEsc,
		"new_admins_7d":    newAdmins,
		"attack_breakdown": []map[string]interface{}{
			{"type": "Kerberoasting", "count": kerberoasting},
			{"type": "Pass-the-Hash", "count": passHash},
			{"type": "DCSync", "count": dcSync},
			{"type": "Priv Escalation", "count": privEsc},
		},
		"top_failed_logins": topFailedLogins,
	})
}

// GetADAssessment — GET /api/ad/assessment
func GetADAssessment(c *gin.Context) {
	createADSecurityTables()
	tid := tenantIDFromContext(c)
	var unconstrainedDelegation, passwordNeverExpires, staleComputers, inactivePrivileged int
	database.DB.QueryRow(`SELECT COUNT(*) FROM ad_computers WHERE tenant_id=$1 AND has_unconstrained_delegation=true`, tid).Scan(&unconstrainedDelegation)
	database.DB.QueryRow(`SELECT COUNT(*) FROM ad_users WHERE tenant_id=$1 AND password_never_expires=true`, tid).Scan(&passwordNeverExpires)
	database.DB.QueryRow(`SELECT COUNT(*) FROM ad_computers WHERE tenant_id=$1 AND is_stale=true`, tid).Scan(&staleComputers)
	database.DB.QueryRow(`SELECT COUNT(*) FROM ad_users WHERE tenant_id=$1 AND is_admin=true AND last_logon < NOW() - INTERVAL '90 days'`, tid).Scan(&inactivePrivileged)

	checks := []map[string]interface{}{}
	failCount := 0
	addCheck := func(id, title, severity, detail, remediation string, count int) {
		status := "pass"
		if count > 0 {
			status = "fail"
			failCount++
		}
		checks = append(checks, map[string]interface{}{
			"id": id, "title": title, "status": status, "severity": severity,
			"detail": detail, "remediation": remediation,
		})
	}
	addCheck("inactive_privs", "Inactive Privileged Accounts", "high",
		fmt.Sprintf("%d admin accounts have not logged in for >90 days", inactivePrivileged),
		"Audit all privileged accounts quarterly; disable or delete stale admin accounts", inactivePrivileged)
	addCheck("unconstrained_delegation", "Unconstrained Delegation", "critical",
		fmt.Sprintf("%d computers with unconstrained Kerberos delegation", unconstrainedDelegation),
		"Remove unconstrained delegation from all computers except DCs; use constrained delegation or RBCD instead", unconstrainedDelegation)
	addCheck("stale_computers", "Stale Computer Accounts", "medium",
		fmt.Sprintf("%d computer accounts haven't authenticated in 180+ days", staleComputers),
		"Disable or delete stale computer accounts; implement automated stale account cleanup", staleComputers)
	addCheck("password_never_expires", "Password Never Expires", "medium",
		fmt.Sprintf("%d accounts have Password Never Expires set", passwordNeverExpires),
		"Remove 'Password Never Expires' from all accounts except designated break-glass accounts", passwordNeverExpires)

	score := 100 - failCount*20
	if score < 0 {
		score = 0
	}

	c.JSON(http.StatusOK, gin.H{
		"overall_score": score,
		"checks":        checks,
	})
}

// PostADResponse — POST /api/ad/response
func PostADResponse(c *gin.Context) {
	createADSecurityTables()
	tid := tenantIDFromContext(c)
	var body struct {
		Action string `json:"action"`
		Target string `json:"target"`
		Domain string `json:"domain"`
		Reason string `json:"reason"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Action == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "action required"})
		return
	}

	switch body.Action {
	case "disable_user":
		if body.Target == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "target required"})
			return
		}
		res, _ := database.DB.Exec(`UPDATE ad_users SET is_enabled=false WHERE tenant_id=$1 AND sam_account=$2`, tid, body.Target)
		if n, _ := res.RowsAffected(); n == 0 {
			c.JSON(http.StatusNotFound, gin.H{"error": "no matching AD user found"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true, "action": body.Action, "target": body.Target, "message": "User account disabled in Active Directory"})
	case "reset_password":
		if body.Target == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "target required"})
			return
		}
		res, _ := database.DB.Exec(`UPDATE ad_users SET last_password_change=NOW() WHERE tenant_id=$1 AND sam_account=$2`, tid, body.Target)
		if n, _ := res.RowsAffected(); n == 0 {
			c.JSON(http.StatusNotFound, gin.H{"error": "no matching AD user found"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true, "action": body.Action, "target": body.Target, "message": "Password reset — user must change on next login"})
	case "remove_group_membership":
		if body.Target == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "target required"})
			return
		}
		res, _ := database.DB.Exec(`UPDATE ad_users SET is_admin=false WHERE tenant_id=$1 AND sam_account=$2 AND is_admin=true`, tid, body.Target)
		if n, _ := res.RowsAffected(); n == 0 {
			c.JSON(http.StatusOK, gin.H{"ok": true, "action": body.Action, "target": body.Target, "message": "No privileged group membership found for this account"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true, "action": body.Action, "target": body.Target, "message": "Removed from privileged group"})
	case "disable_service_account":
		if body.Target == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "target required"})
			return
		}
		res, _ := database.DB.Exec(`UPDATE ad_users SET is_enabled=false WHERE tenant_id=$1 AND sam_account=$2 AND is_service_account=true`, tid, body.Target)
		if n, _ := res.RowsAffected(); n == 0 {
			c.JSON(http.StatusNotFound, gin.H{"error": "no matching service account found"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true, "action": body.Action, "target": body.Target, "message": "Service account disabled"})
	case "force_ticket_renewal", "isolate_endpoint":
		c.JSON(http.StatusNotImplemented, gin.H{"error": "no real Kerberos KDC / EDR integration configured for this action"})
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "unknown action"})
	}
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
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
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
