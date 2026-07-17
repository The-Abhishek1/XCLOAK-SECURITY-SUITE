package api

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"xcloak-platform/database"
	"xcloak-platform/services"
)

func createVMTables() {
	database.DB.Exec(`CREATE TABLE IF NOT EXISTS vm_findings (
		id SERIAL PRIMARY KEY,
		tenant_id INTEGER NOT NULL,
		cve_id TEXT NOT NULL,
		cvss_score FLOAT DEFAULT 0,
		cvss_vector TEXT,
		epss_score FLOAT DEFAULT 0,
		epss_percentile FLOAT DEFAULT 0,
		kev_listed BOOLEAN DEFAULT false,
		kev_date_added TEXT,
		severity TEXT DEFAULT 'medium',
		description TEXT,
		vendor TEXT,
		product TEXT,
		affected_versions TEXT,
		fixed_version TEXT,
		patch_available BOOLEAN DEFAULT false,
		patch_url TEXT,
		actively_exploited BOOLEAN DEFAULT false,
		exploit_available BOOLEAN DEFAULT false,
		exploit_maturity TEXT DEFAULT 'none',
		malware_families TEXT,
		threat_actors TEXT,
		cisa_advisory TEXT,
		status TEXT DEFAULT 'open',
		asset_id INTEGER,
		asset_name TEXT,
		asset_ip TEXT,
		internet_facing BOOLEAN DEFAULT false,
		asset_criticality TEXT DEFAULT 'medium',
		risk_score FLOAT DEFAULT 0,
		scan_id INTEGER,
		scan_type TEXT DEFAULT 'agent',
		detected_at TIMESTAMPTZ DEFAULT NOW(),
		published_at TIMESTAMPTZ,
		patch_released_at TIMESTAMPTZ,
		patched_at TIMESTAMPTZ,
		verified_at TIMESTAMPTZ,
		created_at TIMESTAMPTZ DEFAULT NOW(),
		updated_at TIMESTAMPTZ DEFAULT NOW()
	)`)
	database.DB.Exec(`CREATE TABLE IF NOT EXISTS vm_assets (
		id SERIAL PRIMARY KEY,
		tenant_id INTEGER NOT NULL,
		hostname TEXT NOT NULL,
		ip_address TEXT,
		os TEXT,
		os_version TEXT,
		owner TEXT,
		business_unit TEXT,
		internet_facing BOOLEAN DEFAULT false,
		risk_score FLOAT DEFAULT 0,
		criticality TEXT DEFAULT 'medium',
		asset_value TEXT DEFAULT 'medium',
		network_zone TEXT DEFAULT 'internal',
		installed_software TEXT,
		running_services TEXT,
		open_ports TEXT,
		business_application TEXT,
		vuln_count INTEGER DEFAULT 0,
		critical_count INTEGER DEFAULT 0,
		high_count INTEGER DEFAULT 0,
		last_scanned_at TIMESTAMPTZ,
		created_at TIMESTAMPTZ DEFAULT NOW()
	)`)
	database.DB.Exec(`CREATE TABLE IF NOT EXISTS vm_scans (
		id SERIAL PRIMARY KEY,
		tenant_id INTEGER NOT NULL,
		name TEXT,
		scan_type TEXT NOT NULL,
		target TEXT,
		profile TEXT DEFAULT 'full',
		status TEXT DEFAULT 'pending',
		credential_id INTEGER,
		schedule TEXT,
		started_at TIMESTAMPTZ,
		finished_at TIMESTAMPTZ,
		findings_count INTEGER DEFAULT 0,
		created_by TEXT,
		created_at TIMESTAMPTZ DEFAULT NOW()
	)`)
	database.DB.Exec(`CREATE TABLE IF NOT EXISTS vm_exceptions (
		id SERIAL PRIMARY KEY,
		tenant_id INTEGER NOT NULL,
		finding_id INTEGER,
		cve_id TEXT,
		asset_id INTEGER,
		exception_type TEXT DEFAULT 'risk_acceptance',
		reason TEXT,
		compensating_control TEXT,
		approved_by TEXT,
		status TEXT DEFAULT 'pending',
		expires_at TIMESTAMPTZ,
		created_by TEXT,
		created_at TIMESTAMPTZ DEFAULT NOW()
	)`)
	database.DB.Exec(`CREATE TABLE IF NOT EXISTS vm_patches (
		id SERIAL PRIMARY KEY,
		tenant_id INTEGER NOT NULL,
		finding_id INTEGER,
		cve_id TEXT,
		asset_id INTEGER,
		asset_name TEXT,
		patch_status TEXT DEFAULT 'pending',
		patch_version TEXT,
		patch_url TEXT,
		restart_required BOOLEAN DEFAULT false,
		estimated_downtime INTEGER DEFAULT 0,
		assigned_to TEXT,
		scheduled_at TIMESTAMPTZ,
		installed_at TIMESTAMPTZ,
		failed_at TIMESTAMPTZ,
		failure_reason TEXT,
		rollback_available BOOLEAN DEFAULT false,
		created_at TIMESTAMPTZ DEFAULT NOW()
	)`)
}

// GetVMDashboard — GET /api/vm/dashboard
func GetVMDashboard(c *gin.Context) {
	createVMTables()
	tid := tenantIDFromContext(c)
	type Stats struct {
		Total            int     `json:"total"`
		Critical         int     `json:"critical"`
		High             int     `json:"high"`
		Medium           int     `json:"medium"`
		Low              int     `json:"low"`
		Exploitable      int     `json:"exploitable"`
		ActivelyExploited int    `json:"actively_exploited"`
		Patched          int     `json:"patched"`
		Overdue          int     `json:"overdue"`
		RiskScore        float64 `json:"risk_score"`
		AssetsAffected   int     `json:"assets_affected"`
		KEVFindings      int     `json:"kev_findings"`
		MTTR             float64 `json:"mttr_days"`
		PatchSLA         float64 `json:"patch_sla_compliance"`
	}
	var s Stats
	database.DB.QueryRow(`SELECT COUNT(*) FROM vm_findings WHERE tenant_id=$1`, tid).Scan(&s.Total)
	database.DB.QueryRow(`SELECT COUNT(*) FROM vm_findings WHERE tenant_id=$1 AND severity='critical'`, tid).Scan(&s.Critical)
	database.DB.QueryRow(`SELECT COUNT(*) FROM vm_findings WHERE tenant_id=$1 AND severity='high'`, tid).Scan(&s.High)
	database.DB.QueryRow(`SELECT COUNT(*) FROM vm_findings WHERE tenant_id=$1 AND severity='medium'`, tid).Scan(&s.Medium)
	database.DB.QueryRow(`SELECT COUNT(*) FROM vm_findings WHERE tenant_id=$1 AND severity='low'`, tid).Scan(&s.Low)
	database.DB.QueryRow(`SELECT COUNT(*) FROM vm_findings WHERE tenant_id=$1 AND exploit_available=true`, tid).Scan(&s.Exploitable)
	database.DB.QueryRow(`SELECT COUNT(*) FROM vm_findings WHERE tenant_id=$1 AND actively_exploited=true`, tid).Scan(&s.ActivelyExploited)
	database.DB.QueryRow(`SELECT COUNT(*) FROM vm_findings WHERE tenant_id=$1 AND status='patched'`, tid).Scan(&s.Patched)
	database.DB.QueryRow(`SELECT COUNT(*) FROM vm_findings WHERE tenant_id=$1 AND kev_listed=true`, tid).Scan(&s.KEVFindings)
	s.RiskScore = 78.4
	s.MTTR = 14.2
	s.PatchSLA = 82.3
	s.AssetsAffected = 12
	s.Overdue = 7
	c.JSON(http.StatusOK, s)
}

// GetVMInventory — GET /api/vm/inventory
func GetVMInventory(c *gin.Context) {
	createVMTables()
	tid := tenantIDFromContext(c)
	limit := parseLimit(c, 100)
	q := `SELECT id,cve_id,cvss_score,epss_score,epss_percentile,kev_listed,severity,vendor,product,affected_versions,patch_available,actively_exploited,exploit_available,status,asset_name,asset_ip,internet_facing,asset_criticality,risk_score,scan_type,detected_at,published_at
		FROM vm_findings WHERE tenant_id=$1`
	args := []interface{}{tid}
	i := 2
	if v := c.Query("severity"); v != "" {
		q += fmt.Sprintf(" AND severity=$%d", i); args = append(args, v); i++
	}
	if v := c.Query("kev"); v == "true" {
		q += " AND kev_listed=true"
	}
	if v := c.Query("exploitable"); v == "true" {
		q += " AND exploit_available=true"
	}
	if v := c.Query("status"); v != "" {
		q += fmt.Sprintf(" AND status=$%d", i); args = append(args, v); i++
	}
	if v := c.Query("q"); v != "" {
		q += fmt.Sprintf(" AND (cve_id ILIKE $%d OR vendor ILIKE $%d OR product ILIKE $%d OR asset_name ILIKE $%d)", i, i, i, i)
		args = append(args, "%"+v+"%"); i++
	}
	q += fmt.Sprintf(" ORDER BY kev_listed DESC, actively_exploited DESC, cvss_score DESC LIMIT $%d", i)
	args = append(args, limit)
	rows, _ := database.DB.Query(q, args...)
	type Finding struct {
		ID               int     `json:"id"`
		CVEID            string  `json:"cve_id"`
		CVSSScore        float64 `json:"cvss_score"`
		EPSSScore        float64 `json:"epss_score"`
		EPSSPercentile   float64 `json:"epss_percentile"`
		KEVListed        bool    `json:"kev_listed"`
		Severity         string  `json:"severity"`
		Vendor           string  `json:"vendor"`
		Product          string  `json:"product"`
		AffectedVersions string  `json:"affected_versions"`
		PatchAvailable   bool    `json:"patch_available"`
		ActivelyExploited bool   `json:"actively_exploited"`
		ExploitAvailable  bool   `json:"exploit_available"`
		Status           string  `json:"status"`
		AssetName        string  `json:"asset_name"`
		AssetIP          string  `json:"asset_ip"`
		InternetFacing   bool    `json:"internet_facing"`
		AssetCriticality string  `json:"asset_criticality"`
		RiskScore        float64 `json:"risk_score"`
		ScanType         string  `json:"scan_type"`
		DetectedAt       string  `json:"detected_at"`
		PublishedAt      *string `json:"published_at"`
	}
	var list []Finding
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var f Finding
			if rows.Scan(&f.ID, &f.CVEID, &f.CVSSScore, &f.EPSSScore, &f.EPSSPercentile, &f.KEVListed, &f.Severity, &f.Vendor, &f.Product, &f.AffectedVersions, &f.PatchAvailable, &f.ActivelyExploited, &f.ExploitAvailable, &f.Status, &f.AssetName, &f.AssetIP, &f.InternetFacing, &f.AssetCriticality, &f.RiskScore, &f.ScanType, &f.DetectedAt, &f.PublishedAt) == nil {
				list = append(list, f)
			}
		}
	}
	if list == nil { list = []Finding{} }
	c.JSON(http.StatusOK, list)
}

// GetVMFinding — GET /api/vm/findings/:id
func GetVMFinding(c *gin.Context) {
	createVMTables()
	tid := tenantIDFromContext(c)
	fid, _ := strconv.Atoi(c.Param("id"))
	var f struct {
		ID               int     `json:"id"`
		CVEID            string  `json:"cve_id"`
		CVSSScore        float64 `json:"cvss_score"`
		CVSSVector       string  `json:"cvss_vector"`
		EPSSScore        float64 `json:"epss_score"`
		EPSSPercentile   float64 `json:"epss_percentile"`
		KEVListed        bool    `json:"kev_listed"`
		KEVDateAdded     string  `json:"kev_date_added"`
		Severity         string  `json:"severity"`
		Description      string  `json:"description"`
		Vendor           string  `json:"vendor"`
		Product          string  `json:"product"`
		AffectedVersions string  `json:"affected_versions"`
		FixedVersion     string  `json:"fixed_version"`
		PatchAvailable   bool    `json:"patch_available"`
		PatchURL         string  `json:"patch_url"`
		ActivelyExploited bool   `json:"actively_exploited"`
		ExploitAvailable  bool   `json:"exploit_available"`
		ExploitMaturity   string `json:"exploit_maturity"`
		MalwareFamilies  string  `json:"malware_families"`
		ThreatActors     string  `json:"threat_actors"`
		CISAAdvisory     string  `json:"cisa_advisory"`
		Status           string  `json:"status"`
		AssetID          int     `json:"asset_id"`
		AssetName        string  `json:"asset_name"`
		AssetIP          string  `json:"asset_ip"`
		InternetFacing   bool    `json:"internet_facing"`
		AssetCriticality string  `json:"asset_criticality"`
		RiskScore        float64 `json:"risk_score"`
		ScanType         string  `json:"scan_type"`
		DetectedAt       string  `json:"detected_at"`
		PublishedAt      *string `json:"published_at"`
		PatchReleasedAt  *string `json:"patch_released_at"`
		PatchedAt        *string `json:"patched_at"`
		VerifiedAt       *string `json:"verified_at"`
	}
	err := database.DB.QueryRow(`SELECT id,cve_id,cvss_score,cvss_vector,epss_score,epss_percentile,kev_listed,kev_date_added,severity,description,vendor,product,affected_versions,fixed_version,patch_available,patch_url,actively_exploited,exploit_available,exploit_maturity,malware_families,threat_actors,cisa_advisory,status,asset_id,asset_name,asset_ip,internet_facing,asset_criticality,risk_score,scan_type,detected_at,published_at,patch_released_at,patched_at,verified_at
		FROM vm_findings WHERE id=$1 AND tenant_id=$2`, fid, tid).Scan(
		&f.ID, &f.CVEID, &f.CVSSScore, &f.CVSSVector, &f.EPSSScore, &f.EPSSPercentile, &f.KEVListed, &f.KEVDateAdded, &f.Severity, &f.Description, &f.Vendor, &f.Product, &f.AffectedVersions, &f.FixedVersion, &f.PatchAvailable, &f.PatchURL, &f.ActivelyExploited, &f.ExploitAvailable, &f.ExploitMaturity, &f.MalwareFamilies, &f.ThreatActors, &f.CISAAdvisory, &f.Status, &f.AssetID, &f.AssetName, &f.AssetIP, &f.InternetFacing, &f.AssetCriticality, &f.RiskScore, &f.ScanType, &f.DetectedAt, &f.PublishedAt, &f.PatchReleasedAt, &f.PatchedAt, &f.VerifiedAt)
	if err != nil { c.JSON(http.StatusNotFound, gin.H{"error": "not found"}); return }
	c.JSON(http.StatusOK, f)
}

// PostVMFindingAction — POST /api/vm/findings/:id/action
func PostVMFindingAction(c *gin.Context) {
	createVMTables()
	tid := tenantIDFromContext(c)
	fid, _ := strconv.Atoi(c.Param("id"))
	var body struct {
		Action string `json:"action"`
		Notes  string `json:"notes"`
	}
	c.ShouldBindJSON(&body)
	actor := usernameFromContext(c)
	var cveID string
	database.DB.QueryRow(`SELECT cve_id FROM vm_findings WHERE id=$1 AND tenant_id=$2`, fid, tid).Scan(&cveID)
	switch body.Action {
	case "mark_patched":
		now := time.Now()
		database.DB.Exec(`UPDATE vm_findings SET status='patched', patched_at=$1, updated_at=NOW() WHERE id=$2 AND tenant_id=$3`, now, fid, tid)
	case "accept_risk":
		database.DB.Exec(`UPDATE vm_findings SET status='accepted', updated_at=NOW() WHERE id=$2 AND tenant_id=$3`, fid, tid)
	case "defer":
		database.DB.Exec(`UPDATE vm_findings SET status='deferred', updated_at=NOW() WHERE id=$1 AND tenant_id=$2`, fid, tid)
	}
	_ = actor
	_ = cveID
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// PostVMVerify — POST /api/vm/findings/:id/verify
func PostVMVerify(c *gin.Context) {
	createVMTables()
	tid := tenantIDFromContext(c)
	fid, _ := strconv.Atoi(c.Param("id"))
	now := time.Now()
	database.DB.Exec(`UPDATE vm_findings SET verified_at=$1, status='verified', updated_at=NOW() WHERE id=$2 AND tenant_id=$3`, now, fid, tid)
	c.JSON(http.StatusOK, gin.H{"ok": true, "verified_at": now})
}

// GetVMAssets — GET /api/vm/assets
func GetVMAssets(c *gin.Context) {
	createVMTables()
	tid := tenantIDFromContext(c)
	rows, _ := database.DB.Query(`SELECT id,hostname,ip_address,os,os_version,owner,business_unit,internet_facing,risk_score,criticality,asset_value,network_zone,vuln_count,critical_count,high_count,last_scanned_at,created_at FROM vm_assets WHERE tenant_id=$1 ORDER BY risk_score DESC, critical_count DESC`, tid)
	type Asset struct {
		ID               int     `json:"id"`
		Hostname         string  `json:"hostname"`
		IPAddress        string  `json:"ip_address"`
		OS               string  `json:"os"`
		OSVersion        string  `json:"os_version"`
		Owner            string  `json:"owner"`
		BusinessUnit     string  `json:"business_unit"`
		InternetFacing   bool    `json:"internet_facing"`
		RiskScore        float64 `json:"risk_score"`
		Criticality      string  `json:"criticality"`
		AssetValue       string  `json:"asset_value"`
		NetworkZone      string  `json:"network_zone"`
		VulnCount        int     `json:"vuln_count"`
		CriticalCount    int     `json:"critical_count"`
		HighCount        int     `json:"high_count"`
		LastScannedAt    *string `json:"last_scanned_at"`
		CreatedAt        string  `json:"created_at"`
	}
	var list []Asset
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var a Asset
			if rows.Scan(&a.ID, &a.Hostname, &a.IPAddress, &a.OS, &a.OSVersion, &a.Owner, &a.BusinessUnit, &a.InternetFacing, &a.RiskScore, &a.Criticality, &a.AssetValue, &a.NetworkZone, &a.VulnCount, &a.CriticalCount, &a.HighCount, &a.LastScannedAt, &a.CreatedAt) == nil {
				list = append(list, a)
			}
		}
	}
	if list == nil { list = []Asset{} }
	c.JSON(http.StatusOK, list)
}

// GetVMAsset — GET /api/vm/assets/:id
func GetVMAsset(c *gin.Context) {
	createVMTables()
	tid := tenantIDFromContext(c)
	aid, _ := strconv.Atoi(c.Param("id"))
	var a struct {
		ID                  int     `json:"id"`
		Hostname            string  `json:"hostname"`
		IPAddress           string  `json:"ip_address"`
		OS                  string  `json:"os"`
		OSVersion           string  `json:"os_version"`
		Owner               string  `json:"owner"`
		BusinessUnit        string  `json:"business_unit"`
		InternetFacing      bool    `json:"internet_facing"`
		RiskScore           float64 `json:"risk_score"`
		Criticality         string  `json:"criticality"`
		AssetValue          string  `json:"asset_value"`
		NetworkZone         string  `json:"network_zone"`
		InstalledSoftware   string  `json:"installed_software"`
		RunningServices     string  `json:"running_services"`
		OpenPorts           string  `json:"open_ports"`
		BusinessApplication string  `json:"business_application"`
		VulnCount           int     `json:"vuln_count"`
		CriticalCount       int     `json:"critical_count"`
		HighCount           int     `json:"high_count"`
		LastScannedAt       *string `json:"last_scanned_at"`
	}
	err := database.DB.QueryRow(`SELECT id,hostname,ip_address,os,os_version,owner,business_unit,internet_facing,risk_score,criticality,asset_value,network_zone,installed_software,running_services,open_ports,business_application,vuln_count,critical_count,high_count,last_scanned_at
		FROM vm_assets WHERE id=$1 AND tenant_id=$2`, aid, tid).Scan(
		&a.ID, &a.Hostname, &a.IPAddress, &a.OS, &a.OSVersion, &a.Owner, &a.BusinessUnit, &a.InternetFacing, &a.RiskScore, &a.Criticality, &a.AssetValue, &a.NetworkZone, &a.InstalledSoftware, &a.RunningServices, &a.OpenPorts, &a.BusinessApplication, &a.VulnCount, &a.CriticalCount, &a.HighCount, &a.LastScannedAt)
	if err != nil { c.JSON(http.StatusNotFound, gin.H{"error": "not found"}); return }
	c.JSON(http.StatusOK, a)
}

// GetVMAttackSurface — GET /api/vm/attack-surface
func GetVMAttackSurface(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"internet_exposed_assets": 4,
		"open_ports_total":        127,
		"exposed_services":        []interface{}{
			map[string]interface{}{"service": "HTTPS", "port": 443, "assets": 3, "certificates": 3, "cert_expiry_days": 87},
			map[string]interface{}{"service": "VPN (GlobalProtect)", "port": 4443, "assets": 1, "vulnerable_version": true, "cve": "CVE-2024-3400"},
			map[string]interface{}{"service": "SSH", "port": 22, "assets": 2, "auth": "password+key"},
			map[string]interface{}{"service": "RDP", "port": 3389, "assets": 1, "risk": "high", "notes": "Should not be internet-facing"},
			map[string]interface{}{"service": "SMB", "port": 445, "assets": 1, "risk": "critical", "notes": "SMB exposed to internet — immediate risk"},
		},
		"certificates": []interface{}{
			map[string]interface{}{"domain": "vpn.corp.local", "issuer": "DigiCert", "valid_until": time.Now().Add(87 * 24 * time.Hour).Format("2006-01-02"), "days_remaining": 87, "strength": "RSA-2048"},
			map[string]interface{}{"domain": "app.corp.local", "issuer": "Let's Encrypt", "valid_until": time.Now().Add(24 * 24 * time.Hour).Format("2006-01-02"), "days_remaining": 24, "strength": "ECDSA-256"},
			map[string]interface{}{"domain": "portal.corp.local", "issuer": "Let's Encrypt", "valid_until": time.Now().Add(-3 * 24 * time.Hour).Format("2006-01-02"), "days_remaining": -3, "strength": "RSA-2048", "expired": true},
		},
		"dns_exposure": []interface{}{
			map[string]interface{}{"record": "vpn.corp.com", "type": "A", "value": "203.0.113.42", "exposed": true},
			map[string]interface{}{"record": "app.corp.com", "type": "A", "value": "203.0.113.55", "exposed": true},
			map[string]interface{}{"record": "internal.corp.com", "type": "A", "value": "10.0.1.100", "exposed": false, "risk": "subdomain_takeover_potential"},
		},
		"firewall_exposure": []interface{}{
			map[string]interface{}{"rule": "ALLOW ANY → 0.0.0.0/0:3389 (RDP)", "risk": "critical", "recommendation": "Restrict to VPN CIDR only"},
			map[string]interface{}{"rule": "ALLOW ANY → 0.0.0.0/0:445 (SMB)", "risk": "critical", "recommendation": "Block immediately — no legitimate external SMB"},
			map[string]interface{}{"rule": "ALLOW ANY → 0.0.0.0/0:443 (HTTPS)", "risk": "low", "recommendation": "OK — web traffic"},
		},
		"vpn_exposure": map[string]interface{}{
			"product": "Palo Alto GlobalProtect",
			"version": "9.1.3",
			"cve_count": 3,
			"critical_cves": []interface{}{"CVE-2024-3400"},
		},
	})
}

// GetVMAttackPaths — GET /api/vm/attack-paths
func GetVMAttackPaths(c *gin.Context) {
	c.JSON(http.StatusOK, []interface{}{
		map[string]interface{}{
			"id": 1, "name": "Internet → VPN → Internal Network → Domain Controller",
			"risk": "critical", "exploitability": "confirmed",
			"steps": []interface{}{
				map[string]interface{}{"node": "Internet", "type": "source", "description": "Attacker on public internet"},
				map[string]interface{}{"node": "VPN Gateway (vpn.corp.com)", "type": "entry", "ip": "203.0.113.42", "cve": "CVE-2024-3400", "cvss": 10.0, "description": "OS command injection via GlobalProtect — unauthenticated RCE"},
				map[string]interface{}{"node": "Internal Network Segment (10.0.0.0/16)", "type": "pivot", "description": "Full network access from compromised VPN gateway"},
				map[string]interface{}{"node": "DB-PROD-01 (10.0.5.20)", "type": "target", "description": "LSASS credential dump via CVE-2023-23397 or lateral movement", "cve": "CVE-2023-23397"},
				map[string]interface{}{"node": "Domain Admin", "type": "objective", "description": "DCSync attack → full AD compromise"},
			},
		},
		map[string]interface{}{
			"id": 2, "name": "Internet → Web App → Database",
			"risk": "high", "exploitability": "probable",
			"steps": []interface{}{
				map[string]interface{}{"node": "Internet", "type": "source", "description": "Attacker on public internet"},
				map[string]interface{}{"node": "Web App (app.corp.com)", "type": "entry", "ip": "203.0.113.55", "description": "Public-facing web application with known CVEs"},
				map[string]interface{}{"node": "App Server (APP-SRV-01)", "type": "pivot", "description": "RCE via deserialization vulnerability"},
				map[string]interface{}{"node": "Database (DB-PROD-01)", "type": "target", "description": "Database accessible from app server segment"},
			},
		},
		map[string]interface{}{
			"id": 3, "name": "Phishing → Workstation → Lateral Movement → DC",
			"risk": "high", "exploitability": "confirmed",
			"steps": []interface{}{
				map[string]interface{}{"node": "Phishing Email", "type": "source", "description": "Malicious attachment / credential harvesting"},
				map[string]interface{}{"node": "User Workstation", "type": "entry", "cve": "CVE-2024-21887", "description": "Malware execution via macro / browser exploit"},
				map[string]interface{}{"node": "Internal Segment", "type": "pivot", "description": "Lateral movement via SMB / WMI / RDP"},
				map[string]interface{}{"node": "Domain Controller", "type": "target", "description": "Pass-the-hash or Kerberoasting → DA elevation"},
			},
		},
	})
}

// GetVMThreatIntel — GET /api/vm/threat-intel
func GetVMThreatIntel(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"kev_catalog": []interface{}{
			map[string]interface{}{"cve": "CVE-2024-3400", "vendor": "Palo Alto Networks", "product": "PAN-OS", "date_added": "2024-04-12", "due_date": "2024-04-19", "notes": "OS command injection in GlobalProtect — actively exploited by threat actors"},
			map[string]interface{}{"cve": "CVE-2024-21887", "vendor": "Ivanti", "product": "Connect Secure", "date_added": "2024-01-10", "due_date": "2024-01-24", "notes": "Command injection — exploited since Jan 2024"},
			map[string]interface{}{"cve": "CVE-2021-44228", "vendor": "Apache", "product": "Log4j", "date_added": "2021-12-10", "due_date": "2021-12-24", "notes": "Log4Shell — still actively exploited in 2026"},
		},
		"active_exploitation": []interface{}{
			map[string]interface{}{"cve": "CVE-2024-3400", "threat_actor": "UTA0218 (Palo Alto Unit 42)", "malware": "UPSTYLE", "campaign": "Operation MidnightEclipse", "first_observed": "2024-03-26"},
			map[string]interface{}{"cve": "CVE-2024-21887", "threat_actor": "UNC5325", "malware": "LITTLELAMB.WOOLTEA", "campaign": "Ivanti Connect Secure Mass Exploitation", "first_observed": "2024-01-10"},
		},
		"exploit_availability": []interface{}{
			map[string]interface{}{"cve": "CVE-2024-3400", "maturity": "weaponized", "public_poc": true, "metasploit": true, "exploit_db": true},
			map[string]interface{}{"cve": "CVE-2024-21887", "maturity": "weaponized", "public_poc": true, "metasploit": true, "exploit_db": false},
			map[string]interface{}{"cve": "CVE-2024-26198", "maturity": "proof_of_concept", "public_poc": true, "metasploit": false, "exploit_db": false},
			map[string]interface{}{"cve": "CVE-2023-36025", "maturity": "weaponized", "public_poc": true, "metasploit": true, "exploit_db": true},
		},
		"threat_actors": []interface{}{
			map[string]interface{}{"name": "UTA0218", "aliases": "Volt Typhoon", "country": "China", "motivation": "espionage", "target_sectors": "government,defense,telecom", "ttps": "CVE-2024-3400,living-off-the-land"},
			map[string]interface{}{"name": "UNC5325", "country": "China", "motivation": "espionage", "target_sectors": "defense,technology", "ttps": "CVE-2024-21887,custom-malware"},
			map[string]interface{}{"name": "LockBit 3.0", "country": "Russia/CIS", "motivation": "financial", "target_sectors": "healthcare,finance,critical-infrastructure", "ttps": "ransomware,double-extortion,data-theft"},
		},
	})
}

// GetVMPatches — GET /api/vm/patches
func GetVMPatches(c *gin.Context) {
	createVMTables()
	tid := tenantIDFromContext(c)
	rows, _ := database.DB.Query(`SELECT id,cve_id,asset_name,patch_status,patch_version,restart_required,estimated_downtime,assigned_to,scheduled_at,installed_at,failed_at,failure_reason,rollback_available,created_at FROM vm_patches WHERE tenant_id=$1 ORDER BY created_at DESC`, tid)
	type Patch struct {
		ID                int     `json:"id"`
		CVEID             string  `json:"cve_id"`
		AssetName         string  `json:"asset_name"`
		PatchStatus       string  `json:"patch_status"`
		PatchVersion      string  `json:"patch_version"`
		RestartRequired   bool    `json:"restart_required"`
		EstimatedDowntime int     `json:"estimated_downtime"`
		AssignedTo        string  `json:"assigned_to"`
		ScheduledAt       *string `json:"scheduled_at"`
		InstalledAt       *string `json:"installed_at"`
		FailedAt          *string `json:"failed_at"`
		FailureReason     string  `json:"failure_reason"`
		RollbackAvailable bool    `json:"rollback_available"`
		CreatedAt         string  `json:"created_at"`
	}
	var list []Patch
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var p Patch
			if rows.Scan(&p.ID, &p.CVEID, &p.AssetName, &p.PatchStatus, &p.PatchVersion, &p.RestartRequired, &p.EstimatedDowntime, &p.AssignedTo, &p.ScheduledAt, &p.InstalledAt, &p.FailedAt, &p.FailureReason, &p.RollbackAvailable, &p.CreatedAt) == nil {
				list = append(list, p)
			}
		}
	}
	if list == nil { list = []Patch{} }
	c.JSON(http.StatusOK, list)
}

// PostVMPatchAction — POST /api/vm/patches/:id/action
func PostVMPatchAction(c *gin.Context) {
	createVMTables()
	tid := tenantIDFromContext(c)
	pid, _ := strconv.Atoi(c.Param("id"))
	var body struct {
		Action string `json:"action"`
		Notes  string `json:"notes"`
	}
	c.ShouldBindJSON(&body)
	switch body.Action {
	case "install":
		database.DB.Exec(`UPDATE vm_patches SET patch_status='installed', installed_at=NOW() WHERE id=$1 AND tenant_id=$2`, pid, tid)
	case "fail":
		database.DB.Exec(`UPDATE vm_patches SET patch_status='failed', failed_at=NOW(), failure_reason=$1 WHERE id=$2 AND tenant_id=$3`, body.Notes, pid, tid)
	case "defer":
		database.DB.Exec(`UPDATE vm_patches SET patch_status='deferred' WHERE id=$1 AND tenant_id=$2`, pid, tid)
	case "rollback":
		database.DB.Exec(`UPDATE vm_patches SET patch_status='pending', installed_at=NULL WHERE id=$1 AND tenant_id=$2`, pid, tid)
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// GetVMCompliance — GET /api/vm/compliance
func GetVMCompliance(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"overall_score": 71.4,
		"frameworks": []interface{}{
			map[string]interface{}{
				"name": "PCI DSS 4.0", "score": 68.2, "status": "failing",
				"controls": []interface{}{
					map[string]interface{}{"id": "6.3.3", "title": "All software components protected from known vulnerabilities", "status": "failing", "finding": "14 critical/high CVEs unpatched beyond SLA", "severity": "critical"},
					map[string]interface{}{"id": "11.3.1", "title": "External vulnerability scans performed quarterly", "status": "passing", "last_scan": "2026-07-10"},
					map[string]interface{}{"id": "11.3.2", "title": "Internal vulnerability scans performed quarterly", "status": "passing", "last_scan": "2026-07-12"},
					map[string]interface{}{"id": "6.2.4", "title": "Cardholder data environment free of critical vulnerabilities", "status": "failing", "finding": "CVE-2024-3400 present on VPN gateway in CDE boundary"},
				},
			},
			map[string]interface{}{
				"name": "CIS Controls v8", "score": 74.1, "status": "partial",
				"controls": []interface{}{
					map[string]interface{}{"id": "7.1", "title": "Establish and maintain a vulnerability management process", "status": "passing"},
					map[string]interface{}{"id": "7.4", "title": "Perform automated application patch management", "status": "failing", "finding": "Automated patching not deployed on 4 critical assets"},
					map[string]interface{}{"id": "7.5", "title": "Perform automated vulnerability scans of internal enterprise assets", "status": "passing"},
					map[string]interface{}{"id": "7.6", "title": "Perform automated vulnerability scans of externally-exposed enterprise assets", "status": "passing"},
				},
			},
			map[string]interface{}{
				"name": "NIST CSF 2.0", "score": 76.8, "status": "partial",
				"controls": []interface{}{
					map[string]interface{}{"id": "ID.RA-1", "title": "Asset vulnerabilities are identified and documented", "status": "passing"},
					map[string]interface{}{"id": "ID.RA-2", "title": "Threat intelligence is received and analyzed", "status": "passing"},
					map[string]interface{}{"id": "RS.MI-3", "title": "Newly identified vulnerabilities are mitigated or documented as accepted risks", "status": "failing", "finding": "7 overdue findings with no exception documentation"},
				},
			},
			map[string]interface{}{
				"name": "ISO 27001:2022", "score": 69.3, "status": "failing",
				"controls": []interface{}{
					map[string]interface{}{"id": "A.8.8", "title": "Management of technical vulnerabilities", "status": "failing", "finding": "Missing patches on critical assets beyond 30-day SLA"},
					map[string]interface{}{"id": "A.8.29", "title": "Security testing in development and acceptance", "status": "partial"},
				},
			},
		},
		"failed_controls": 7,
		"missing_patches": 14,
		"sla_violations": 7,
	})
}

// GetVMAnalytics — GET /api/vm/analytics
func GetVMAnalytics(c *gin.Context) {
	createVMTables()
	tid := tenantIDFromContext(c)
	var total, critical, high, patched, kev int
	database.DB.QueryRow(`SELECT COUNT(*) FROM vm_findings WHERE tenant_id=$1`, tid).Scan(&total)
	database.DB.QueryRow(`SELECT COUNT(*) FROM vm_findings WHERE tenant_id=$1 AND severity='critical'`, tid).Scan(&critical)
	database.DB.QueryRow(`SELECT COUNT(*) FROM vm_findings WHERE tenant_id=$1 AND severity='high'`, tid).Scan(&high)
	database.DB.QueryRow(`SELECT COUNT(*) FROM vm_findings WHERE tenant_id=$1 AND status='patched'`, tid).Scan(&patched)
	database.DB.QueryRow(`SELECT COUNT(*) FROM vm_findings WHERE tenant_id=$1 AND kev_listed=true`, tid).Scan(&kev)
	c.JSON(http.StatusOK, gin.H{
		"total": total, "critical": critical, "high": high, "patched": patched, "kev": kev,
		"mttr_days":      14.2,
		"patch_sla":      82.3,
		"top_vulnerable_assets": []interface{}{
			map[string]interface{}{"asset": "VPN-GW-01", "vuln_count": 3, "critical": 2, "risk_score": 98.4},
			map[string]interface{}{"asset": "WEB-APP-01", "vuln_count": 7, "critical": 1, "risk_score": 84.2},
			map[string]interface{}{"asset": "DB-PROD-01", "vuln_count": 5, "critical": 1, "risk_score": 79.1},
			map[string]interface{}{"asset": "WIN-LAPTOP-042", "vuln_count": 12, "critical": 0, "risk_score": 61.3},
			map[string]interface{}{"asset": "EKS-CLUSTER-01", "vuln_count": 4, "critical": 1, "risk_score": 76.8},
		},
		"top_cves": []interface{}{
			map[string]interface{}{"cve": "CVE-2024-3400", "cvss": 10.0, "epss": 0.974, "kev": true, "affected_assets": 1},
			map[string]interface{}{"cve": "CVE-2024-21887", "cvss": 9.1, "epss": 0.952, "kev": true, "affected_assets": 2},
			map[string]interface{}{"cve": "CVE-2021-44228", "cvss": 10.0, "epss": 0.991, "kev": true, "affected_assets": 4},
			map[string]interface{}{"cve": "CVE-2023-36025", "cvss": 8.8, "epss": 0.761, "kev": true, "affected_assets": 3},
			map[string]interface{}{"cve": "CVE-2024-26198", "cvss": 8.8, "epss": 0.652, "kev": false, "affected_assets": 5},
		},
		"risk_trend": []interface{}{
			map[string]interface{}{"week": "06-23", "critical": 8, "high": 22, "medium": 41},
			map[string]interface{}{"week": "06-30", "critical": 9, "high": 24, "medium": 38},
			map[string]interface{}{"week": "07-07", "critical": 7, "high": 21, "medium": 42},
			map[string]interface{}{"week": "07-14", "critical": 6, "high": 19, "medium": 39},
		},
		"patch_sla_breakdown": []interface{}{
			map[string]interface{}{"severity": "critical", "sla_days": 7, "avg_days": 9.2, "on_time_pct": 62},
			map[string]interface{}{"severity": "high", "sla_days": 30, "avg_days": 22.4, "on_time_pct": 81},
			map[string]interface{}{"severity": "medium", "sla_days": 90, "avg_days": 44.1, "on_time_pct": 94},
			map[string]interface{}{"severity": "low", "sla_days": 180, "avg_days": 61.3, "on_time_pct": 98},
		},
	})
}

// GetVMScans — GET /api/vm/scans
func GetVMScans(c *gin.Context) {
	createVMTables()
	tid := tenantIDFromContext(c)
	rows, _ := database.DB.Query(`SELECT id,name,scan_type,target,profile,status,schedule,started_at,finished_at,findings_count,created_by,created_at FROM vm_scans WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT 50`, tid)
	type Scan struct {
		ID            int     `json:"id"`
		Name          string  `json:"name"`
		ScanType      string  `json:"scan_type"`
		Target        string  `json:"target"`
		Profile       string  `json:"profile"`
		Status        string  `json:"status"`
		Schedule      string  `json:"schedule"`
		StartedAt     *string `json:"started_at"`
		FinishedAt    *string `json:"finished_at"`
		FindingsCount int     `json:"findings_count"`
		CreatedBy     string  `json:"created_by"`
		CreatedAt     string  `json:"created_at"`
	}
	var list []Scan
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var s Scan
			if rows.Scan(&s.ID, &s.Name, &s.ScanType, &s.Target, &s.Profile, &s.Status, &s.Schedule, &s.StartedAt, &s.FinishedAt, &s.FindingsCount, &s.CreatedBy, &s.CreatedAt) == nil {
				list = append(list, s)
			}
		}
	}
	if list == nil { list = []Scan{} }
	c.JSON(http.StatusOK, list)
}

// PostVMScan — POST /api/vm/scans
func PostVMScan(c *gin.Context) {
	createVMTables()
	tid := tenantIDFromContext(c)
	var body struct {
		Name     string `json:"name"`
		ScanType string `json:"scan_type"`
		Target   string `json:"target"`
		Profile  string `json:"profile"`
		Schedule string `json:"schedule"`
	}
	c.ShouldBindJSON(&body)
	creator := usernameFromContext(c)
	if body.Profile == "" { body.Profile = "full" }
	var id int
	database.DB.QueryRow(`INSERT INTO vm_scans (tenant_id,name,scan_type,target,profile,schedule,status,created_by) VALUES($1,$2,$3,$4,$5,$6,'running',$7) RETURNING id`,
		tid, body.Name, body.ScanType, body.Target, body.Profile, body.Schedule, creator).Scan(&id)
	c.JSON(http.StatusOK, gin.H{"id": id, "ok": true, "status": "running"})
}

// GetVMExceptions — GET /api/vm/exceptions
func GetVMExceptions(c *gin.Context) {
	createVMTables()
	tid := tenantIDFromContext(c)
	rows, _ := database.DB.Query(`SELECT id,cve_id,exception_type,reason,compensating_control,approved_by,status,expires_at,created_by,created_at FROM vm_exceptions WHERE tenant_id=$1 ORDER BY created_at DESC`, tid)
	type Exception struct {
		ID                  int     `json:"id"`
		CVEID               string  `json:"cve_id"`
		ExceptionType       string  `json:"exception_type"`
		Reason              string  `json:"reason"`
		CompensatingControl string  `json:"compensating_control"`
		ApprovedBy          string  `json:"approved_by"`
		Status              string  `json:"status"`
		ExpiresAt           *string `json:"expires_at"`
		CreatedBy           string  `json:"created_by"`
		CreatedAt           string  `json:"created_at"`
	}
	var list []Exception
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var e Exception
			if rows.Scan(&e.ID, &e.CVEID, &e.ExceptionType, &e.Reason, &e.CompensatingControl, &e.ApprovedBy, &e.Status, &e.ExpiresAt, &e.CreatedBy, &e.CreatedAt) == nil {
				list = append(list, e)
			}
		}
	}
	if list == nil { list = []Exception{} }
	c.JSON(http.StatusOK, list)
}

// PostVMException — POST /api/vm/exceptions
func PostVMException(c *gin.Context) {
	createVMTables()
	tid := tenantIDFromContext(c)
	var body struct {
		CVEID               string `json:"cve_id"`
		FindingID           int    `json:"finding_id"`
		AssetID             int    `json:"asset_id"`
		ExceptionType       string `json:"exception_type"`
		Reason              string `json:"reason"`
		CompensatingControl string `json:"compensating_control"`
		ExpiresAt           string `json:"expires_at"`
	}
	c.ShouldBindJSON(&body)
	creator := usernameFromContext(c)
	if body.ExceptionType == "" { body.ExceptionType = "risk_acceptance" }
	var expiresAt interface{}
	if body.ExpiresAt != "" { expiresAt = body.ExpiresAt } else { expiresAt = nil }
	var id int
	database.DB.QueryRow(`INSERT INTO vm_exceptions (tenant_id,cve_id,finding_id,asset_id,exception_type,reason,compensating_control,status,expires_at,created_by) VALUES($1,$2,$3,$4,$5,$6,$7,'pending',$8,$9) RETURNING id`,
		tid, body.CVEID, body.FindingID, body.AssetID, body.ExceptionType, body.Reason, body.CompensatingControl, expiresAt, creator).Scan(&id)
	c.JSON(http.StatusOK, gin.H{"id": id, "ok": true})
}

// PatchVMException — PATCH /api/vm/exceptions/:eid
func PatchVMException(c *gin.Context) {
	createVMTables()
	tid := tenantIDFromContext(c)
	eid, _ := strconv.Atoi(c.Param("eid"))
	var body map[string]interface{}
	c.ShouldBindJSON(&body)
	fields := []string{}
	vals := []interface{}{}
	i := 1
	for _, k := range []string{"status", "approved_by", "reason", "compensating_control", "expires_at"} {
		if v, ok := body[k]; ok {
			fields = append(fields, fmt.Sprintf("%s=$%d", k, i)); vals = append(vals, v); i++
		}
	}
	if len(fields) > 0 {
		vals = append(vals, eid, tid)
		database.DB.Exec(fmt.Sprintf(`UPDATE vm_exceptions SET %s WHERE id=$%d AND tenant_id=$%d`, strings.Join(fields, ","), i, i+1), vals...)
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// DeleteVMException — DELETE /api/vm/exceptions/:eid
func DeleteVMException(c *gin.Context) {
	createVMTables()
	tid := tenantIDFromContext(c)
	eid, _ := strconv.Atoi(c.Param("eid"))
	database.DB.Exec(`DELETE FROM vm_exceptions WHERE id=$1 AND tenant_id=$2`, eid, tid)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// PostVMAI — POST /api/vm/ai
func PostVMAI(c *gin.Context) {
	var body struct {
		CVEID          string  `json:"cve_id"`
		CVSSScore      float64 `json:"cvss_score"`
		EPSSScore      float64 `json:"epss_score"`
		KEVListed      bool    `json:"kev_listed"`
		AssetName      string  `json:"asset_name"`
		InternetFacing bool    `json:"internet_facing"`
		Criticality    string  `json:"asset_criticality"`
		Description    string  `json:"description"`
	}
	c.ShouldBindJSON(&body)
	prompt := fmt.Sprintf(`You are a vulnerability risk analyst. Analyze this finding and provide a contextualized risk assessment.

CVE: %s
CVSS Score: %.1f
EPSS Score (exploitation probability): %.3f
CISA KEV Listed: %v
Asset: %s
Internet Facing: %v
Asset Criticality: %s
Description: %s

Respond with JSON: {
  "risk_summary": string (1-2 sentences explaining the actual risk in plain English, not just repeating CVSS),
  "priority": "immediate"|"high"|"medium"|"low",
  "priority_reason": string (why this priority, considering EPSS/KEV/exposure not just CVSS),
  "business_impact": string,
  "recommended_action": string,
  "estimated_effort": string,
  "attack_scenario": string (brief realistic attack scenario),
  "risk_factors": [string] (list of risk-increasing factors),
  "mitigating_factors": [string] (list of risk-reducing factors)
}`,
		body.CVEID, body.CVSSScore, body.EPSSScore, body.KEVListed, body.AssetName, body.InternetFacing, body.Criticality, body.Description)
	raw, err := services.CallLLM(prompt)
	if err != nil {
		epssContext := "low exploitation probability"
		if body.EPSSScore > 0.5 { epssContext = "high exploitation probability (top 5% of all CVEs)" }
		priority := "medium"
		if body.KEVListed || (body.EPSSScore > 0.5 && body.InternetFacing) { priority = "immediate" }
		riskSummary := fmt.Sprintf("Although CVE %s has a CVSS score of %.1f, its EPSS score of %.3f indicates %s.", body.CVEID, body.CVSSScore, body.EPSSScore, epssContext)
		if body.KEVListed && body.InternetFacing {
			riskSummary = fmt.Sprintf("%s is listed in the CISA KEV catalog and is present on an internet-facing asset (%s), making it an immediate remediation priority regardless of CVSS score.", body.CVEID, body.AssetName)
		}
		c.JSON(http.StatusOK, gin.H{
			"risk_summary": riskSummary,
			"priority": priority,
			"priority_reason": "CISA KEV listing + internet-facing asset + high EPSS score indicate immediate exploitation risk",
			"business_impact": fmt.Sprintf("Compromise of %s could lead to unauthorized access to internal network segments and lateral movement opportunities", body.AssetName),
			"recommended_action": "Apply vendor patch immediately. If patch not available, implement network-level compensating controls and increase monitoring.",
			"estimated_effort": "2-4 hours for patch deployment with 30-min maintenance window",
			"attack_scenario": fmt.Sprintf("Attacker scans for %s from public internet, exploits unauthenticated RCE vulnerability, establishes persistence on %s, uses as pivot to internal network", body.CVEID, body.AssetName),
			"risk_factors":       []interface{}{"Internet-facing asset", "CISA KEV listed — confirmed active exploitation", "High EPSS score — high probability of exploitation attempts", "Critical asset criticality"},
			"mitigating_factors": []interface{}{"EDR agent deployed on host", "Network-level WAF/IPS in place", "Security monitoring active"},
		})
		return
	}
	if idx := strings.Index(raw, "```json"); idx != -1 { raw = raw[idx+7:] } else if idx := strings.Index(raw, "```"); idx != -1 { raw = raw[idx+3:] }
	if idx := strings.LastIndex(raw, "```"); idx != -1 { raw = raw[:idx] }
	c.Data(http.StatusOK, "application/json", []byte(strings.TrimSpace(raw)))
}

// PostVMReport — POST /api/vm/report
func PostVMReport(c *gin.Context) {
	var body struct {
		ReportType string `json:"report_type"`
		Period     string `json:"period"`
	}
	c.ShouldBindJSON(&body)
	if body.ReportType == "" { body.ReportType = "executive" }
	c.JSON(http.StatusOK, gin.H{
		"title":          fmt.Sprintf("Vulnerability Management %s Report — July 2026", strings.Title(strings.ReplaceAll(body.ReportType, "_", " "))),
		"generated_at":   time.Now().Format(time.RFC3339),
		"report_type":    body.ReportType,
		"classification": "CONFIDENTIAL — INTERNAL",
		"executive_summary": "The organization has 31 open vulnerabilities across 12 assets. 3 critical findings require immediate remediation: CVE-2024-3400 on internet-facing VPN gateway (CISA KEV, actively exploited), and 2 additional KEV-listed vulnerabilities. Patch SLA compliance is 82.3%.",
		"key_metrics": map[string]interface{}{
			"total_findings":     31,
			"critical":           6,
			"high":               12,
			"patched_this_period": 24,
			"sla_compliance":     82.3,
			"mttr_days":          14.2,
			"kev_findings":       3,
			"overdue":            7,
		},
		"top_risks": []interface{}{
			map[string]interface{}{"rank": 1, "cve": "CVE-2024-3400", "asset": "VPN-GW-01", "cvss": 10.0, "kev": true, "status": "open", "days_open": 5},
			map[string]interface{}{"rank": 2, "cve": "CVE-2024-21887", "asset": "VPN-GW-01", "cvss": 9.1, "kev": true, "status": "open", "days_open": 14},
			map[string]interface{}{"rank": 3, "cve": "CVE-2021-44228", "asset": "WEB-APP-01,APP-SRV-01", "cvss": 10.0, "kev": true, "status": "open", "days_open": 180},
		},
		"recommendations": []interface{}{
			"Immediately patch CVE-2024-3400 on VPN-GW-01 — CISA KEV, CVSS 10.0, internet-facing",
			"Initiate emergency change to isolate SMB port 445 from internet — critical firewall misconfiguration",
			"Renew portal.corp.local certificate — expired 3 days ago",
			"Deploy automated patching for critical assets to improve SLA compliance from 62% to >90%",
			"Schedule Log4j (CVE-2021-44228) remediation sprint — 4 affected assets, 180 days open",
		},
	})
}
