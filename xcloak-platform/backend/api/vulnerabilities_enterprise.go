package api

import (
	"database/sql"
	"encoding/json"
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
		Total             int     `json:"total"`
		Critical          int     `json:"critical"`
		High              int     `json:"high"`
		Medium            int     `json:"medium"`
		Low               int     `json:"low"`
		Exploitable       int     `json:"exploitable"`
		ActivelyExploited int     `json:"actively_exploited"`
		Patched           int     `json:"patched"`
		Overdue           int     `json:"overdue"`
		RiskScore         float64 `json:"risk_score"`
		AssetsAffected    int     `json:"assets_affected"`
		KEVFindings       int     `json:"kev_findings"`
		MTTR              float64 `json:"mttr_days"`
		PatchSLA          float64 `json:"patch_sla_compliance"`
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
	database.DB.QueryRow(`SELECT COALESCE(AVG(risk_score),0) FROM vm_findings WHERE tenant_id=$1 AND status='open'`, tid).Scan(&s.RiskScore)
	database.DB.QueryRow(`SELECT COALESCE(AVG(EXTRACT(EPOCH FROM (patched_at-detected_at))/86400),0) FROM vm_findings WHERE tenant_id=$1 AND status='patched' AND patched_at IS NOT NULL`, tid).Scan(&s.MTTR)
	database.DB.QueryRow(`SELECT COUNT(DISTINCT asset_id) FROM vm_findings WHERE tenant_id=$1 AND status='open'`, tid).Scan(&s.AssetsAffected)
	// "Overdue" and patch-SLA compliance both use the same per-severity SLA
	// windows: critical=7d, high=30d, medium=90d, low=180d.
	database.DB.QueryRow(`
		SELECT COUNT(*) FROM vm_findings WHERE tenant_id=$1 AND status='open' AND
			((severity='critical' AND detected_at < NOW()-INTERVAL '7 days') OR
			 (severity='high' AND detected_at < NOW()-INTERVAL '30 days') OR
			 (severity='medium' AND detected_at < NOW()-INTERVAL '90 days') OR
			 (severity='low' AND detected_at < NOW()-INTERVAL '180 days'))`, tid).Scan(&s.Overdue)
	database.DB.QueryRow(`
		SELECT CASE WHEN COUNT(*) > 0 THEN 100.0 * COUNT(*) FILTER (WHERE
			(severity='critical' AND patched_at <= detected_at+INTERVAL '7 days') OR
			(severity='high' AND patched_at <= detected_at+INTERVAL '30 days') OR
			(severity='medium' AND patched_at <= detected_at+INTERVAL '90 days') OR
			(severity='low' AND patched_at <= detected_at+INTERVAL '180 days')
		) / COUNT(*) ELSE 100.0 END
		FROM vm_findings WHERE tenant_id=$1 AND status='patched' AND patched_at IS NOT NULL`, tid).Scan(&s.PatchSLA)
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
		q += fmt.Sprintf(" AND severity=$%d", i)
		args = append(args, v)
		i++
	}
	if v := c.Query("kev"); v == "true" {
		q += " AND kev_listed=true"
	}
	if v := c.Query("exploitable"); v == "true" {
		q += " AND exploit_available=true"
	}
	if v := c.Query("status"); v != "" {
		q += fmt.Sprintf(" AND status=$%d", i)
		args = append(args, v)
		i++
	}
	if v := c.Query("q"); v != "" {
		q += fmt.Sprintf(" AND (cve_id ILIKE $%d OR vendor ILIKE $%d OR product ILIKE $%d OR asset_name ILIKE $%d)", i, i, i, i)
		args = append(args, "%"+v+"%")
		i++
	}
	q += fmt.Sprintf(" ORDER BY kev_listed DESC, actively_exploited DESC, cvss_score DESC LIMIT $%d", i)
	args = append(args, limit)
	rows, _ := database.DB.Query(q, args...)
	type Finding struct {
		ID                int     `json:"id"`
		CVEID             string  `json:"cve_id"`
		CVSSScore         float64 `json:"cvss_score"`
		EPSSScore         float64 `json:"epss_score"`
		EPSSPercentile    float64 `json:"epss_percentile"`
		KEVListed         bool    `json:"kev_listed"`
		Severity          string  `json:"severity"`
		Vendor            string  `json:"vendor"`
		Product           string  `json:"product"`
		AffectedVersions  string  `json:"affected_versions"`
		PatchAvailable    bool    `json:"patch_available"`
		ActivelyExploited bool    `json:"actively_exploited"`
		ExploitAvailable  bool    `json:"exploit_available"`
		Status            string  `json:"status"`
		AssetName         string  `json:"asset_name"`
		AssetIP           string  `json:"asset_ip"`
		InternetFacing    bool    `json:"internet_facing"`
		AssetCriticality  string  `json:"asset_criticality"`
		RiskScore         float64 `json:"risk_score"`
		ScanType          string  `json:"scan_type"`
		DetectedAt        string  `json:"detected_at"`
		PublishedAt       *string `json:"published_at"`
	}
	list := []Finding{}
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var f Finding
			if rows.Scan(&f.ID, &f.CVEID, &f.CVSSScore, &f.EPSSScore, &f.EPSSPercentile, &f.KEVListed, &f.Severity, &f.Vendor, &f.Product, &f.AffectedVersions, &f.PatchAvailable, &f.ActivelyExploited, &f.ExploitAvailable, &f.Status, &f.AssetName, &f.AssetIP, &f.InternetFacing, &f.AssetCriticality, &f.RiskScore, &f.ScanType, &f.DetectedAt, &f.PublishedAt) == nil {
				list = append(list, f)
			}
		}
	}
	if list == nil {
		list = []Finding{}
	}
	c.JSON(http.StatusOK, list)
}

// GetVMFinding — GET /api/vm/findings/:id
func GetVMFinding(c *gin.Context) {
	createVMTables()
	tid := tenantIDFromContext(c)
	fid, _ := strconv.Atoi(c.Param("id"))
	var f struct {
		ID                int     `json:"id"`
		CVEID             string  `json:"cve_id"`
		CVSSScore         float64 `json:"cvss_score"`
		CVSSVector        string  `json:"cvss_vector"`
		EPSSScore         float64 `json:"epss_score"`
		EPSSPercentile    float64 `json:"epss_percentile"`
		KEVListed         bool    `json:"kev_listed"`
		KEVDateAdded      string  `json:"kev_date_added"`
		Severity          string  `json:"severity"`
		Description       string  `json:"description"`
		Vendor            string  `json:"vendor"`
		Product           string  `json:"product"`
		AffectedVersions  string  `json:"affected_versions"`
		FixedVersion      string  `json:"fixed_version"`
		PatchAvailable    bool    `json:"patch_available"`
		PatchURL          string  `json:"patch_url"`
		ActivelyExploited bool    `json:"actively_exploited"`
		ExploitAvailable  bool    `json:"exploit_available"`
		ExploitMaturity   string  `json:"exploit_maturity"`
		MalwareFamilies   string  `json:"malware_families"`
		ThreatActors      string  `json:"threat_actors"`
		CISAAdvisory      string  `json:"cisa_advisory"`
		Status            string  `json:"status"`
		AssetID           int     `json:"asset_id"`
		AssetName         string  `json:"asset_name"`
		AssetIP           string  `json:"asset_ip"`
		InternetFacing    bool    `json:"internet_facing"`
		AssetCriticality  string  `json:"asset_criticality"`
		RiskScore         float64 `json:"risk_score"`
		ScanType          string  `json:"scan_type"`
		DetectedAt        string  `json:"detected_at"`
		PublishedAt       *string `json:"published_at"`
		PatchReleasedAt   *string `json:"patch_released_at"`
		PatchedAt         *string `json:"patched_at"`
		VerifiedAt        *string `json:"verified_at"`
	}
	err := database.DB.QueryRow(`SELECT id,cve_id,cvss_score,cvss_vector,epss_score,epss_percentile,kev_listed,kev_date_added,severity,description,vendor,product,affected_versions,fixed_version,patch_available,patch_url,actively_exploited,exploit_available,exploit_maturity,malware_families,threat_actors,cisa_advisory,status,asset_id,asset_name,asset_ip,internet_facing,asset_criticality,risk_score,scan_type,detected_at,published_at,patch_released_at,patched_at,verified_at
		FROM vm_findings WHERE id=$1 AND tenant_id=$2`, fid, tid).Scan(
		&f.ID, &f.CVEID, &f.CVSSScore, &f.CVSSVector, &f.EPSSScore, &f.EPSSPercentile, &f.KEVListed, &f.KEVDateAdded, &f.Severity, &f.Description, &f.Vendor, &f.Product, &f.AffectedVersions, &f.FixedVersion, &f.PatchAvailable, &f.PatchURL, &f.ActivelyExploited, &f.ExploitAvailable, &f.ExploitMaturity, &f.MalwareFamilies, &f.ThreatActors, &f.CISAAdvisory, &f.Status, &f.AssetID, &f.AssetName, &f.AssetIP, &f.InternetFacing, &f.AssetCriticality, &f.RiskScore, &f.ScanType, &f.DetectedAt, &f.PublishedAt, &f.PatchReleasedAt, &f.PatchedAt, &f.VerifiedAt)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
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

	var res sql.Result
	var err error
	switch body.Action {
	case "mark_patched":
		res, err = database.DB.Exec(`UPDATE vm_findings SET status='patched', patched_at=NOW(), updated_at=NOW() WHERE id=$1 AND tenant_id=$2`, fid, tid)
	case "accept_risk":
		// Was previously WHERE id=$2 AND tenant_id=$3 with only 2 args bound
		// (fid, tid) — $3 was never bound, so this always errored and the
		// error was silently discarded, meaning "Accept Risk" never
		// actually updated anything despite returning {"ok": true}.
		res, err = database.DB.Exec(`UPDATE vm_findings SET status='accepted', updated_at=NOW() WHERE id=$1 AND tenant_id=$2`, fid, tid)
	case "defer":
		res, err = database.DB.Exec(`UPDATE vm_findings SET status='deferred', updated_at=NOW() WHERE id=$1 AND tenant_id=$2`, fid, tid)
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "unrecognized action"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "finding not found"})
		return
	}
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
		ID             int     `json:"id"`
		Hostname       string  `json:"hostname"`
		IPAddress      string  `json:"ip_address"`
		OS             string  `json:"os"`
		OSVersion      string  `json:"os_version"`
		Owner          string  `json:"owner"`
		BusinessUnit   string  `json:"business_unit"`
		InternetFacing bool    `json:"internet_facing"`
		RiskScore      float64 `json:"risk_score"`
		Criticality    string  `json:"criticality"`
		AssetValue     string  `json:"asset_value"`
		NetworkZone    string  `json:"network_zone"`
		VulnCount      int     `json:"vuln_count"`
		CriticalCount  int     `json:"critical_count"`
		HighCount      int     `json:"high_count"`
		LastScannedAt  *string `json:"last_scanned_at"`
		CreatedAt      string  `json:"created_at"`
	}
	list := []Asset{}
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var a Asset
			if rows.Scan(&a.ID, &a.Hostname, &a.IPAddress, &a.OS, &a.OSVersion, &a.Owner, &a.BusinessUnit, &a.InternetFacing, &a.RiskScore, &a.Criticality, &a.AssetValue, &a.NetworkZone, &a.VulnCount, &a.CriticalCount, &a.HighCount, &a.LastScannedAt, &a.CreatedAt) == nil {
				list = append(list, a)
			}
		}
	}
	if list == nil {
		list = []Asset{}
	}
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
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	c.JSON(http.StatusOK, a)
}

// well-known-port name lookup used only to label real open ports found on
// real internet-facing assets — not a source of data itself.
var wellKnownPorts = map[string]struct {
	service string
	risk    string
	notes   string
}{
	"22":   {"SSH", "", ""},
	"23":   {"Telnet", "critical", "Unencrypted remote access exposed to the internet"},
	"443":  {"HTTPS", "", ""},
	"445":  {"SMB", "critical", "SMB exposed to internet — immediate risk"},
	"3389": {"RDP", "high", "Should not be internet-facing"},
	"3306": {"MySQL", "high", "Database port should not be internet-facing"},
	"5432": {"PostgreSQL", "high", "Database port should not be internet-facing"},
}

// GetVMAttackSurface — GET /api/vm/attack-surface
//
// Derived from real vm_assets (internet_facing/open_ports) and real
// firewall_rules — certificates/DNS-exposure were dropped entirely, since
// no certificate store or DNS zone tracking exists anywhere in this
// codebase to back either honestly.
func GetVMAttackSurface(c *gin.Context) {
	createVMTables()
	tid := tenantIDFromContext(c)

	var internetExposed int
	database.DB.QueryRow(`SELECT COUNT(*) FROM vm_assets WHERE tenant_id=$1 AND internet_facing=true`, tid).Scan(&internetExposed)

	type svcRow struct {
		Service           string `json:"service"`
		Port              int    `json:"port"`
		Assets            int    `json:"assets"`
		Risk              string `json:"risk,omitempty"`
		Notes             string `json:"notes,omitempty"`
		VulnerableVersion bool   `json:"vulnerable_version,omitempty"`
	}
	portAssets := map[string]int{}
	openPortsTotal := 0
	rows, _ := database.DB.Query(`SELECT open_ports FROM vm_assets WHERE tenant_id=$1 AND internet_facing=true AND open_ports != ''`, tid)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var raw string
			if rows.Scan(&raw) != nil {
				continue
			}
			for _, p := range strings.Split(raw, ",") {
				p = strings.TrimSpace(p)
				if p == "" {
					continue
				}
				portAssets[p]++
				openPortsTotal++
			}
		}
	}
	exposedServices := []svcRow{}
	for port, count := range portAssets {
		portNum, _ := strconv.Atoi(port)
		svc := svcRow{Service: port, Port: portNum, Assets: count}
		if wk, ok := wellKnownPorts[port]; ok {
			svc.Service = wk.service
			svc.Risk = wk.risk
			svc.Notes = wk.notes
		}
		exposedServices = append(exposedServices, svc)
	}

	type fwRow struct {
		Rule           string `json:"rule"`
		Risk           string `json:"risk"`
		Recommendation string `json:"recommendation"`
	}
	firewallExposure := []fwRow{}
	fRows, _ := database.DB.Query(`
		SELECT name, source_ip, destination_ip, port, protocol FROM firewall_rules
		WHERE tenant_id=$1 AND enabled=true AND action='allow' AND source_ip IN ('any','0.0.0.0/0','*','ANY')
		ORDER BY port LIMIT 20`, tid)
	if fRows != nil {
		defer fRows.Close()
		for fRows.Next() {
			var name, srcIP, dstIP, protocol string
			var port int
			if fRows.Scan(&name, &srcIP, &dstIP, &port, &protocol) != nil {
				continue
			}
			portStr := strconv.Itoa(port)
			risk, rec := "low", "Review — confirm this is intentional external access"
			if wk, ok := wellKnownPorts[portStr]; ok && wk.risk != "" {
				risk = wk.risk
				rec = wk.notes
			}
			firewallExposure = append(firewallExposure, fwRow{
				Rule:           fmt.Sprintf("ALLOW %s → %s:%d (%s)", srcIP, dstIP, port, protocol),
				Risk:           risk,
				Recommendation: rec,
			})
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"internet_exposed_assets": internetExposed,
		"open_ports_total":        openPortsTotal,
		"exposed_services":        exposedServices,
		"firewall_exposure":       firewallExposure,
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
// GetVMThreatIntel — GET /api/vm/threat-intel
//
// The frontend's own section title ("CISA KEV Catalog — Matched Findings")
// already promised per-tenant matching, but this handler previously
// returned 3 fixed CVEs regardless of tenant. Every field used below
// (cve_id/vendor/product/kev_date_added/malware_families/threat_actors/
// exploit_maturity) is a real column already tracked per finding — this
// now genuinely matches against this tenant's own data instead of a
// generic global list. Dropped fields with no real backing anywhere in
// this schema: campaign/first_observed (no campaign-tracking concept),
// public_poc/metasploit/exploit_db (only a single real exploit_maturity
// column exists, not per-tool flags), and country/motivation/
// target_sectors/aliases/ttps on threat actors (malware_families/
// threat_actors are free-text columns with no such metadata attached).
func GetVMThreatIntel(c *gin.Context) {
	createVMTables()
	tid := tenantIDFromContext(c)

	type kevRow struct {
		CVE       string `json:"cve"`
		Vendor    string `json:"vendor"`
		Product   string `json:"product"`
		DateAdded string `json:"date_added"`
		Notes     string `json:"notes"`
	}
	kevCatalog := []kevRow{}
	kRows, _ := database.DB.Query(`SELECT DISTINCT ON (cve_id) cve_id, vendor, product, kev_date_added, description FROM vm_findings WHERE tenant_id=$1 AND kev_listed=true ORDER BY cve_id LIMIT 20`, tid)
	if kRows != nil {
		defer kRows.Close()
		for kRows.Next() {
			var r kevRow
			if kRows.Scan(&r.CVE, &r.Vendor, &r.Product, &r.DateAdded, &r.Notes) == nil {
				kevCatalog = append(kevCatalog, r)
			}
		}
	}

	type exploitRow struct {
		CVE         string `json:"cve"`
		ThreatActor string `json:"threat_actor,omitempty"`
		Malware     string `json:"malware,omitempty"`
	}
	activeExploitation := []exploitRow{}
	eRows, _ := database.DB.Query(`SELECT DISTINCT ON (cve_id) cve_id, threat_actors, malware_families FROM vm_findings WHERE tenant_id=$1 AND actively_exploited=true ORDER BY cve_id LIMIT 20`, tid)
	if eRows != nil {
		defer eRows.Close()
		for eRows.Next() {
			var r exploitRow
			if eRows.Scan(&r.CVE, &r.ThreatActor, &r.Malware) == nil {
				activeExploitation = append(activeExploitation, r)
			}
		}
	}

	type maturityRow struct {
		CVE      string `json:"cve"`
		Maturity string `json:"maturity"`
	}
	exploitAvailability := []maturityRow{}
	mRows, _ := database.DB.Query(`SELECT DISTINCT ON (cve_id) cve_id, exploit_maturity FROM vm_findings WHERE tenant_id=$1 AND exploit_available=true AND exploit_maturity != 'none' ORDER BY cve_id LIMIT 20`, tid)
	if mRows != nil {
		defer mRows.Close()
		for mRows.Next() {
			var r maturityRow
			if mRows.Scan(&r.CVE, &r.Maturity) == nil {
				exploitAvailability = append(exploitAvailability, r)
			}
		}
	}

	type actorRow struct {
		Name  string `json:"name"`
		Count int    `json:"count"`
	}
	threatActors := []actorRow{}
	aRows, _ := database.DB.Query(`SELECT threat_actors, COUNT(*) FROM vm_findings WHERE tenant_id=$1 AND threat_actors != '' GROUP BY threat_actors ORDER BY COUNT(*) DESC LIMIT 10`, tid)
	if aRows != nil {
		defer aRows.Close()
		for aRows.Next() {
			var r actorRow
			if aRows.Scan(&r.Name, &r.Count) == nil {
				threatActors = append(threatActors, r)
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"kev_catalog":          kevCatalog,
		"active_exploitation":  activeExploitation,
		"exploit_availability": exploitAvailability,
		"threat_actors":        threatActors,
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
	list := []Patch{}
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var p Patch
			if rows.Scan(&p.ID, &p.CVEID, &p.AssetName, &p.PatchStatus, &p.PatchVersion, &p.RestartRequired, &p.EstimatedDowntime, &p.AssignedTo, &p.ScheduledAt, &p.InstalledAt, &p.FailedAt, &p.FailureReason, &p.RollbackAvailable, &p.CreatedAt) == nil {
				list = append(list, p)
			}
		}
	}
	if list == nil {
		list = []Patch{}
	}
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
//
// Backed by the shared fce_frameworks/fce_controls tables (the same real
// compliance-assessment data the Dashboard/Container/Supply Chain/OT-ICS
// pages already use) rather than a fixed 4-framework fake grid — the
// established fix shape for this exact fabrication pattern this phase.
func GetVMCompliance(c *gin.Context) {
	createVMTables()
	createFCETables()
	tid := tenantIDFromContext(c)
	db := database.DB

	type ctrlRow struct {
		ID      string `json:"id"`
		Title   string `json:"title"`
		Status  string `json:"status"`
		Finding string `json:"finding"`
	}
	type fwRow struct {
		FrameworkID string    `json:"-"`
		Name        string    `json:"name"`
		Score       int       `json:"score"`
		Status      string    `json:"status"`
		Controls    []ctrlRow `json:"controls"`
	}
	// fce_controls/fce_frameworks use their own real vocabulary
	// ('failed'/'passed' controls, 'compliant'/'partially_compliant'/
	// 'not_assessed' frameworks) — this page's frontend expects
	// 'failing'/'passing'/'partial', matching the vocabulary the old fake
	// data happened to use. Translate rather than leaving every control
	// silently uncounted as failing.
	ctrlStatus := map[string]string{"failed": "failing", "passed": "passing"}
	fwStatus := map[string]string{"compliant": "passing", "partially_compliant": "partial", "not_assessed": "not_assessed"}

	frows, _ := db.Query(`SELECT framework_id, name, overall_score, compliance_status FROM fce_frameworks WHERE tenant_id=$1 AND is_active=true ORDER BY overall_score ASC`, tid)
	frameworks := []fwRow{}
	if frows != nil {
		for frows.Next() {
			var fw fwRow
			var rawStatus string
			if frows.Scan(&fw.FrameworkID, &fw.Name, &fw.Score, &rawStatus) == nil {
				fw.Status = fwStatus[rawStatus]
				if fw.Status == "" {
					fw.Status = rawStatus
				}
				frameworks = append(frameworks, fw)
			}
		}
		// Close before issuing the per-framework queries below rather than
		// holding this cursor open with `defer` — nested Query calls on the
		// same *sql.DB while an earlier Rows is still open silently
		// returned zero controls for every framework (confirmed live: real
		// fce_controls rows existed but every framework showed 0 until
		// this was closed eagerly).
		frows.Close()
	}
	failedControls := 0
	for i := range frameworks {
		// fce_controls.description is nullable with no DEFAULT — scanning
		// NULL into a plain Go string silently failed rows.Scan() for
		// every real control (confirmed live: 20 real rows existed per
		// framework, all silently dropped) — the same NULL-scan bug class
		// found on the Approval Queue page, this time on a shared table
		// this handler doesn't own. COALESCE rather than altering a table
		// other pages also depend on.
		crows, _ := db.Query(`SELECT control_id, name, assessment_status, COALESCE(description,'') FROM fce_controls WHERE tenant_id=$1 AND framework_id=$2 ORDER BY CASE risk_level WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END LIMIT 20`, tid, frameworks[i].FrameworkID)
		if crows == nil {
			continue
		}
		for crows.Next() {
			var ctrl ctrlRow
			var rawStatus string
			if crows.Scan(&ctrl.ID, &ctrl.Title, &rawStatus, &ctrl.Finding) == nil {
				ctrl.Status = ctrlStatus[rawStatus]
				if ctrl.Status == "" {
					ctrl.Status = rawStatus
				}
				frameworks[i].Controls = append(frameworks[i].Controls, ctrl)
				if ctrl.Status == "failing" {
					failedControls++
				}
			}
		}
		crows.Close()
	}

	var overallScore float64
	db.QueryRow(`SELECT COALESCE(AVG(overall_score),0) FROM fce_frameworks WHERE tenant_id=$1 AND is_active=true`, tid).Scan(&overallScore)

	var missingPatches, slaViolations int
	db.QueryRow(`SELECT COUNT(*) FROM vm_findings WHERE tenant_id=$1 AND status='open' AND patch_available=true`, tid).Scan(&missingPatches)
	db.QueryRow(`
		SELECT COUNT(*) FROM vm_findings WHERE tenant_id=$1 AND status='open' AND
			((severity='critical' AND detected_at < NOW()-INTERVAL '7 days') OR
			 (severity='high' AND detected_at < NOW()-INTERVAL '30 days') OR
			 (severity='medium' AND detected_at < NOW()-INTERVAL '90 days'))`, tid).Scan(&slaViolations)

	c.JSON(http.StatusOK, gin.H{
		"overall_score":   overallScore,
		"frameworks":      frameworks,
		"failed_controls": failedControls,
		"missing_patches": missingPatches,
		"sla_violations":  slaViolations,
	})
}

// GetVMAnalytics — GET /api/vm/analytics
func GetVMAnalytics(c *gin.Context) {
	createVMTables()
	tid := tenantIDFromContext(c)
	var total, critical, high, patched, kev int
	var mttr, patchSLA float64
	database.DB.QueryRow(`SELECT COUNT(*) FROM vm_findings WHERE tenant_id=$1`, tid).Scan(&total)
	database.DB.QueryRow(`SELECT COUNT(*) FROM vm_findings WHERE tenant_id=$1 AND severity='critical'`, tid).Scan(&critical)
	database.DB.QueryRow(`SELECT COUNT(*) FROM vm_findings WHERE tenant_id=$1 AND severity='high'`, tid).Scan(&high)
	database.DB.QueryRow(`SELECT COUNT(*) FROM vm_findings WHERE tenant_id=$1 AND status='patched'`, tid).Scan(&patched)
	database.DB.QueryRow(`SELECT COUNT(*) FROM vm_findings WHERE tenant_id=$1 AND kev_listed=true`, tid).Scan(&kev)
	database.DB.QueryRow(`SELECT COALESCE(AVG(EXTRACT(EPOCH FROM (patched_at-detected_at))/86400),0) FROM vm_findings WHERE tenant_id=$1 AND status='patched' AND patched_at IS NOT NULL`, tid).Scan(&mttr)
	database.DB.QueryRow(`
		SELECT CASE WHEN COUNT(*) > 0 THEN 100.0 * COUNT(*) FILTER (WHERE
			(severity='critical' AND patched_at <= detected_at+INTERVAL '7 days') OR
			(severity='high' AND patched_at <= detected_at+INTERVAL '30 days') OR
			(severity='medium' AND patched_at <= detected_at+INTERVAL '90 days') OR
			(severity='low' AND patched_at <= detected_at+INTERVAL '180 days')
		) / COUNT(*) ELSE 100.0 END
		FROM vm_findings WHERE tenant_id=$1 AND status='patched' AND patched_at IS NOT NULL`, tid).Scan(&patchSLA)

	type assetRow struct {
		Asset     string  `json:"asset"`
		VulnCount int     `json:"vuln_count"`
		Critical  int     `json:"critical"`
		RiskScore float64 `json:"risk_score"`
	}
	topAssets := []assetRow{}
	aRows, _ := database.DB.Query(`SELECT hostname, vuln_count, critical_count, risk_score FROM vm_assets WHERE tenant_id=$1 AND vuln_count>0 ORDER BY risk_score DESC LIMIT 5`, tid)
	if aRows != nil {
		defer aRows.Close()
		for aRows.Next() {
			var r assetRow
			if aRows.Scan(&r.Asset, &r.VulnCount, &r.Critical, &r.RiskScore) == nil {
				topAssets = append(topAssets, r)
			}
		}
	}

	type cveRow struct {
		CVE            string  `json:"cve"`
		CVSS           float64 `json:"cvss"`
		EPSS           float64 `json:"epss"`
		KEV            bool    `json:"kev"`
		AffectedAssets int     `json:"affected_assets"`
	}
	topCVEs := []cveRow{}
	cRows, _ := database.DB.Query(`
		SELECT cve_id, MAX(cvss_score), MAX(epss_score), BOOL_OR(kev_listed), COUNT(DISTINCT asset_id)
		FROM vm_findings WHERE tenant_id=$1 GROUP BY cve_id ORDER BY MAX(cvss_score) DESC LIMIT 5`, tid)
	if cRows != nil {
		defer cRows.Close()
		for cRows.Next() {
			var r cveRow
			if cRows.Scan(&r.CVE, &r.CVSS, &r.EPSS, &r.KEV, &r.AffectedAssets) == nil {
				topCVEs = append(topCVEs, r)
			}
		}
	}

	type trendRow struct {
		Week     string `json:"week"`
		Critical int    `json:"critical"`
		High     int    `json:"high"`
		Medium   int    `json:"medium"`
	}
	trend := []trendRow{}
	for i := 3; i >= 0; i-- {
		weekStart := time.Now().AddDate(0, 0, -7*(i+1))
		weekEnd := time.Now().AddDate(0, 0, -7*i)
		var r trendRow
		r.Week = weekEnd.Format("01-02")
		database.DB.QueryRow(`SELECT COUNT(*) FROM vm_findings WHERE tenant_id=$1 AND severity='critical' AND detected_at>=$2 AND detected_at<$3`, tid, weekStart, weekEnd).Scan(&r.Critical)
		database.DB.QueryRow(`SELECT COUNT(*) FROM vm_findings WHERE tenant_id=$1 AND severity='high' AND detected_at>=$2 AND detected_at<$3`, tid, weekStart, weekEnd).Scan(&r.High)
		database.DB.QueryRow(`SELECT COUNT(*) FROM vm_findings WHERE tenant_id=$1 AND severity='medium' AND detected_at>=$2 AND detected_at<$3`, tid, weekStart, weekEnd).Scan(&r.Medium)
		trend = append(trend, r)
	}

	type slaRow struct {
		Severity  string  `json:"severity"`
		SLADays   int     `json:"sla_days"`
		AvgDays   float64 `json:"avg_days"`
		OnTimePct float64 `json:"on_time_pct"`
	}
	slaBreakdown := []slaRow{}
	for _, sev := range []struct {
		name string
		days int
	}{{"critical", 7}, {"high", 30}, {"medium", 90}, {"low", 180}} {
		var r slaRow
		r.Severity = sev.name
		r.SLADays = sev.days
		database.DB.QueryRow(`SELECT COALESCE(AVG(EXTRACT(EPOCH FROM (patched_at-detected_at))/86400),0) FROM vm_findings WHERE tenant_id=$1 AND severity=$2 AND status='patched' AND patched_at IS NOT NULL`, tid, sev.name).Scan(&r.AvgDays)
		database.DB.QueryRow(`
			SELECT CASE WHEN COUNT(*) > 0 THEN 100.0 * COUNT(*) FILTER (WHERE patched_at <= detected_at+($3||' days')::interval) / COUNT(*) ELSE 100.0 END
			FROM vm_findings WHERE tenant_id=$1 AND severity=$2 AND status='patched' AND patched_at IS NOT NULL`, tid, sev.name, sev.days).Scan(&r.OnTimePct)
		slaBreakdown = append(slaBreakdown, r)
	}

	c.JSON(http.StatusOK, gin.H{
		"total": total, "critical": critical, "high": high, "patched": patched, "kev": kev,
		"mttr_days":             mttr,
		"patch_sla":             patchSLA,
		"top_vulnerable_assets": topAssets,
		"top_cves":              topCVEs,
		"risk_trend":            trend,
		"patch_sla_breakdown":   slaBreakdown,
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
	list := []Scan{}
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var s Scan
			if rows.Scan(&s.ID, &s.Name, &s.ScanType, &s.Target, &s.Profile, &s.Status, &s.Schedule, &s.StartedAt, &s.FinishedAt, &s.FindingsCount, &s.CreatedBy, &s.CreatedAt) == nil {
				list = append(list, s)
			}
		}
	}
	if list == nil {
		list = []Scan{}
	}
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
	if body.Profile == "" {
		body.Profile = "full"
	}
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
	list := []Exception{}
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var e Exception
			if rows.Scan(&e.ID, &e.CVEID, &e.ExceptionType, &e.Reason, &e.CompensatingControl, &e.ApprovedBy, &e.Status, &e.ExpiresAt, &e.CreatedBy, &e.CreatedAt) == nil {
				list = append(list, e)
			}
		}
	}
	if list == nil {
		list = []Exception{}
	}
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
	if body.ExceptionType == "" {
		body.ExceptionType = "risk_acceptance"
	}
	var expiresAt interface{}
	if body.ExpiresAt != "" {
		expiresAt = body.ExpiresAt
	} else {
		expiresAt = nil
	}
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
			fields = append(fields, fmt.Sprintf("%s=$%d", k, i))
			vals = append(vals, v)
			i++
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
		if body.EPSSScore > 0.5 {
			epssContext = "high exploitation probability (top 5% of all CVEs)"
		}
		priority := "medium"
		if body.KEVListed || (body.EPSSScore > 0.5 && body.InternetFacing) {
			priority = "immediate"
		}
		riskSummary := fmt.Sprintf("Although CVE %s has a CVSS score of %.1f, its EPSS score of %.3f indicates %s.", body.CVEID, body.CVSSScore, body.EPSSScore, epssContext)
		if body.KEVListed && body.InternetFacing {
			riskSummary = fmt.Sprintf("%s is listed in the CISA KEV catalog and is present on an internet-facing asset (%s), making it an immediate remediation priority regardless of CVSS score.", body.CVEID, body.AssetName)
		}
		c.JSON(http.StatusOK, gin.H{
			"risk_summary":       riskSummary,
			"priority":           priority,
			"priority_reason":    "CISA KEV listing + internet-facing asset + high EPSS score indicate immediate exploitation risk",
			"business_impact":    fmt.Sprintf("Compromise of %s could lead to unauthorized access to internal network segments and lateral movement opportunities", body.AssetName),
			"recommended_action": "Apply vendor patch immediately. If patch not available, implement network-level compensating controls and increase monitoring.",
			"estimated_effort":   "2-4 hours for patch deployment with 30-min maintenance window",
			"attack_scenario":    fmt.Sprintf("Attacker scans for %s from public internet, exploits unauthenticated RCE vulnerability, establishes persistence on %s, uses as pivot to internal network", body.CVEID, body.AssetName),
			"risk_factors":       []interface{}{"Internet-facing asset", "CISA KEV listed — confirmed active exploitation", "High EPSS score — high probability of exploitation attempts", "Critical asset criticality"},
			"mitigating_factors": []interface{}{"EDR agent deployed on host", "Network-level WAF/IPS in place", "Security monitoring active"},
		})
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

// PostVMReport — POST /api/vm/report
func PostVMReport(c *gin.Context) {
	createVMTables()
	tid := tenantIDFromContext(c)
	var body struct {
		ReportType string `json:"report_type"`
		Period     string `json:"period"`
	}
	c.ShouldBindJSON(&body)
	if body.ReportType == "" {
		body.ReportType = "executive"
	}

	var total, critical, high, patchedThisPeriod, kevFindings, overdue, assetsAffected int
	var slaCompliance, mttr float64
	database.DB.QueryRow(`SELECT COUNT(*) FROM vm_findings WHERE tenant_id=$1 AND status='open'`, tid).Scan(&total)
	database.DB.QueryRow(`SELECT COUNT(*) FROM vm_findings WHERE tenant_id=$1 AND status='open' AND severity='critical'`, tid).Scan(&critical)
	database.DB.QueryRow(`SELECT COUNT(*) FROM vm_findings WHERE tenant_id=$1 AND status='open' AND severity='high'`, tid).Scan(&high)
	database.DB.QueryRow(`SELECT COUNT(*) FROM vm_findings WHERE tenant_id=$1 AND status='patched' AND patched_at > NOW()-INTERVAL '30 days'`, tid).Scan(&patchedThisPeriod)
	database.DB.QueryRow(`SELECT COUNT(*) FROM vm_findings WHERE tenant_id=$1 AND status='open' AND kev_listed=true`, tid).Scan(&kevFindings)
	database.DB.QueryRow(`SELECT COUNT(DISTINCT asset_id) FROM vm_findings WHERE tenant_id=$1 AND status='open'`, tid).Scan(&assetsAffected)
	database.DB.QueryRow(`
		SELECT COUNT(*) FROM vm_findings WHERE tenant_id=$1 AND status='open' AND
			((severity='critical' AND detected_at < NOW()-INTERVAL '7 days') OR
			 (severity='high' AND detected_at < NOW()-INTERVAL '30 days') OR
			 (severity='medium' AND detected_at < NOW()-INTERVAL '90 days'))`, tid).Scan(&overdue)
	database.DB.QueryRow(`
		SELECT CASE WHEN COUNT(*) > 0 THEN 100.0 * COUNT(*) FILTER (WHERE
			(severity='critical' AND patched_at <= detected_at+INTERVAL '7 days') OR
			(severity='high' AND patched_at <= detected_at+INTERVAL '30 days') OR
			(severity='medium' AND patched_at <= detected_at+INTERVAL '90 days') OR
			(severity='low' AND patched_at <= detected_at+INTERVAL '180 days')
		) / COUNT(*) ELSE 100.0 END
		FROM vm_findings WHERE tenant_id=$1 AND status='patched' AND patched_at IS NOT NULL`, tid).Scan(&slaCompliance)
	database.DB.QueryRow(`SELECT COALESCE(AVG(EXTRACT(EPOCH FROM (patched_at-detected_at))/86400),0) FROM vm_findings WHERE tenant_id=$1 AND status='patched' AND patched_at IS NOT NULL`, tid).Scan(&mttr)

	type riskRow struct {
		Rank     int     `json:"rank"`
		CVE      string  `json:"cve"`
		Asset    string  `json:"asset"`
		CVSS     float64 `json:"cvss"`
		KEV      bool    `json:"kev"`
		Status   string  `json:"status"`
		DaysOpen int     `json:"days_open"`
	}
	topRisks := []riskRow{}
	rRows, _ := database.DB.Query(`
		SELECT cve_id, asset_name, cvss_score, kev_listed, status, EXTRACT(EPOCH FROM (NOW()-detected_at))/86400
		FROM vm_findings WHERE tenant_id=$1 AND status='open' ORDER BY kev_listed DESC, cvss_score DESC LIMIT 5`, tid)
	if rRows != nil {
		defer rRows.Close()
		rank := 1
		for rRows.Next() {
			var r riskRow
			var daysOpen float64
			if rRows.Scan(&r.CVE, &r.Asset, &r.CVSS, &r.KEV, &r.Status, &daysOpen) == nil {
				r.Rank = rank
				r.DaysOpen = int(daysOpen)
				topRisks = append(topRisks, r)
				rank++
			}
		}
	}

	prompt := fmt.Sprintf(`You are a vulnerability management reporting assistant. Write a %s report based on these REAL metrics: %d open findings (%d critical, %d high), %d assets affected, %d KEV-listed findings, %d overdue past SLA, %.1f%% patch SLA compliance, %.1f-day average time to patch, %d findings patched in the last 30 days. Top open risks: %v. Respond as a JSON object with fields: executive_summary (2-3 sentences grounded only in these numbers, no invented CVEs or incidents), recommendations (a JSON array of up to 5 short actionable strings based only on the real data given).`,
		body.ReportType, total, critical, high, assetsAffected, kevFindings, overdue, slaCompliance, mttr, patchedThisPeriod, topRisks)
	var summary string
	var recommendations []string
	raw, err := services.CallLLM(prompt)
	if err == nil {
		clean := raw
		if idx := strings.Index(clean, "```json"); idx != -1 {
			clean = clean[idx+7:]
		} else if idx := strings.Index(clean, "```"); idx != -1 {
			clean = clean[idx+3:]
		}
		if idx := strings.LastIndex(clean, "```"); idx != -1 {
			clean = clean[:idx]
		}
		var parsed struct {
			ExecutiveSummary string   `json:"executive_summary"`
			Recommendations  []string `json:"recommendations"`
		}
		if json.Unmarshal([]byte(strings.TrimSpace(clean)), &parsed) == nil {
			summary = parsed.ExecutiveSummary
			recommendations = parsed.Recommendations
		}
	}
	if summary == "" {
		if total == 0 {
			summary = "No open vulnerability findings have been recorded for this tenant."
		} else {
			summary = fmt.Sprintf("The organization has %d open vulnerabilities across %d assets, including %d critical findings. Patch SLA compliance is %.1f%%.", total, assetsAffected, critical, slaCompliance)
		}
		recommendations = []string{}
	}

	c.JSON(http.StatusOK, gin.H{
		"title":             fmt.Sprintf("Vulnerability Management %s Report — %s", strings.Title(strings.ReplaceAll(body.ReportType, "_", " ")), time.Now().Format("Jan 2006")),
		"generated_at":      time.Now().Format(time.RFC3339),
		"report_type":       body.ReportType,
		"classification":    "CONFIDENTIAL — INTERNAL",
		"executive_summary": summary,
		"key_metrics": gin.H{
			"total_findings":      total,
			"critical":            critical,
			"high":                high,
			"patched_this_period": patchedThisPeriod,
			"sla_compliance":      slaCompliance,
			"mttr_days":           mttr,
			"kev_findings":        kevFindings,
			"overdue":             overdue,
		},
		"top_risks":       topRisks,
		"recommendations": recommendations,
	})
}
