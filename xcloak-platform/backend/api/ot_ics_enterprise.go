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

func createOTICSTables() {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS ot_assets (
			id SERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL,
			name TEXT DEFAULT '', asset_type TEXT DEFAULT 'plc',
			vendor TEXT DEFAULT '', model TEXT DEFAULT '',
			firmware TEXT DEFAULT '', ip TEXT DEFAULT '',
			mac TEXT DEFAULT '', zone TEXT DEFAULT '',
			site TEXT DEFAULT '', purdue_level INTEGER DEFAULT 2,
			criticality TEXT DEFAULT 'medium', risk_score INTEGER DEFAULT 0,
			is_online BOOLEAN DEFAULT true, uptime_hours INTEGER DEFAULT 0,
			last_seen TIMESTAMPTZ DEFAULT NOW(), created_at TIMESTAMPTZ DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS ot_traffic (
			id SERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL,
			src_ip TEXT DEFAULT '', dst_ip TEXT DEFAULT '',
			protocol TEXT DEFAULT '', function_code TEXT DEFAULT '',
			operation TEXT DEFAULT '', register_addr TEXT DEFAULT '',
			value TEXT DEFAULT '', is_authorized BOOLEAN DEFAULT true,
			severity TEXT DEFAULT 'info', created_at TIMESTAMPTZ DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS ot_alerts (
			id SERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL,
			asset_id INTEGER DEFAULT 0, alert_type TEXT DEFAULT '',
			title TEXT DEFAULT '', description TEXT DEFAULT '',
			severity TEXT DEFAULT 'medium', protocol TEXT DEFAULT '',
			src_ip TEXT DEFAULT '', status TEXT DEFAULT 'open',
			created_at TIMESTAMPTZ DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS ot_vulnerabilities (
			id SERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL,
			asset_id INTEGER DEFAULT 0, cve_id TEXT DEFAULT '',
			cvss NUMERIC(4,1) DEFAULT 0, severity TEXT DEFAULT 'medium',
			title TEXT DEFAULT '', vendor_advisory TEXT DEFAULT '',
			patch_available BOOLEAN DEFAULT false, requires_maintenance_window BOOLEAN DEFAULT true,
			created_at TIMESTAMPTZ DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS ot_zones (
			id SERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL,
			name TEXT DEFAULT '', purdue_level INTEGER DEFAULT 2,
			asset_count INTEGER DEFAULT 0, allowed_protocols TEXT DEFAULT '',
			firewall_policy TEXT DEFAULT '', risk_score INTEGER DEFAULT 0,
			created_at TIMESTAMPTZ DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS ot_baselines (
			id SERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL,
			baseline_type TEXT DEFAULT '', description TEXT DEFAULT '',
			learned_at TIMESTAMPTZ DEFAULT NOW(), is_active BOOLEAN DEFAULT true,
			created_at TIMESTAMPTZ DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS ot_incidents (
			id SERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL,
			title TEXT DEFAULT '', description TEXT DEFAULT '',
			severity TEXT DEFAULT 'medium', status TEXT DEFAULT 'open',
			affected_assets TEXT DEFAULT '', response_mode TEXT DEFAULT 'alert_only',
			created_at TIMESTAMPTZ DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS ot_firmware (
			id SERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL,
			asset_id INTEGER DEFAULT 0, firmware_version TEXT DEFAULT '',
			previous_version TEXT DEFAULT '', changed_at TIMESTAMPTZ DEFAULT NOW(),
			changed_by TEXT DEFAULT '', is_authorized BOOLEAN DEFAULT false,
			created_at TIMESTAMPTZ DEFAULT NOW()
		)`,
	}
	for _, s := range stmts {
		database.DB.Exec(s)
	}
}

// GetOTDashboard — GET /api/ot/dashboard
func GetOTDashboard(c *gin.Context) {
	createOTICSTables()
	tid := tenantIDFromContext(c)
	var sites, plcs, hmis, rtus, ewss, scadaServers, totalAssets, criticalAlerts, activeIncidents int
	var riskScore float64
	database.DB.QueryRow(`SELECT COUNT(DISTINCT site) FROM ot_assets WHERE tenant_id=$1`, tid).Scan(&sites)
	database.DB.QueryRow(`SELECT COUNT(*) FROM ot_assets WHERE tenant_id=$1 AND asset_type='plc'`, tid).Scan(&plcs)
	database.DB.QueryRow(`SELECT COUNT(*) FROM ot_assets WHERE tenant_id=$1 AND asset_type='hmi'`, tid).Scan(&hmis)
	database.DB.QueryRow(`SELECT COUNT(*) FROM ot_assets WHERE tenant_id=$1 AND asset_type='rtu'`, tid).Scan(&rtus)
	database.DB.QueryRow(`SELECT COUNT(*) FROM ot_assets WHERE tenant_id=$1 AND asset_type='engineering_workstation'`, tid).Scan(&ewss)
	database.DB.QueryRow(`SELECT COUNT(*) FROM ot_assets WHERE tenant_id=$1 AND asset_type='scada_server'`, tid).Scan(&scadaServers)
	database.DB.QueryRow(`SELECT COUNT(*) FROM ot_assets WHERE tenant_id=$1`, tid).Scan(&totalAssets)
	database.DB.QueryRow(`SELECT COUNT(*) FROM ot_alerts WHERE tenant_id=$1 AND severity='critical' AND status='open'`, tid).Scan(&criticalAlerts)
	database.DB.QueryRow(`SELECT COUNT(*) FROM ot_incidents WHERE tenant_id=$1 AND status='open'`, tid).Scan(&activeIncidents)
	database.DB.QueryRow(`SELECT COALESCE(AVG(risk_score),50) FROM ot_assets WHERE tenant_id=$1`, tid).Scan(&riskScore)
	var industrial_zones int
	database.DB.QueryRow(`SELECT COUNT(*) FROM ot_zones WHERE tenant_id=$1`, tid).Scan(&industrial_zones)
	networkHealth := 94
	if criticalAlerts > 5 {
		networkHealth = 72
	}
	c.JSON(http.StatusOK, gin.H{
		"sites":                    sites,
		"industrial_zones":         industrial_zones,
		"plcs":                     plcs,
		"hmis":                     hmis,
		"rtus":                     rtus,
		"engineering_workstations": ewss,
		"scada_servers":            scadaServers,
		"total_assets":             totalAssets,
		"ot_risk_score":            int(riskScore),
		"critical_alerts":          criticalAlerts,
		"active_incidents":         activeIncidents,
		"network_health":           networkHealth,
	})
}

// GetOTAssets — GET /api/ot/assets
func GetOTAssets(c *gin.Context) {
	createOTICSTables()
	tid := tenantIDFromContext(c)
	limit := parseLimit(c, 100)
	q := `SELECT id, name, asset_type, vendor, model, firmware, ip, mac,
		zone, site, purdue_level, criticality, risk_score, is_online, uptime_hours, last_seen, created_at
		FROM ot_assets WHERE tenant_id=$1`
	args := []interface{}{tid}
	i := 2
	if v := c.Query("type"); v != "" {
		q += fmt.Sprintf(" AND asset_type=$%d", i)
		args = append(args, v)
		i++
	}
	if v := c.Query("zone"); v != "" {
		q += fmt.Sprintf(" AND zone=$%d", i)
		args = append(args, v)
		i++
	}
	if v := c.Query("site"); v != "" {
		q += fmt.Sprintf(" AND site=$%d", i)
		args = append(args, v)
		i++
	}
	q += fmt.Sprintf(" ORDER BY risk_score DESC LIMIT $%d", i)
	args = append(args, limit)
	rows, err := database.DB.Query(q, args...)
	type Asset struct {
		ID          int    `json:"id"`
		Name        string `json:"name"`
		AssetType   string `json:"asset_type"`
		Vendor      string `json:"vendor"`
		Model       string `json:"model"`
		Firmware    string `json:"firmware"`
		IP          string `json:"ip"`
		MAC         string `json:"mac"`
		Zone        string `json:"zone"`
		Site        string `json:"site"`
		PurdueLevel int    `json:"purdue_level"`
		Criticality string `json:"criticality"`
		RiskScore   int    `json:"risk_score"`
		IsOnline    bool   `json:"is_online"`
		UptimeHours int    `json:"uptime_hours"`
		LastSeen    string `json:"last_seen"`
		CreatedAt   string `json:"created_at"`
	}
	assets := []Asset{}
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var a Asset
			if rows.Scan(&a.ID, &a.Name, &a.AssetType, &a.Vendor, &a.Model, &a.Firmware, &a.IP, &a.MAC,
				&a.Zone, &a.Site, &a.PurdueLevel, &a.Criticality, &a.RiskScore, &a.IsOnline, &a.UptimeHours, &a.LastSeen, &a.CreatedAt) == nil {
				assets = append(assets, a)
			}
		}
	}
	if assets == nil {
		assets = []Asset{}
	}
	c.JSON(http.StatusOK, assets)
}

// GetOTTopology — GET /api/ot/topology
func GetOTTopology(c *gin.Context) {
	createOTICSTables()
	tid := tenantIDFromContext(c)
	rows, _ := database.DB.Query(`SELECT id, name, asset_type, ip, zone, purdue_level, is_online, risk_score
		FROM ot_assets WHERE tenant_id=$1 LIMIT 50`, tid)
	type Node struct {
		ID          int    `json:"id"`
		Name        string `json:"name"`
		AssetType   string `json:"asset_type"`
		IP          string `json:"ip"`
		Zone        string `json:"zone"`
		PurdueLevel int    `json:"purdue_level"`
		IsOnline    bool   `json:"is_online"`
		RiskScore   int    `json:"risk_score"`
	}
	nodes := []Node{}
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var n Node
			if rows.Scan(&n.ID, &n.Name, &n.AssetType, &n.IP, &n.Zone, &n.PurdueLevel, &n.IsOnline, &n.RiskScore) == nil {
				nodes = append(nodes, n)
			}
		}
	}
	if nodes == nil {
		nodes = []Node{}
	}

	type Link struct {
		Src      string `json:"src"`
		Dst      string `json:"dst"`
		Protocol string `json:"protocol"`
		Active   bool   `json:"active"`
	}
	links := []Link{}
	linkRows, _ := database.DB.Query(`
		SELECT src_ip, dst_ip, protocol, bool_or(created_at > NOW() - INTERVAL '1 hour') AS active
		FROM ot_traffic WHERE tenant_id=$1
		GROUP BY src_ip, dst_ip, protocol LIMIT 50`, tid)
	if linkRows != nil {
		defer linkRows.Close()
		for linkRows.Next() {
			var l Link
			if linkRows.Scan(&l.Src, &l.Dst, &l.Protocol, &l.Active) == nil {
				links = append(links, l)
			}
		}
	}
	c.JSON(http.StatusOK, gin.H{"nodes": nodes, "links": links})
}

// GetOTProtocols — GET /api/ot/protocols
func GetOTProtocols(c *gin.Context) {
	createOTICSTables()
	tid := tenantIDFromContext(c)
	rows, _ := database.DB.Query(`SELECT protocol, COUNT(*) as count
		FROM ot_traffic WHERE tenant_id=$1 GROUP BY protocol ORDER BY count DESC LIMIT 20`, tid)
	type ProtoStat struct {
		Protocol string `json:"protocol"`
		Count    int    `json:"count"`
	}
	stats := []ProtoStat{}
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var s ProtoStat
			if rows.Scan(&s.Protocol, &s.Count) == nil {
				stats = append(stats, s)
			}
		}
	}
	if stats == nil {
		stats = []ProtoStat{}
	}

	type Session struct {
		Src      string `json:"src"`
		Dst      string `json:"dst"`
		Protocol string `json:"protocol"`
		Packets  int    `json:"packets"`
		LastSeen string `json:"last_seen"`
		Anomaly  string `json:"anomaly,omitempty"`
	}
	sessions := []Session{}
	sRows, _ := database.DB.Query(`
		SELECT src_ip, dst_ip, protocol, COUNT(*) AS packets, MAX(created_at) AS last_seen, bool_or(is_authorized=false) AS unauthorized
		FROM ot_traffic WHERE tenant_id=$1
		GROUP BY src_ip, dst_ip, protocol ORDER BY packets DESC LIMIT 20`, tid)
	if sRows != nil {
		defer sRows.Close()
		for sRows.Next() {
			var s Session
			var unauthorized bool
			if sRows.Scan(&s.Src, &s.Dst, &s.Protocol, &s.Packets, &s.LastSeen, &unauthorized) == nil {
				if unauthorized {
					s.Anomaly = "unauthorized_source"
				}
				sessions = append(sessions, s)
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"protocol_stats": stats,
		"supported_protocols": []string{
			"Modbus TCP", "DNP3", "OPC UA", "EtherNet/IP", "PROFINET",
			"BACnet", "IEC 60870-5-104", "IEC 61850", "S7", "CIP", "MQTT",
		},
		"sessions": sessions,
	})
}

// GetOTTraffic — GET /api/ot/traffic
func GetOTTraffic(c *gin.Context) {
	createOTICSTables()
	tid := tenantIDFromContext(c)
	limit := parseLimit(c, 50)
	q := `SELECT id, src_ip, dst_ip, protocol, function_code, operation,
		register_addr, value, is_authorized, severity, created_at
		FROM ot_traffic WHERE tenant_id=$1`
	args := []interface{}{tid}
	i := 2
	if v := c.Query("protocol"); v != "" {
		q += fmt.Sprintf(" AND protocol=$%d", i)
		args = append(args, v)
		i++
	}
	if c.Query("unauthorized") == "true" {
		q += " AND is_authorized=false"
	}
	q += fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d", i)
	args = append(args, limit)
	rows, err := database.DB.Query(q, args...)
	type Traffic struct {
		ID           int    `json:"id"`
		SrcIP        string `json:"src_ip"`
		DstIP        string `json:"dst_ip"`
		Protocol     string `json:"protocol"`
		FunctionCode string `json:"function_code"`
		Operation    string `json:"operation"`
		RegisterAddr string `json:"register_addr"`
		Value        string `json:"value"`
		IsAuthorized bool   `json:"is_authorized"`
		Severity     string `json:"severity"`
		CreatedAt    string `json:"created_at"`
	}
	traffic := []Traffic{}
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var t Traffic
			if rows.Scan(&t.ID, &t.SrcIP, &t.DstIP, &t.Protocol, &t.FunctionCode, &t.Operation,
				&t.RegisterAddr, &t.Value, &t.IsAuthorized, &t.Severity, &t.CreatedAt) == nil {
				traffic = append(traffic, t)
			}
		}
	}
	if traffic == nil {
		traffic = []Traffic{}
	}
	c.JSON(http.StatusOK, traffic)
}

// GetOTAlerts — GET /api/ot/alerts
func GetOTAlerts(c *gin.Context) {
	createOTICSTables()
	tid := tenantIDFromContext(c)
	limit := parseLimit(c, 50)
	q := `SELECT id, asset_id, alert_type, title, description, severity, protocol, src_ip, status, created_at
		FROM ot_alerts WHERE tenant_id=$1`
	args := []interface{}{tid}
	i := 2
	if v := c.Query("severity"); v != "" {
		q += fmt.Sprintf(" AND severity=$%d", i)
		args = append(args, v)
		i++
	}
	q += fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d", i)
	args = append(args, limit)
	rows, err := database.DB.Query(q, args...)
	type Alert struct {
		ID          int    `json:"id"`
		AssetID     int    `json:"asset_id"`
		AlertType   string `json:"alert_type"`
		Title       string `json:"title"`
		Description string `json:"description"`
		Severity    string `json:"severity"`
		Protocol    string `json:"protocol"`
		SrcIP       string `json:"src_ip"`
		Status      string `json:"status"`
		CreatedAt   string `json:"created_at"`
	}
	alerts := []Alert{}
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var a Alert
			if rows.Scan(&a.ID, &a.AssetID, &a.AlertType, &a.Title, &a.Description, &a.Severity, &a.Protocol, &a.SrcIP, &a.Status, &a.CreatedAt) == nil {
				alerts = append(alerts, a)
			}
		}
	}
	if alerts == nil {
		alerts = []Alert{}
	}
	var total, open, critical int
	database.DB.QueryRow(`SELECT COUNT(*) FROM ot_alerts WHERE tenant_id=$1`, tid).Scan(&total)
	database.DB.QueryRow(`SELECT COUNT(*) FROM ot_alerts WHERE tenant_id=$1 AND status='open'`, tid).Scan(&open)
	database.DB.QueryRow(`SELECT COUNT(*) FROM ot_alerts WHERE tenant_id=$1 AND severity='critical'`, tid).Scan(&critical)
	c.JSON(http.StatusOK, gin.H{"alerts": alerts, "total": total, "open": open, "critical": critical})
}

// GetOTDeviceStatus — GET /api/ot/devices
func GetOTDeviceStatus(c *gin.Context) {
	createOTICSTables()
	tid := tenantIDFromContext(c)
	rows, _ := database.DB.Query(`SELECT id, name, asset_type, firmware, ip, zone, is_online, uptime_hours, last_seen
		FROM ot_assets WHERE tenant_id=$1 ORDER BY is_online DESC, last_seen DESC LIMIT 50`, tid)
	type Device struct {
		ID          int    `json:"id"`
		Name        string `json:"name"`
		AssetType   string `json:"asset_type"`
		Firmware    string `json:"firmware"`
		IP          string `json:"ip"`
		Zone        string `json:"zone"`
		IsOnline    bool   `json:"is_online"`
		UptimeHours int    `json:"uptime_hours"`
		LastSeen    string `json:"last_seen"`
	}
	devices := []Device{}
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var d Device
			if rows.Scan(&d.ID, &d.Name, &d.AssetType, &d.Firmware, &d.IP, &d.Zone, &d.IsOnline, &d.UptimeHours, &d.LastSeen) == nil {
				devices = append(devices, d)
			}
		}
	}
	if devices == nil {
		devices = []Device{}
	}
	fwRows, _ := database.DB.Query(`SELECT id, asset_id, firmware_version, previous_version, changed_at, changed_by, is_authorized
		FROM ot_firmware WHERE tenant_id=$1 ORDER BY changed_at DESC LIMIT 20`, tid)
	type FWChange struct {
		ID              int    `json:"id"`
		AssetID         int    `json:"asset_id"`
		FirmwareVersion string `json:"firmware_version"`
		PreviousVersion string `json:"previous_version"`
		ChangedAt       string `json:"changed_at"`
		ChangedBy       string `json:"changed_by"`
		IsAuthorized    bool   `json:"is_authorized"`
	}
	fwChanges := []FWChange{}
	if fwRows != nil {
		defer fwRows.Close()
		for fwRows.Next() {
			var f FWChange
			if fwRows.Scan(&f.ID, &f.AssetID, &f.FirmwareVersion, &f.PreviousVersion, &f.ChangedAt, &f.ChangedBy, &f.IsAuthorized) == nil {
				fwChanges = append(fwChanges, f)
			}
		}
	}
	if fwChanges == nil {
		fwChanges = []FWChange{}
	}
	c.JSON(http.StatusOK, gin.H{"devices": devices, "firmware_changes": fwChanges})
}

// GetOTThreatDetection — GET /api/ot/threats
func GetOTThreatDetection(c *gin.Context) {
	createOTICSTables()
	tid := tenantIDFromContext(c)
	limit := parseLimit(c, 50)
	rows, _ := database.DB.Query(`SELECT id, alert_type, title, description, severity, protocol, src_ip, status, created_at
		FROM ot_alerts WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT $2`, tid, limit)
	type Threat struct {
		ID          int    `json:"id"`
		AlertType   string `json:"alert_type"`
		Title       string `json:"title"`
		Description string `json:"description"`
		Severity    string `json:"severity"`
		Protocol    string `json:"protocol"`
		SrcIP       string `json:"src_ip"`
		Status      string `json:"status"`
		CreatedAt   string `json:"created_at"`
	}
	threats := []Threat{}
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var t Threat
			if rows.Scan(&t.ID, &t.AlertType, &t.Title, &t.Description, &t.Severity, &t.Protocol, &t.SrcIP, &t.Status, &t.CreatedAt) == nil {
				threats = append(threats, t)
			}
		}
	}
	if threats == nil {
		threats = []Threat{}
	}
	c.JSON(http.StatusOK, gin.H{
		"threats": threats,
		"detection_categories": []string{
			"unauthorized_plc_programming", "firmware_change", "engineering_station_abuse",
			"new_device", "protocol_misuse", "command_injection",
			"unauthorized_write", "network_scanning", "lateral_movement",
		},
	})
}

// GetOTDPI — GET /api/ot/dpi
func GetOTDPI(c *gin.Context) {
	createOTICSTables()
	tid := tenantIDFromContext(c)
	limit := parseLimit(c, 50)
	rows, _ := database.DB.Query(`SELECT id, src_ip, dst_ip, protocol, function_code, operation,
		register_addr, value, is_authorized, severity, created_at
		FROM ot_traffic WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT $2`, tid, limit)
	type DPIEntry struct {
		ID           int    `json:"id"`
		SrcIP        string `json:"src_ip"`
		DstIP        string `json:"dst_ip"`
		Protocol     string `json:"protocol"`
		FunctionCode string `json:"function_code"`
		Operation    string `json:"operation"`
		RegisterAddr string `json:"register_addr"`
		Value        string `json:"value"`
		IsAuthorized bool   `json:"is_authorized"`
		Severity     string `json:"severity"`
		CreatedAt    string `json:"created_at"`
	}
	entries := []DPIEntry{}
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var e DPIEntry
			if rows.Scan(&e.ID, &e.SrcIP, &e.DstIP, &e.Protocol, &e.FunctionCode, &e.Operation,
				&e.RegisterAddr, &e.Value, &e.IsAuthorized, &e.Severity, &e.CreatedAt) == nil {
				entries = append(entries, e)
			}
		}
	}
	if entries == nil {
		entries = []DPIEntry{}
	}
	c.JSON(http.StatusOK, gin.H{"decoded_frames": entries})
}

// GetOTRiskAssessment — GET /api/ot/risk
func GetOTRiskAssessment(c *gin.Context) {
	createOTICSTables()
	tid := tenantIDFromContext(c)
	var total, internetExposed, unsupportedFirmware, missingSegmentation int
	database.DB.QueryRow(`SELECT COUNT(*) FROM ot_assets WHERE tenant_id=$1`, tid).Scan(&total)
	database.DB.QueryRow(`SELECT COUNT(*) FROM ot_assets WHERE tenant_id=$1 AND purdue_level=0`, tid).Scan(&internetExposed)
	database.DB.QueryRow(`SELECT COUNT(*) FROM ot_assets WHERE tenant_id=$1 AND firmware LIKE '%-eol'`, tid).Scan(&unsupportedFirmware)
	database.DB.QueryRow(`SELECT COUNT(*) FROM ot_zones WHERE tenant_id=$1 AND (firewall_policy='' OR firewall_policy IS NULL)`, tid).Scan(&missingSegmentation)

	criticalAssets := []map[string]interface{}{}
	rows, err := database.DB.Query(`
		SELECT name, asset_type, ip, purdue_level, firmware, criticality, risk_score
		FROM ot_assets WHERE tenant_id=$1 AND risk_score>=60 ORDER BY risk_score DESC LIMIT 10`, tid)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var name, atype, ip, firmware, criticality string
			var purdue, risk int
			if rows.Scan(&name, &atype, &ip, &purdue, &firmware, &criticality, &risk) == nil {
				reasons := []string{}
				if purdue == 0 {
					reasons = append(reasons, "internet-reachable (Purdue level 0)")
				}
				if strings.HasSuffix(firmware, "-eol") {
					reasons = append(reasons, "running end-of-life firmware ("+firmware+")")
				}
				if criticality == "critical" || criticality == "high" {
					reasons = append(reasons, criticality+" criticality asset")
				}
				reason := strings.Join(reasons, "; ")
				if reason == "" {
					reason = "elevated risk score"
				}
				criticalAssets = append(criticalAssets, map[string]interface{}{
					"name": name, "type": atype, "ip": ip, "risk": risk, "reason": reason,
				})
			}
		}
	}

	findings := []map[string]interface{}{}
	if internetExposed > 0 {
		findings = append(findings, map[string]interface{}{
			"category": "Internet Exposure", "count": internetExposed, "severity": "critical",
			"detail": fmt.Sprintf("%d OT assets are at Purdue level 0 (internet-reachable)", internetExposed),
		})
	}
	if unsupportedFirmware > 0 {
		findings = append(findings, map[string]interface{}{
			"category": "Unsupported Firmware", "count": unsupportedFirmware, "severity": "high",
			"detail": fmt.Sprintf("%d devices running firmware versions no longer receiving security updates", unsupportedFirmware),
		})
	}
	if missingSegmentation > 0 {
		findings = append(findings, map[string]interface{}{
			"category": "Missing Segmentation", "count": missingSegmentation, "severity": "high",
			"detail": fmt.Sprintf("%d zones have no firewall policy configured", missingSegmentation),
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"total_assets":         total,
		"internet_exposed":     internetExposed,
		"unsupported_firmware": unsupportedFirmware,
		"missing_segmentation": missingSegmentation,
		"critical_assets":      criticalAssets,
		"findings":             findings,
	})
}

// GetOTVulnerabilities — GET /api/ot/vulnerabilities
func GetOTVulnerabilities(c *gin.Context) {
	createOTICSTables()
	tid := tenantIDFromContext(c)
	limit := parseLimit(c, 50)
	rows, _ := database.DB.Query(`SELECT id, asset_id, cve_id, cvss, severity, title,
		vendor_advisory, patch_available, requires_maintenance_window, created_at
		FROM ot_vulnerabilities WHERE tenant_id=$1 ORDER BY cvss DESC LIMIT $2`, tid, limit)
	type Vuln struct {
		ID                        int     `json:"id"`
		AssetID                   int     `json:"asset_id"`
		CVEID                     string  `json:"cve_id"`
		CVSS                      float64 `json:"cvss"`
		Severity                  string  `json:"severity"`
		Title                     string  `json:"title"`
		VendorAdvisory            string  `json:"vendor_advisory"`
		PatchAvailable            bool    `json:"patch_available"`
		RequiresMaintenanceWindow bool    `json:"requires_maintenance_window"`
		CreatedAt                 string  `json:"created_at"`
	}
	vulns := []Vuln{}
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var v Vuln
			if rows.Scan(&v.ID, &v.AssetID, &v.CVEID, &v.CVSS, &v.Severity, &v.Title,
				&v.VendorAdvisory, &v.PatchAvailable, &v.RequiresMaintenanceWindow, &v.CreatedAt) == nil {
				vulns = append(vulns, v)
			}
		}
	}
	if vulns == nil {
		vulns = []Vuln{}
	}
	var critical, high, patchable int
	database.DB.QueryRow(`SELECT COUNT(*) FROM ot_vulnerabilities WHERE tenant_id=$1 AND severity='critical'`, tid).Scan(&critical)
	database.DB.QueryRow(`SELECT COUNT(*) FROM ot_vulnerabilities WHERE tenant_id=$1 AND severity='high'`, tid).Scan(&high)
	database.DB.QueryRow(`SELECT COUNT(*) FROM ot_vulnerabilities WHERE tenant_id=$1 AND patch_available=true`, tid).Scan(&patchable)
	c.JSON(http.StatusOK, gin.H{"vulns": vulns, "critical": critical, "high": high, "patchable": patchable})
}

// GetOTZones — GET /api/ot/zones
func GetOTZones(c *gin.Context) {
	createOTICSTables()
	tid := tenantIDFromContext(c)
	rows, _ := database.DB.Query(`SELECT id, name, purdue_level, asset_count, allowed_protocols, firewall_policy, risk_score
		FROM ot_zones WHERE tenant_id=$1 ORDER BY purdue_level`, tid)
	type Zone struct {
		ID               int    `json:"id"`
		Name             string `json:"name"`
		PurdueLevel      int    `json:"purdue_level"`
		AssetCount       int    `json:"asset_count"`
		AllowedProtocols string `json:"allowed_protocols"`
		FirewallPolicy   string `json:"firewall_policy"`
		RiskScore        int    `json:"risk_score"`
	}
	zones := []Zone{}
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var z Zone
			if rows.Scan(&z.ID, &z.Name, &z.PurdueLevel, &z.AssetCount, &z.AllowedProtocols, &z.FirewallPolicy, &z.RiskScore) == nil {
				zones = append(zones, z)
			}
		}
	}
	if zones == nil {
		zones = []Zone{}
	}
	c.JSON(http.StatusOK, gin.H{
		"zones": zones,
		"purdue_model": []map[string]interface{}{
			{"level": 4, "name": "Enterprise IT", "description": "Business planning & logistics (ERP, email, corporate IT)", "asset_types": []string{"workstation", "server", "printer"}},
			{"level": 3, "name": "Operations & Business Logistics", "description": "Site-wide operations, Historians, MES systems", "asset_types": []string{"historian", "mes_server", "reporting"}},
			{"level": 2, "name": "Supervisory Control", "description": "SCADA, DCS, HMI systems", "asset_types": []string{"scada_server", "hmi", "dcs"}},
			{"level": 1, "name": "Control", "description": "PLCs, RTUs, field control devices", "asset_types": []string{"plc", "rtu", "dcs_controller"}},
			{"level": 0, "name": "Process", "description": "Physical process: sensors, actuators, drives", "asset_types": []string{"sensor", "actuator", "drive"}},
		},
		"allowed_paths": []map[string]interface{}{
			{"from_level": 4, "to_level": 3, "allowed": true, "protocols": "HTTPS,RDP (managed)", "requires_firewall": true},
			{"from_level": 3, "to_level": 2, "allowed": true, "protocols": "OPC UA,Historian replication", "requires_firewall": true},
			{"from_level": 2, "to_level": 1, "allowed": true, "protocols": "Modbus TCP,EtherNet/IP,DNP3", "requires_firewall": false},
			{"from_level": 1, "to_level": 0, "allowed": true, "protocols": "Modbus RTU,Profibus,CAN", "requires_firewall": false},
			{"from_level": 4, "to_level": 1, "allowed": false, "protocols": "", "requires_firewall": true},
			{"from_level": 4, "to_level": 0, "allowed": false, "protocols": "", "requires_firewall": true},
		},
	})
}

// GetOTBaseline — GET /api/ot/baseline
func GetOTBaseline(c *gin.Context) {
	createOTICSTables()
	tid := tenantIDFromContext(c)
	rows, _ := database.DB.Query(`SELECT id, baseline_type, description, learned_at, is_active
		FROM ot_baselines WHERE tenant_id=$1 ORDER BY learned_at DESC LIMIT 50`, tid)
	type Baseline struct {
		ID           int    `json:"id"`
		BaselineType string `json:"baseline_type"`
		Description  string `json:"description"`
		LearnedAt    string `json:"learned_at"`
		IsActive     bool   `json:"is_active"`
	}
	baselines := []Baseline{}
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var b Baseline
			if rows.Scan(&b.ID, &b.BaselineType, &b.Description, &b.LearnedAt, &b.IsActive) == nil {
				baselines = append(baselines, b)
			}
		}
	}
	if baselines == nil {
		baselines = []Baseline{}
	}

	type catRow struct {
		Type    string `json:"type"`
		Learned bool   `json:"learned"`
		Items   int    `json:"items"`
	}
	categories := []catRow{}
	catRows, _ := database.DB.Query(`
		SELECT baseline_type, bool_or(is_active), COUNT(*)
		FROM ot_baselines WHERE tenant_id=$1 GROUP BY baseline_type ORDER BY baseline_type`, tid)
	if catRows != nil {
		defer catRows.Close()
		for catRows.Next() {
			var r catRow
			if catRows.Scan(&r.Type, &r.Learned, &r.Items) == nil {
				categories = append(categories, r)
			}
		}
	}

	deviations := []map[string]interface{}{}
	devRows, _ := database.DB.Query(`
		SELECT alert_type, title, severity, created_at FROM ot_alerts
		WHERE tenant_id=$1 AND status='open' ORDER BY created_at DESC LIMIT 10`, tid)
	if devRows != nil {
		defer devRows.Close()
		for devRows.Next() {
			var atype, title, severity, createdAt string
			if devRows.Scan(&atype, &title, &severity, &createdAt) == nil {
				deviations = append(deviations, map[string]interface{}{
					"type": atype, "detail": title, "severity": severity, "time": createdAt,
				})
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"baselines":  baselines,
		"categories": categories,
		"deviations": deviations,
	})
}

// GetOTThreatIntel — GET /api/ot/threat-intel
func GetOTThreatIntel(c *gin.Context) {
	createOTICSTables()
	tid := tenantIDFromContext(c)

	// Real per-tenant IOC matching: check this tenant's actual iocs table
	// against IPs seen in real OT traffic/assets. Only emit a match when a
	// real row exists — no placeholder rows.
	iocMatches := []map[string]interface{}{}
	rows, err := database.DB.Query(`
		SELECT DISTINCT i.type, i.indicator, i.hit_count
		FROM iocs i
		WHERE i.tenant_id=$1 AND i.enabled=true AND i.type='ip'
		AND (
			EXISTS (SELECT 1 FROM ot_assets a WHERE a.tenant_id=$1 AND a.ip=i.indicator)
			OR EXISTS (SELECT 1 FROM ot_traffic t WHERE t.tenant_id=$1 AND (t.src_ip=i.indicator OR t.dst_ip=i.indicator))
		)
		ORDER BY i.hit_count DESC LIMIT 10`, tid)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var itype, indicator string
			var hits int
			if rows.Scan(&itype, &indicator, &hits) == nil {
				iocMatches = append(iocMatches, map[string]interface{}{
					"type": itype, "value": indicator, "hits": hits,
				})
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"ioc_matches": iocMatches,
		"ot_threat_actors": []map[string]interface{}{
			{"name": "Sandworm", "nation": "Russia", "targets": "Energy, Water, Critical Infrastructure", "malware": "BlackEnergy, Industroyer, CaddyWiper", "active": true, "risk": "critical"},
			{"name": "XENOTIME", "nation": "Russia", "targets": "Oil & Gas, Safety Systems (SIS)", "malware": "TRITON/TRISIS", "active": true, "risk": "critical"},
			{"name": "APT40", "nation": "China", "targets": "Maritime, Defense, Aviation ICS", "malware": "Custom RATs", "active": true, "risk": "high"},
			{"name": "Lazarus Group", "nation": "North Korea", "targets": "Energy, Defense ICS", "malware": "BLINDINGCAN", "active": true, "risk": "high"},
			{"name": "MAGNALLIUM", "nation": "Iran", "targets": "ICS/SCADA, Oil & Gas", "malware": "POWERSHOWER", "active": false, "risk": "medium"},
		},
		"industrial_malware": []map[string]interface{}{
			{"name": "TRITON/TRISIS", "type": "SIS Attack", "target": "Schneider Triconex SIS", "year": 2017, "capability": "Physical damage via Safety Instrumented System manipulation"},
			{"name": "Industroyer/CRASHOVERRIDE", "type": "Power Grid Attack", "target": "IEC 60870-5-101/104, IEC 61850, OPC DA", "year": 2016, "capability": "Electric grid disruption — caused 2016 Ukraine blackout"},
			{"name": "Stuxnet", "type": "PLC Worm", "target": "Siemens S7-315/S7-417 + Step 7", "year": 2010, "capability": "Physical destruction of centrifuges via PLC logic manipulation"},
			{"name": "BlackEnergy", "type": "ICS Recon Malware", "target": "HMI systems, GE Cimplicity, Siemens WinCC", "year": 2015, "capability": "Credential theft, file destruction, ICS plugin framework"},
			{"name": "FrostyGoop", "type": "Modbus Attack", "target": "Lviv District Heating", "year": 2024, "capability": "Direct Modbus TCP commands caused heating outage in winter"},
		},
		"sector_advisories": []map[string]interface{}{
			{"id": "CISA-ICS-24-001", "title": "Rockwell Automation PLC RCE Vulnerability", "severity": "critical", "date": "2024-01-15", "affected": "ControlLogix, CompactLogix"},
			{"id": "CISA-ICS-24-007", "title": "Schneider Electric Modicon Authentication Bypass", "severity": "high", "date": "2024-02-03", "affected": "Modicon M340, M580"},
			{"id": "CISA-ICS-24-012", "title": "Siemens SIMATIC S7 Denial of Service", "severity": "high", "date": "2024-03-12", "affected": "S7-300, S7-400, S7-1200, S7-1500"},
		},
	})
}

// GetOTTimeline — GET /api/ot/timeline
func GetOTTimeline(c *gin.Context) {
	createOTICSTables()
	tid := tenantIDFromContext(c)
	limit := parseLimit(c, 50)
	rows, _ := database.DB.Query(`SELECT id, alert_type, title, severity, src_ip, status, created_at
		FROM ot_alerts WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT $2`, tid, limit)
	type TLEvent struct {
		ID        int    `json:"id"`
		EventType string `json:"event_type"`
		Title     string `json:"title"`
		Severity  string `json:"severity"`
		Source    string `json:"source"`
		Status    string `json:"status"`
		CreatedAt string `json:"created_at"`
	}
	events := []TLEvent{}
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var id int
			var alertType, title, severity, srcIP, status, createdAt string
			if rows.Scan(&id, &alertType, &title, &severity, &srcIP, &status, &createdAt) == nil {
				events = append(events, TLEvent{ID: id, EventType: alertType, Title: title, Severity: severity, Source: srcIP, Status: status, CreatedAt: createdAt})
			}
		}
	}
	if events == nil {
		events = []TLEvent{}
	}
	c.JSON(http.StatusOK, events)
}

// GetOTCompliance — GET /api/ot/compliance
func GetOTCompliance(c *gin.Context) {
	createOTICSTables()
	createFCETables()
	tid := tenantIDFromContext(c)
	db := database.DB

	type fwRow struct {
		Name   string `json:"name"`
		Score  int    `json:"score"`
		Passed int    `json:"passed"`
		Failed int    `json:"failed"`
		Total  int    `json:"total"`
		Status string `json:"status"`
	}
	frows, _ := db.Query(`SELECT name, overall_score, passed_controls, failed_controls, total_controls, compliance_status
		FROM fce_frameworks WHERE tenant_id=$1 AND is_active=TRUE ORDER BY overall_score ASC`, tid)
	frameworks := []fwRow{}
	if frows != nil {
		defer frows.Close()
		for frows.Next() {
			var r fwRow
			if frows.Scan(&r.Name, &r.Score, &r.Passed, &r.Failed, &r.Total, &r.Status) == nil {
				frameworks = append(frameworks, r)
			}
		}
	}

	var overallScore float64
	db.QueryRow(`SELECT COALESCE(AVG(overall_score),0) FROM fce_frameworks WHERE tenant_id=$1 AND is_active=TRUE`, tid).Scan(&overallScore)

	type ctrlRow struct {
		Control   string `json:"control"`
		Title     string `json:"title"`
		Severity  string `json:"severity"`
		Framework string `json:"framework"`
	}
	crows, _ := db.Query(`SELECT c.control_id, c.name, c.risk_level, f.name
		FROM fce_controls c JOIN fce_frameworks f ON f.id=c.framework_id
		WHERE c.tenant_id=$1 AND c.assessment_status='failed'
		ORDER BY CASE c.risk_level WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END LIMIT 20`, tid)
	failedControls := []ctrlRow{}
	if crows != nil {
		defer crows.Close()
		for crows.Next() {
			var r ctrlRow
			if crows.Scan(&r.Control, &r.Title, &r.Severity, &r.Framework) == nil {
				failedControls = append(failedControls, r)
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"overall_score":   int(overallScore),
		"frameworks":      frameworks,
		"failed_controls": failedControls,
	})
}

// GetOTAttackPaths — GET /api/ot/attack-paths
func GetOTAttackPaths(c *gin.Context) {
	createOTICSTables()
	tid := tenantIDFromContext(c)

	riskAssets := []map[string]interface{}{}
	rows, err := database.DB.Query(`
		SELECT name, asset_type, ip, zone, purdue_level, criticality, risk_score
		FROM ot_assets WHERE tenant_id=$1 ORDER BY risk_score DESC LIMIT 5`, tid)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var name, atype, ip, zone, criticality string
			var purdue, risk int
			if rows.Scan(&name, &atype, &ip, &zone, &purdue, &criticality, &risk) == nil {
				riskAssets = append(riskAssets, map[string]interface{}{
					"name": name, "asset_type": atype, "ip": ip, "zone": zone,
					"purdue_level": purdue, "criticality": criticality, "risk_score": risk,
				})
			}
		}
	}

	exposedVulns := []map[string]interface{}{}
	vRows, err := database.DB.Query(`
		SELECT v.cve_id, v.cvss, v.severity, a.name
		FROM ot_vulnerabilities v JOIN ot_assets a ON a.id=v.asset_id AND a.tenant_id=v.tenant_id
		WHERE v.tenant_id=$1 AND a.purdue_level<=1 ORDER BY v.cvss DESC LIMIT 5`, tid)
	if err == nil {
		defer vRows.Close()
		for vRows.Next() {
			var cve, severity, assetName string
			var cvss float64
			if vRows.Scan(&cve, &cvss, &severity, &assetName) == nil {
				exposedVulns = append(exposedVulns, map[string]interface{}{
					"cve_id": cve, "cvss": cvss, "severity": severity, "asset": assetName,
				})
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"risk_assets":           riskAssets,
		"exposed_control_vulns": exposedVulns,
	})
}

// GetOTAnalytics — GET /api/ot/analytics
func GetOTAnalytics(c *gin.Context) {
	createOTICSTables()
	tid := tenantIDFromContext(c)
	type TrendPoint struct {
		Date  string `json:"date"`
		Count int    `json:"count"`
	}
	trend := []TrendPoint{}
	for i := 13; i >= 0; i-- {
		d := time.Now().AddDate(0, 0, -i).Format("2006-01-02")
		var cnt int
		database.DB.QueryRow(`SELECT COUNT(*) FROM ot_alerts WHERE tenant_id=$1 AND DATE(created_at)<=$2`, tid, d).Scan(&cnt)
		trend = append(trend, TrendPoint{Date: d, Count: cnt})
	}
	type plcRow struct {
		Name      string `json:"name"`
		Commands  int    `json:"commands"`
		Writes    int    `json:"writes"`
		Reads     int    `json:"reads"`
		Anomalies int    `json:"anomalies"`
	}
	mostActivePLCs := []plcRow{}
	plcRows, _ := database.DB.Query(`
		SELECT a.name,
			COUNT(*) AS commands,
			COUNT(*) FILTER (WHERE t.operation='write') AS writes,
			COUNT(*) FILTER (WHERE t.operation='read') AS reads,
			COUNT(*) FILTER (WHERE t.is_authorized=false) AS anomalies
		FROM ot_traffic t JOIN ot_assets a ON a.ip=t.dst_ip AND a.tenant_id=t.tenant_id
		WHERE t.tenant_id=$1 AND a.asset_type IN ('plc','rtu')
		GROUP BY a.name ORDER BY commands DESC LIMIT 5`, tid)
	if plcRows != nil {
		defer plcRows.Close()
		for plcRows.Next() {
			var r plcRow
			if plcRows.Scan(&r.Name, &r.Commands, &r.Writes, &r.Reads, &r.Anomalies) == nil {
				mostActivePLCs = append(mostActivePLCs, r)
			}
		}
	}

	type protoRow struct {
		Protocol string `json:"protocol"`
		Percent  int    `json:"percent"`
	}
	protocolDistribution := []protoRow{}
	var totalTraffic int
	database.DB.QueryRow(`SELECT COUNT(*) FROM ot_traffic WHERE tenant_id=$1`, tid).Scan(&totalTraffic)
	if totalTraffic > 0 {
		protoRows, _ := database.DB.Query(`
			SELECT protocol, COUNT(*) FROM ot_traffic WHERE tenant_id=$1
			GROUP BY protocol ORDER BY COUNT(*) DESC LIMIT 10`, tid)
		if protoRows != nil {
			defer protoRows.Close()
			for protoRows.Next() {
				var proto string
				var cnt int
				if protoRows.Scan(&proto, &cnt) == nil {
					protocolDistribution = append(protocolDistribution, protoRow{Protocol: proto, Percent: cnt * 100 / totalTraffic})
				}
			}
		}
	}

	type dayRow struct {
		Day   string `json:"day"`
		Count int    `json:"count"`
	}
	configChanges := []dayRow{}
	for i := 6; i >= 0; i-- {
		d := time.Now().AddDate(0, 0, -i)
		var cnt int
		database.DB.QueryRow(`SELECT COUNT(*) FROM ot_firmware WHERE tenant_id=$1 AND DATE(changed_at)=$2`, tid, d.Format("2006-01-02")).Scan(&cnt)
		configChanges = append(configChanges, dayRow{Day: d.Format("Mon"), Count: cnt})
	}

	c.JSON(http.StatusOK, gin.H{
		"alert_trend":           trend,
		"most_active_plcs":      mostActivePLCs,
		"protocol_distribution": protocolDistribution,
		"config_changes_7d":     configChanges,
	})
}

// PostOTAI — POST /api/ot/ai
func PostOTAI(c *gin.Context) {
	createOTICSTables()
	var body struct {
		Mode    string `json:"mode"`
		Content string `json:"content"`
		Alert   string `json:"alert"`
	}
	c.ShouldBindJSON(&body)
	var prompt string
	switch body.Mode {
	case "alert":
		prompt = fmt.Sprintf(`You are an OT/ICS cybersecurity expert with deep knowledge of industrial control systems, SCADA, PLCs, and OT-specific threats.
Analyze this OT security alert: %s
Provide compact JSON: {"verdict":"confirmed_threat|likely_benign|needs_investigation","confidence":90,"threat_technique":"technique name","mitre_ics_technique":"TXXXX","explanation":"2-3 sentences explaining significance in OT context","ot_impact":"potential physical/operational impact","recommended_actions":["action"],"safety_note":"important safety consideration"}`, body.Alert)
	default:
		prompt = fmt.Sprintf(`You are an OT/ICS cybersecurity expert. Answer this question about industrial control system security: %s
Provide compact JSON: {"answer":"concise expert answer","confidence":88,"ot_context":"why this matters in OT","recommended_actions":["action"],"safety_note":"any safety considerations"}`, body.Content)
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

// PostOTResponse — POST /api/ot/response
func PostOTResponse(c *gin.Context) {
	createOTICSTables()
	createAQTables()
	tid := tenantIDFromContext(c)
	var body struct {
		Action       string `json:"action"`
		Target       string `json:"target"`
		Reason       string `json:"reason"`
		ResponseMode string `json:"response_mode"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Action == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "action required"})
		return
	}
	safetyNote := "All actions that may affect physical operations require explicit operator approval before execution."

	switch body.Action {
	case "create_incident":
		var incidentID int
		if err := database.DB.QueryRow(`
			INSERT INTO ot_incidents (tenant_id, title, description, severity, status, affected_assets, response_mode)
			VALUES ($1,$2,$3,'high','open',$4,$5) RETURNING id`,
			tid, "OT Security Escalation: "+body.Target, body.Reason, body.Target, body.ResponseMode,
		).Scan(&incidentID); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true, "action": body.Action, "target": body.Target, "message": fmt.Sprintf("OT incident #%d created", incidentID), "safety_note": safetyNote})
	case "block_network_path", "escalate_emergency":
		requester := usernameFromContext(c)
		isEmergency := body.Action == "escalate_emergency"
		severity := "high"
		policy := "manager_approval"
		if isEmergency {
			severity = "critical"
			policy = "emergency"
		}
		approvalID := fmt.Sprintf("AQ-%d-%06d", time.Now().Year(), time.Now().UnixNano()%1000000)
		var reqID int
		database.DB.QueryRow(`
			INSERT INTO aq_requests (tenant_id, approval_id, request_type, action_category, severity, description, requested_action, target_asset, requester, is_emergency, policy, risk_level, due_at)
			VALUES ($1,$2,'ot_response','ot_network',$3,$4,$5,$6,$7,$8,$9,$3,NOW()+INTERVAL '30 minutes') RETURNING id`,
			tid, approvalID, severity, body.Reason, body.Action, body.Target, requester, isEmergency, policy,
		).Scan(&reqID)
		database.DB.Exec(`INSERT INTO aq_audit (tenant_id,request_id,approval_id,actor,action,details) VALUES($1,$2,$3,$4,'created','Submitted from OT/ICS response panel')`, tid, reqID, approvalID, requester)
		msg := "Network path block request submitted for operator approval"
		if isEmergency {
			msg = "Emergency escalation submitted to the approval queue"
		}
		c.JSON(http.StatusOK, gin.H{
			"ok": true, "action": body.Action, "target": body.Target, "message": msg,
			"requires_approval": true, "approval_id": approvalID, "safety_note": safetyNote,
		})
	case "notify_operators", "capture_traffic":
		c.JSON(http.StatusNotImplemented, gin.H{"error": "no real operator-alarm/PCAP-capture integration configured for this action"})
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "unknown action"})
	}
}

// PostOTReport — POST /api/ot/report
func PostOTReport(c *gin.Context) {
	createOTICSTables()
	tid := tenantIDFromContext(c)
	var body struct {
		ReportType string `json:"report_type"`
	}
	c.ShouldBindJSON(&body)
	var totalAssets, criticalAlerts, openVulns, activeIncidents int
	database.DB.QueryRow(`SELECT COUNT(*) FROM ot_assets WHERE tenant_id=$1`, tid).Scan(&totalAssets)
	database.DB.QueryRow(`SELECT COUNT(*) FROM ot_alerts WHERE tenant_id=$1 AND severity='critical' AND status='open'`, tid).Scan(&criticalAlerts)
	database.DB.QueryRow(`SELECT COUNT(*) FROM ot_vulnerabilities WHERE tenant_id=$1`, tid).Scan(&openVulns)
	database.DB.QueryRow(`SELECT COUNT(*) FROM ot_incidents WHERE tenant_id=$1 AND status='open'`, tid).Scan(&activeIncidents)
	prompt := fmt.Sprintf(`Generate an executive OT/ICS security report for an industrial environment.
Stats: %d OT assets, %d critical alerts, %d open vulnerabilities, %d active incidents.
Report type: %s
Provide compact JSON: {"title":"...","executive_summary":"3 sentences","key_findings":["finding"],"risk_breakdown":{"critical":0,"high":0,"medium":0},"ot_specific_risks":["risk"],"top_recommendations":[{"priority":1,"action":"action","estimated_effort":"time","safety_note":"safety consideration"}],"metrics":{"total_assets":%d,"critical_alerts":%d,"open_vulnerabilities":%d,"active_incidents":%d}}`,
		totalAssets, criticalAlerts, openVulns, activeIncidents, body.ReportType,
		totalAssets, criticalAlerts, openVulns, activeIncidents)
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
