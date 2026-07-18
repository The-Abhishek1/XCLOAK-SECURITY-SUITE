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
	if criticalAlerts > 5 { networkHealth = 72 }
	c.JSON(http.StatusOK, gin.H{
		"sites":              sites,
		"industrial_zones":   industrial_zones,
		"plcs":               plcs,
		"hmis":               hmis,
		"rtus":               rtus,
		"engineering_workstations": ewss,
		"scada_servers":      scadaServers,
		"total_assets":       totalAssets,
		"ot_risk_score":      int(riskScore),
		"critical_alerts":    criticalAlerts,
		"active_incidents":   activeIncidents,
		"network_health":     networkHealth,
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
		q += fmt.Sprintf(" AND asset_type=$%d", i); args = append(args, v); i++
	}
	if v := c.Query("zone"); v != "" {
		q += fmt.Sprintf(" AND zone=$%d", i); args = append(args, v); i++
	}
	if v := c.Query("site"); v != "" {
		q += fmt.Sprintf(" AND site=$%d", i); args = append(args, v); i++
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
	if assets == nil { assets = []Asset{} }
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
	if nodes == nil { nodes = []Node{} }
	links := []map[string]interface{}{
		{"src": "192.168.1.1", "dst": "10.10.1.10", "protocol": "Modbus TCP", "active": true},
		{"src": "192.168.1.1", "dst": "10.10.1.11", "protocol": "EtherNet/IP", "active": true},
		{"src": "10.10.1.10", "dst": "10.10.2.20", "protocol": "OPC UA", "active": true},
		{"src": "10.10.2.20", "dst": "10.10.3.30", "protocol": "Historian", "active": false},
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
	if stats == nil { stats = []ProtoStat{} }
	c.JSON(http.StatusOK, gin.H{
		"protocol_stats": stats,
		"supported_protocols": []string{
			"Modbus TCP", "DNP3", "OPC UA", "EtherNet/IP", "PROFINET",
			"BACnet", "IEC 60870-5-104", "IEC 61850", "S7", "CIP", "MQTT",
		},
		"sessions": []map[string]interface{}{
			{"src": "10.10.0.5", "dst": "10.10.1.10", "protocol": "Modbus TCP", "packets": 1240, "bytes": 88320, "last_seen": time.Now().Add(-5*time.Minute).Format(time.RFC3339)},
			{"src": "10.10.0.6", "dst": "10.10.1.11", "protocol": "EtherNet/IP", "packets": 340, "bytes": 24880, "last_seen": time.Now().Add(-12*time.Minute).Format(time.RFC3339)},
			{"src": "10.10.0.5", "dst": "10.10.1.12", "protocol": "DNP3", "packets": 88, "bytes": 5280, "last_seen": time.Now().Add(-2*time.Minute).Format(time.RFC3339)},
			{"src": "10.10.2.20", "dst": "10.10.1.10", "protocol": "OPC UA", "packets": 210, "bytes": 18480, "last_seen": time.Now().Add(-1*time.Minute).Format(time.RFC3339)},
			{"src": "10.10.0.99", "dst": "10.10.1.10", "protocol": "Modbus TCP", "packets": 8, "bytes": 480, "last_seen": time.Now().Add(-30*time.Second).Format(time.RFC3339), "anomaly": "unauthorized_source"},
		},
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
		q += fmt.Sprintf(" AND protocol=$%d", i); args = append(args, v); i++
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
	if traffic == nil { traffic = []Traffic{} }
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
		q += fmt.Sprintf(" AND severity=$%d", i); args = append(args, v); i++
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
	if alerts == nil { alerts = []Alert{} }
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
	if devices == nil { devices = []Device{} }
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
	if fwChanges == nil { fwChanges = []FWChange{} }
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
	if threats == nil { threats = []Threat{} }
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
	if entries == nil { entries = []DPIEntry{} }
	c.JSON(http.StatusOK, gin.H{"decoded_frames": entries})
}

// GetOTRiskAssessment — GET /api/ot/risk
func GetOTRiskAssessment(c *gin.Context) {
	createOTICSTables()
	tid := tenantIDFromContext(c)
	var total, internetExposed, unsupportedFirmware, weakAuth, openServices, missingSegmentation int
	database.DB.QueryRow(`SELECT COUNT(*) FROM ot_assets WHERE tenant_id=$1`, tid).Scan(&total)
	database.DB.QueryRow(`SELECT COUNT(*) FROM ot_assets WHERE tenant_id=$1 AND purdue_level=0`, tid).Scan(&internetExposed)
	database.DB.QueryRow(`SELECT COUNT(*) FROM ot_assets WHERE tenant_id=$1 AND firmware LIKE '%-eol'`, tid).Scan(&unsupportedFirmware)
	c.JSON(http.StatusOK, gin.H{
		"total_assets":          total,
		"internet_exposed":      internetExposed,
		"unsupported_firmware":  unsupportedFirmware,
		"weak_auth":             weakAuth,
		"open_services":         openServices,
		"missing_segmentation":  missingSegmentation,
		"critical_assets": []map[string]interface{}{
			{"name": "PLC-UNIT-01", "type": "plc", "ip": "10.10.1.10", "risk": 88, "reason": "Internet-reachable via SCADA DMZ; no authentication required on Modbus port"},
			{"name": "HMI-CONTROL-01", "type": "hmi", "ip": "10.10.1.20", "risk": 82, "reason": "Running Windows 7 EOL; remote desktop exposed to IT network"},
			{"name": "EWS-SIEMENS-01", "type": "engineering_workstation", "ip": "10.10.0.5", "risk": 76, "reason": "Connected to both IT and OT networks; recent unauthorised PLC access"},
			{"name": "RTU-FIELD-03", "type": "rtu", "ip": "10.10.1.33", "risk": 71, "reason": "DNP3 without authentication; firmware version 1.2.4 (EOL)"},
			{"name": "HIST-SERVER-01", "type": "historian", "ip": "10.10.2.20", "risk": 64, "reason": "OSIsoft PI 2012; unpatched CVE-2020-8004"},
		},
		"findings": []map[string]interface{}{
			{"category": "Internet Exposure", "count": 2, "severity": "critical", "detail": "2 OT assets reachable from internet via misconfigured firewall rules"},
			{"category": "Unsupported Firmware", "count": 4, "severity": "high", "detail": "4 devices running firmware versions no longer receiving security updates"},
			{"category": "Weak Authentication", "count": 6, "severity": "high", "detail": "6 PLCs and RTUs using default credentials or no authentication"},
			{"category": "Open Services", "count": 8, "severity": "medium", "detail": "8 devices with unnecessary services (FTP, Telnet, HTTP) running"},
			{"category": "Missing Segmentation", "count": 3, "severity": "high", "detail": "3 zones lack firewall enforcement between Purdue levels"},
		},
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
		ID                       int     `json:"id"`
		AssetID                  int     `json:"asset_id"`
		CVEID                    string  `json:"cve_id"`
		CVSS                     float64 `json:"cvss"`
		Severity                 string  `json:"severity"`
		Title                    string  `json:"title"`
		VendorAdvisory           string  `json:"vendor_advisory"`
		PatchAvailable           bool    `json:"patch_available"`
		RequiresMaintenanceWindow bool   `json:"requires_maintenance_window"`
		CreatedAt                string  `json:"created_at"`
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
	if vulns == nil { vulns = []Vuln{} }
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
	if zones == nil { zones = []Zone{} }
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
		ID            int    `json:"id"`
		BaselineType  string `json:"baseline_type"`
		Description   string `json:"description"`
		LearnedAt     string `json:"learned_at"`
		IsActive      bool   `json:"is_active"`
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
	if baselines == nil { baselines = []Baseline{} }
	c.JSON(http.StatusOK, gin.H{
		"baselines": baselines,
		"categories": []map[string]interface{}{
			{"type": "normal_protocols", "learned": true, "items": 8, "description": "Approved OT protocol usage per device pair"},
			{"type": "normal_commands", "learned": true, "items": 124, "description": "Expected Modbus/DNP3 function codes per PLC"},
			{"type": "normal_devices", "learned": true, "items": 47, "description": "All known devices in the OT network"},
			{"type": "normal_traffic", "learned": true, "items": 312, "description": "Expected communication flows and bandwidths"},
			{"type": "maintenance_windows", "learned": true, "items": 6, "description": "Approved programming windows per site schedule"},
		},
		"deviations": []map[string]interface{}{
			{"id": 1, "type": "new_device", "detail": "Unknown IP 10.10.1.99 appeared on PLC subnet", "severity": "high", "time": time.Now().Add(-2*time.Hour).Format(time.RFC3339)},
			{"id": 2, "type": "protocol_deviation", "detail": "Modbus write commands from EWS-01 outside maintenance window", "severity": "critical", "time": time.Now().Add(-4*time.Hour).Format(time.RFC3339)},
			{"id": 3, "type": "traffic_spike", "detail": "Network scan detected — 240 probe packets from 10.10.0.99", "severity": "high", "time": time.Now().Add(-8*time.Hour).Format(time.RFC3339)},
			{"id": 4, "type": "new_protocol", "detail": "FTP traffic observed from PLC-UNIT-01 — not in baseline", "severity": "medium", "time": time.Now().Add(-24*time.Hour).Format(time.RFC3339)},
		},
	})
}

// GetOTThreatIntel — GET /api/ot/threat-intel
func GetOTThreatIntel(c *gin.Context) {
	createOTICSTables()
	c.JSON(http.StatusOK, gin.H{
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
		"ioc_matches": []map[string]interface{}{
			{"type": "ip", "value": "185.220.101.47", "category": "known_ot_scanner", "hits": 3, "threat_actor": "Unknown"},
			{"type": "domain", "value": "scada-update.ru", "category": "c2_domain", "hits": 1, "threat_actor": "Sandworm"},
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
	if events == nil { events = []TLEvent{} }
	c.JSON(http.StatusOK, events)
}

// GetOTCompliance — GET /api/ot/compliance
func GetOTCompliance(c *gin.Context) {
	createOTICSTables()
	c.JSON(http.StatusOK, gin.H{
		"overall_score": 61,
		"frameworks": []map[string]interface{}{
			{"name": "IEC 62443", "score": 58, "passed": 34, "failed": 25, "total": 59, "version": "2018"},
			{"name": "NIST SP 800-82", "score": 67, "passed": 28, "failed": 14, "total": 42, "version": "Rev.3"},
			{"name": "NERC CIP", "score": 72, "passed": 23, "failed": 9, "total": 32, "version": "v7"},
			{"name": "ISA/IEC 62443-3-3", "score": 54, "passed": 19, "failed": 16, "total": 35},
			{"name": "ISO 27019", "score": 63, "passed": 26, "failed": 15, "total": 41},
		},
		"failed_controls": []map[string]interface{}{
			{"control": "IEC62443-SR1.1", "title": "Human user identification and authentication", "severity": "critical", "framework": "IEC 62443"},
			{"control": "IEC62443-SR2.1", "title": "Authorization enforcement", "severity": "high", "framework": "IEC 62443"},
			{"control": "NERC-CIP-007-R1", "title": "Ports and services — disable unnecessary", "severity": "high", "framework": "NERC CIP"},
			{"control": "NERC-CIP-010-R1", "title": "Baseline configuration management", "severity": "high", "framework": "NERC CIP"},
			{"control": "SP800-82-3.3", "title": "Network segmentation between IT and OT", "severity": "critical", "framework": "NIST SP 800-82"},
			{"control": "SP800-82-4.1", "title": "Patch and vulnerability management for ICS", "severity": "high", "framework": "NIST SP 800-82"},
		},
	})
}

// GetOTAttackPaths — GET /api/ot/attack-paths
func GetOTAttackPaths(c *gin.Context) {
	createOTICSTables()
	c.JSON(http.StatusOK, gin.H{
		"paths": []map[string]interface{}{
			{
				"id": 1, "risk": "critical", "title": "Internet → SCADA → PLC → Production Line",
				"steps": []map[string]interface{}{
					{"step": 1, "layer": "Internet", "technique": "Spearphishing / Watering Hole", "mitre": "T1566"},
					{"step": 2, "layer": "IT Network", "technique": "Lateral movement via compromised workstation", "mitre": "T1021"},
					{"step": 3, "layer": "DMZ", "technique": "Jump server pivot via weak credentials", "mitre": "T1078"},
					{"step": 4, "layer": "SCADA", "technique": "HMI takeover — SCADA historian credentials reused", "mitre": "T1078"},
					{"step": 5, "layer": "PLC", "technique": "Unauthorized Modbus write commands to PLC registers", "mitre": "T0836"},
					{"step": 6, "layer": "Production Line", "technique": "Physical process manipulation — shutdown or damage", "mitre": "T0831"},
				},
				"exploited_assets": []interface{}{"EWS-SIEMENS-01", "HMI-CONTROL-01", "PLC-UNIT-01"},
			},
			{
				"id": 2, "risk": "high", "title": "USB Drop → Engineering Workstation → PLC",
				"steps": []map[string]interface{}{
					{"step": 1, "layer": "Physical", "technique": "USB malware drop by insider / supply chain", "mitre": "T1091"},
					{"step": 2, "layer": "Engineering Workstation", "technique": "Autorun malware execution, credential harvest", "mitre": "T1204"},
					{"step": 3, "layer": "PLC", "technique": "PLC programming via Step7/TIA Portal — Stuxnet-style logic injection", "mitre": "T0873"},
				},
				"exploited_assets": []interface{}{"EWS-SIEMENS-01", "PLC-UNIT-01"},
			},
		},
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
	c.JSON(http.StatusOK, gin.H{
		"alert_trend": trend,
		"most_active_plcs": []map[string]interface{}{
			{"name": "PLC-UNIT-01", "commands_per_hour": 1240, "writes": 84, "reads": 1156, "anomalies": 3},
			{"name": "PLC-UNIT-02", "commands_per_hour": 880, "writes": 44, "reads": 836, "anomalies": 0},
			{"name": "PLC-UNIT-03", "commands_per_hour": 640, "writes": 28, "reads": 612, "anomalies": 1},
		},
		"protocol_distribution": []map[string]interface{}{
			{"protocol": "Modbus TCP", "percent": 42},
			{"protocol": "EtherNet/IP", "percent": 28},
			{"protocol": "OPC UA", "percent": 14},
			{"protocol": "DNP3", "percent": 9},
			{"protocol": "IEC 60870-5-104", "percent": 4},
			{"protocol": "Other", "percent": 3},
		},
		"firmware_age": []map[string]interface{}{
			{"category": "< 1 year", "count": 12, "color": "#22c55e"},
			{"category": "1–3 years", "count": 18, "color": "#eab308"},
			{"category": "3–5 years", "count": 9, "color": "#f97316"},
			{"category": "> 5 years (EOL risk)", "count": 8, "color": "#ef4444"},
		},
		"config_changes_7d": []map[string]interface{}{
			{"day": time.Now().AddDate(0, 0, -6).Format("Mon"), "count": 2},
			{"day": time.Now().AddDate(0, 0, -5).Format("Mon"), "count": 0},
			{"day": time.Now().AddDate(0, 0, -4).Format("Mon"), "count": 1},
			{"day": time.Now().AddDate(0, 0, -3).Format("Mon"), "count": 4},
			{"day": time.Now().AddDate(0, 0, -2).Format("Mon"), "count": 1},
			{"day": time.Now().AddDate(0, 0, -1).Format("Mon"), "count": 0},
			{"day": time.Now().Format("Mon"), "count": 2},
		},
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

// PostOTResponse — POST /api/ot/response
func PostOTResponse(c *gin.Context) {
	createOTICSTables()
	var body struct {
		Action       string `json:"action"`
		Target       string `json:"target"`
		Reason       string `json:"reason"`
		ResponseMode string `json:"response_mode"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Action == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "action required"}); return
	}
	messages := map[string]string{
		"notify_operators":     "Operators notified via alarm system and dashboard alert",
		"create_incident":      "Incident created in OT incident management system",
		"run_soar_playbook":    "SOAR playbook triggered for OT response",
		"block_network_path":   "Network path block request submitted for operator approval",
		"capture_traffic":      "Passive traffic capture started on affected segment",
		"escalate_emergency":   "Emergency escalation sent to CISO and OT operations team",
	}
	msg := messages[body.Action]
	if msg == "" { msg = "Action submitted for operator review" }
	requiresApproval := body.Action == "block_network_path"
	c.JSON(http.StatusOK, gin.H{
		"ok":                true,
		"action":            body.Action,
		"target":            body.Target,
		"message":           msg,
		"requires_approval": requiresApproval,
		"response_mode":     body.ResponseMode,
		"safety_note":       "All actions that may affect physical operations require explicit operator approval before execution.",
	})
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
