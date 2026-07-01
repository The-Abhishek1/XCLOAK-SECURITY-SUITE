package services

// Vulnerability scanner import — ingests Nessus (.nessus), Qualys Asset XML,
// and Tenable.sc XML reports into the vulnerabilities priority queue.
//
// Design:
//   • Each format has its own XML parser function that produces []ScannerFinding.
//   • A common import function resolves hosts → agents, upserts findings, and
//     writes a vuln_scan_imports tracking record.
//   • Agent matching: exact IP match on agents.last_ip_address → hostname ILIKE.
//     Unmatched hosts still import with agent_id=NULL (network-visible findings).
//   • Deduplication: UNIQUE INDEX on (tenant_id, plugin_id, COALESCE(port,0),
//     COALESCE(cve_id,'')) WHERE source IN ('nessus','qualys','tenable').
//     On conflict the existing row's severity and cvss_score are updated so
//     rescans reflect the latest assessment.
//   • After every import, RefreshVulnPriorityScores runs for the tenant so
//     new findings immediately appear ranked in the priority queue.
//
// Severity mappings:
//   Nessus severity field (integer 0-4):
//     0 → skip (informational / passed checks)
//     1 → "low", 2 → "medium", 3 → "high", 4 → "critical"
//   Qualys severity field (integer 1-5):
//     1,2 → "low", 3 → "medium", 4 → "high", 5 → "critical"
//   Tenable.sc severity field (string: "info","low","medium","high","critical"):
//     "info" → skip, others map directly.
//
// MITRE coverage: the findings surface in the existing vuln priority queue
// (T1190 — Exploit Public-Facing Application).

import (
	"database/sql"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"strconv"
	"strings"

	"xcloak-ngfw/database"
)

// ── Common finding struct ─────────────────────────────────────────────────────

// ScannerFinding is the normalised representation of one scanner-reported vuln.
type ScannerFinding struct {
	// Host identification (resolved to agent_id in importFindings)
	HostIP       string
	Hostname     string

	// Finding identity
	PluginID     string
	CVE          string // may be empty if no public CVE assigned
	Name         string
	Description  string
	Remediation  string

	// Risk metadata
	CVSSv3       float64
	CVSSv2       float64
	Severity     string // normalised: "low","medium","high","critical"
	Port         int    // 0 = not port-specific
	Protocol     string // "tcp","udp", or ""

	// Source tag for dedup index
	Source       string // "nessus","qualys","tenable"
}

// ── Import result ─────────────────────────────────────────────────────────────

type ImportResult struct {
	Scanner    string
	HostCount  int
	VulnCount  int
	NewCount   int
}

// ── Top-level import function ──────────────────────────────────────────────────

// ImportScannerXML detects the XML format, parses findings, upserts them, and
// writes a vuln_scan_imports tracking record.
// filename is used only for the tracking record; data is read from r.
func ImportScannerXML(tenantID, importedByUserID int, filename string, r io.Reader) (*ImportResult, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}

	scanner, findings, err := detectAndParse(data)
	if err != nil {
		return nil, err
	}

	result, importErr := importFindings(tenantID, scanner, findings)

	// Always write the tracking record (even on partial failure).
	errMsg := ""
	if importErr != nil {
		errMsg = importErr.Error()
	}
	database.DB.Exec(`
		INSERT INTO vuln_scan_imports
			(tenant_id, filename, scanner, host_count, vuln_count, new_count, imported_by, error_msg)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
	`, tenantID, filename, scanner,
		result.HostCount, result.VulnCount, result.NewCount,
		nullableInt(importedByUserID), errMsg)

	if importErr != nil {
		return result, importErr
	}

	// Re-score so new findings appear ranked immediately.
	go RefreshVulnPriorityScores(tenantID)

	log.Printf("[VulnImport] %s: hosts=%d vulns=%d new=%d tenant=%d",
		scanner, result.HostCount, result.VulnCount, result.NewCount, tenantID)
	return result, nil
}

// ListScanImports returns import history for one tenant, newest first.
func ListScanImports(tenantID, limit, offset int) ([]map[string]interface{}, error) {
	rows, err := database.RDB().Query(`
		SELECT i.id, i.filename, i.scanner, i.host_count, i.vuln_count, i.new_count,
		       i.imported_at, i.error_msg,
		       COALESCE(u.email,'') AS imported_by
		FROM vuln_scan_imports i
		LEFT JOIN users u ON u.id = i.imported_by
		WHERE i.tenant_id = $1
		ORDER BY i.imported_at DESC
		LIMIT $2 OFFSET $3
	`, tenantID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []map[string]interface{}
	for rows.Next() {
		var (
			id, hostCount, vulnCount, newCount int
			filename, scanner, importedAt, errMsg, importedBy string
		)
		if err := rows.Scan(&id, &filename, &scanner, &hostCount, &vulnCount, &newCount,
			&importedAt, &errMsg, &importedBy); err != nil {
			continue
		}
		out = append(out, map[string]interface{}{
			"id":          id,
			"filename":    filename,
			"scanner":     scanner,
			"host_count":  hostCount,
			"vuln_count":  vulnCount,
			"new_count":   newCount,
			"imported_at": importedAt,
			"error_msg":   errMsg,
			"imported_by": importedBy,
		})
	}
	if out == nil {
		out = []map[string]interface{}{}
	}
	return out, nil
}

// ── Format detection and dispatch ─────────────────────────────────────────────

func detectAndParse(data []byte) (string, []ScannerFinding, error) {
	root := strings.ToLower(string(data[:minInt(512, len(data))]))
	switch {
	case strings.Contains(root, "nessusclientdata_v2"):
		f, err := parseNessus(data)
		return "nessus", f, err
	case strings.Contains(root, "<scan>") && strings.Contains(root, "<host>"):
		f, err := parseQualys(data)
		return "qualys", f, err
	case strings.Contains(root, "<tenablesc") || strings.Contains(root, "<listreport"):
		f, err := parseTenable(data)
		return "tenable", f, err
	default:
		return "", nil, fmt.Errorf("unrecognised scanner XML format")
	}
}

// ── Nessus parser ─────────────────────────────────────────────────────────────

// Nessus XML structure used here:
//
//	<NessusClientData_v2>
//	  <Report>
//	    <ReportHost name="...">
//	      <HostProperties><tag name="host-ip">...</tag></HostProperties>
//	      <ReportItem port="443" protocol="tcp" severity="3" pluginID="12345"
//	                  pluginName="...">
//	        <cve>CVE-2021-1234</cve>
//	        <cvss3_base_score>9.8</cvss3_base_score>
//	        <cvss_base_score>7.5</cvss_base_score>
//	        <description>...</description>
//	        <solution>...</solution>
//	      </ReportItem>
//	    </ReportHost>
//	  </Report>
//	</NessusClientData_v2>

type nessusRoot struct {
	XMLName xml.Name      `xml:"NessusClientData_v2"`
	Reports []nessusReport `xml:"Report"`
}
type nessusReport struct {
	Hosts []nessusHost `xml:"ReportHost"`
}
type nessusHost struct {
	Name       string            `xml:"name,attr"`
	Properties []nessusTag       `xml:"HostProperties>tag"`
	Items      []nessusItem      `xml:"ReportItem"`
}
type nessusTag struct {
	Name  string `xml:"name,attr"`
	Value string `xml:",chardata"`
}
type nessusItem struct {
	Port       int    `xml:"port,attr"`
	Protocol   string `xml:"protocol,attr"`
	SeverityN  int    `xml:"severity,attr"`
	PluginID   string `xml:"pluginID,attr"`
	PluginName string `xml:"pluginName,attr"`
	CVE        string `xml:"cve"`
	CVSSv3     string `xml:"cvss3_base_score"`
	CVSSv2     string `xml:"cvss_base_score"`
	Desc       string `xml:"description"`
	Solution   string `xml:"solution"`
}

func parseNessus(data []byte) ([]ScannerFinding, error) {
	var root nessusRoot
	if err := xml.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("nessus parse: %w", err)
	}

	var findings []ScannerFinding
	for _, report := range root.Reports {
		for _, host := range report.Hosts {
			ip, hostname := nessusHostIP(host)
			for _, item := range host.Items {
				if item.SeverityN == 0 {
					continue // informational — skip
				}
				sev := nessusSeverity(item.SeverityN)
				cvssv3, _ := strconv.ParseFloat(strings.TrimSpace(item.CVSSv3), 64)
				cvssv2, _ := strconv.ParseFloat(strings.TrimSpace(item.CVSSv2), 64)
				findings = append(findings, ScannerFinding{
					HostIP:      ip,
					Hostname:    hostname,
					PluginID:    item.PluginID,
					CVE:         strings.TrimSpace(item.CVE),
					Name:        item.PluginName,
					Description: strings.TrimSpace(item.Desc),
					Remediation: strings.TrimSpace(item.Solution),
					CVSSv3:      cvssv3,
					CVSSv2:      cvssv2,
					Severity:    sev,
					Port:        item.Port,
					Protocol:    strings.ToLower(item.Protocol),
					Source:      "nessus",
				})
			}
		}
	}
	return findings, nil
}

func nessusHostIP(host nessusHost) (ip, hostname string) {
	for _, tag := range host.Properties {
		switch tag.Name {
		case "host-ip":
			ip = strings.TrimSpace(tag.Value)
		case "hostname", "host-fqdn":
			hostname = strings.TrimSpace(tag.Value)
		}
	}
	if ip == "" {
		ip = host.Name
	}
	return
}

func nessusSeverity(n int) string {
	switch n {
	case 1:
		return "low"
	case 2:
		return "medium"
	case 3:
		return "high"
	case 4:
		return "critical"
	default:
		return "low"
	}
}

// ── Qualys parser ─────────────────────────────────────────────────────────────

// Qualys Asset XML Report structure:
//
//	<SCAN>
//	  <HOST>
//	    <IP>192.168.1.1</IP>
//	    <DNS>server01</DNS>
//	    <VULN_LIST>
//	      <VULN>
//	        <QID>38173</QID>
//	        <TITLE>OpenSSL Vulnerability</TITLE>
//	        <SEVERITY>4</SEVERITY>   <!-- 1-5 -->
//	        <CVE_LIST><CVE><ID>CVE-2020-1234</ID></CVE></CVE_LIST>
//	        <CVSS_BASE>7.5</CVSS_BASE>
//	        <CVSS3_BASE>9.8</CVSS3_BASE>
//	        <SOLUTION>...</SOLUTION>
//	        <DIAGNOSIS>...</DIAGNOSIS>
//	        <PORT>443</PORT>
//	        <PROTOCOL>TCP</PROTOCOL>
//	      </VULN>
//	    </VULN_LIST>
//	  </HOST>
//	</SCAN>

type qualysScan struct {
	XMLName xml.Name     `xml:"SCAN"`
	Hosts   []qualysHost `xml:"HOST"`
}
type qualysHost struct {
	IP    string       `xml:"IP"`
	DNS   string       `xml:"DNS"`
	Vulns []qualysVuln `xml:"VULN_LIST>VULN"`
}
type qualysVuln struct {
	QID       string        `xml:"QID"`
	Title     string        `xml:"TITLE"`
	SeverityN int           `xml:"SEVERITY"`
	CVEList   []qualysCVE   `xml:"CVE_LIST>CVE"`
	CVSSv2    string        `xml:"CVSS_BASE"`
	CVSSv3    string        `xml:"CVSS3_BASE"`
	Diagnosis string        `xml:"DIAGNOSIS"`
	Solution  string        `xml:"SOLUTION"`
	Port      int           `xml:"PORT"`
	Protocol  string        `xml:"PROTOCOL"`
}
type qualysCVE struct {
	ID string `xml:"ID"`
}

func parseQualys(data []byte) ([]ScannerFinding, error) {
	var root qualysScan
	if err := xml.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("qualys parse: %w", err)
	}

	var findings []ScannerFinding
	for _, host := range root.Hosts {
		for _, vuln := range host.Vulns {
			sev := qualysSeverity(vuln.SeverityN)
			if sev == "" {
				continue // severity 0 / informational
			}
			cvssv3, _ := strconv.ParseFloat(strings.TrimSpace(vuln.CVSSv3), 64)
			cvssv2, _ := strconv.ParseFloat(strings.TrimSpace(vuln.CVSSv2), 64)
			cve := ""
			if len(vuln.CVEList) > 0 {
				cve = strings.TrimSpace(vuln.CVEList[0].ID)
			}
			findings = append(findings, ScannerFinding{
				HostIP:      strings.TrimSpace(host.IP),
				Hostname:    strings.TrimSpace(host.DNS),
				PluginID:    "Q" + vuln.QID, // prefix to namespace from Nessus IDs
				CVE:         cve,
				Name:        strings.TrimSpace(vuln.Title),
				Description: strings.TrimSpace(vuln.Diagnosis),
				Remediation: strings.TrimSpace(vuln.Solution),
				CVSSv3:      cvssv3,
				CVSSv2:      cvssv2,
				Severity:    sev,
				Port:        vuln.Port,
				Protocol:    strings.ToLower(strings.TrimSpace(vuln.Protocol)),
				Source:      "qualys",
			})
		}
	}
	return findings, nil
}

func qualysSeverity(n int) string {
	switch {
	case n <= 0:
		return ""
	case n <= 2:
		return "low"
	case n == 3:
		return "medium"
	case n == 4:
		return "high"
	default:
		return "critical"
	}
}

// ── Tenable.sc parser ─────────────────────────────────────────────────────────

// Tenable.sc (SecurityCenter) XML — cumulative report export:
//
//	<tenableSC>
//	  <reportDefID>1</reportDefID>
//	  <scanResult>
//	    <ipList>
//	      <ip value="192.168.1.1" dnsName="server01">
//	        <pluginList>
//	          <plugin id="12345" pluginName="..." severity="high" protocol="tcp" port="443">
//	            <cveList><cve>CVE-2021-1234</cve></cveList>
//	            <cvssV3BaseScore>9.8</cvssV3BaseScore>
//	            <cvssV2BaseScore>7.5</cvssV2BaseScore>
//	            <description>...</description>
//	            <solution>...</solution>
//	          </plugin>
//	        </pluginList>
//	      </ip>
//	    </ipList>
//	  </scanResult>
//	</tenableSC>

type tenableRoot struct {
	XMLName xml.Name         `xml:"tenableSC"`
	Results []tenableResult  `xml:"scanResult"`
}
type tenableResult struct {
	IPs []tenableIP `xml:"ipList>ip"`
}
type tenableIP struct {
	Value   string          `xml:"value,attr"`
	DNS     string          `xml:"dnsName,attr"`
	Plugins []tenablePlugin `xml:"pluginList>plugin"`
}
type tenablePlugin struct {
	ID       string       `xml:"id,attr"`
	Name     string       `xml:"pluginName,attr"`
	Severity string       `xml:"severity,attr"`
	Protocol string       `xml:"protocol,attr"`
	Port     int          `xml:"port,attr"`
	CVEs     []string     `xml:"cveList>cve"`
	CVSSv3   string       `xml:"cvssV3BaseScore"`
	CVSSv2   string       `xml:"cvssV2BaseScore"`
	Desc     string       `xml:"description"`
	Solution string       `xml:"solution"`
}

func parseTenable(data []byte) ([]ScannerFinding, error) {
	var root tenableRoot
	if err := xml.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("tenable parse: %w", err)
	}

	var findings []ScannerFinding
	for _, result := range root.Results {
		for _, ip := range result.IPs {
			for _, plugin := range ip.Plugins {
				sev := tenableSeverity(plugin.Severity)
				if sev == "" {
					continue // "info" — skip
				}
				cvssv3, _ := strconv.ParseFloat(strings.TrimSpace(plugin.CVSSv3), 64)
				cvssv2, _ := strconv.ParseFloat(strings.TrimSpace(plugin.CVSSv2), 64)
				cve := ""
				if len(plugin.CVEs) > 0 {
					cve = strings.TrimSpace(plugin.CVEs[0])
				}
				findings = append(findings, ScannerFinding{
					HostIP:      strings.TrimSpace(ip.Value),
					Hostname:    strings.TrimSpace(ip.DNS),
					PluginID:    "T" + plugin.ID,
					CVE:         cve,
					Name:        plugin.Name,
					Description: strings.TrimSpace(plugin.Desc),
					Remediation: strings.TrimSpace(plugin.Solution),
					CVSSv3:      cvssv3,
					CVSSv2:      cvssv2,
					Severity:    sev,
					Port:        plugin.Port,
					Protocol:    strings.ToLower(strings.TrimSpace(plugin.Protocol)),
					Source:      "tenable",
				})
			}
		}
	}
	return findings, nil
}

func tenableSeverity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "low":
		return "low"
	case "medium":
		return "medium"
	case "high":
		return "high"
	case "critical":
		return "critical"
	default:
		return "" // "info" and anything else → skip
	}
}

// ── Database upsert ───────────────────────────────────────────────────────────

func importFindings(tenantID int, scanner string, findings []ScannerFinding) (*ImportResult, error) {
	result := &ImportResult{Scanner: scanner}

	// Build a set of distinct hosts for the count.
	hostSet := make(map[string]bool)
	for _, f := range findings {
		hostSet[f.HostIP] = true
	}
	result.HostCount = len(hostSet)
	result.VulnCount = len(findings)

	// Cache agent lookups for this import.
	agentCache := make(map[string]sql.NullInt64) // ip → agent_id

	for _, f := range findings {
		agentID := resolveAgent(tenantID, f.HostIP, f.Hostname, agentCache)

		cvss := f.CVSSv3
		if cvss == 0 {
			cvss = f.CVSSv2
		}
		cveParam := sqlNullString(f.CVE)
		portParam := sqlNullInt(f.Port)
		protoParam := sqlNullString(f.Protocol)

		var inserted bool
		err := database.DB.QueryRow(`
			INSERT INTO vulnerabilities
				(tenant_id, agent_id, cve_id, plugin_id, name, description, remediation,
				 severity, cvss_score, port, protocol, source, patch_status, detected_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'open',NOW())
			ON CONFLICT (tenant_id, plugin_id, COALESCE(port,0), COALESCE(cve_id,''))
			WHERE source IN ('nessus','qualys','tenable')
			DO UPDATE SET
				severity    = EXCLUDED.severity,
				cvss_score  = EXCLUDED.cvss_score,
				agent_id    = COALESCE(EXCLUDED.agent_id, vulnerabilities.agent_id),
				detected_at = NOW()
			RETURNING (xmax = 0)
		`, tenantID, agentID, cveParam, f.PluginID, f.Name, f.Description, f.Remediation,
			f.Severity, cvss, portParam, protoParam, scanner,
		).Scan(&inserted)

		if err != nil {
			log.Printf("[VulnImport] upsert error plugin=%s cve=%s: %v", f.PluginID, f.CVE, err)
			continue
		}
		if inserted {
			result.NewCount++
		}
	}
	return result, nil
}

// resolveAgent looks up the agent_id for a host, caching results.
// Returns a sql.NullInt64 (null if no matching agent found).
func resolveAgent(tenantID int, ip, hostname string, cache map[string]sql.NullInt64) sql.NullInt64 {
	cacheKey := ip + "|" + hostname
	if v, ok := cache[cacheKey]; ok {
		return v
	}

	var agentID sql.NullInt64

	// 1. Exact IP match on agents.last_ip_address
	if ip != "" {
		database.DB.QueryRow(`
			SELECT id FROM agents
			WHERE tenant_id=$1 AND last_ip_address=$2 AND status != 'offline'
			LIMIT 1
		`, tenantID, ip).Scan(&agentID)
	}

	// 2. Hostname ILIKE match
	if !agentID.Valid && hostname != "" {
		database.DB.QueryRow(`
			SELECT id FROM agents
			WHERE tenant_id=$1 AND LOWER(hostname)=LOWER($2)
			LIMIT 1
		`, tenantID, hostname).Scan(&agentID)
	}

	cache[cacheKey] = agentID
	return agentID
}

// ── SQL helpers ───────────────────────────────────────────────────────────────

func sqlNullString(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

func sqlNullInt(n int) interface{} {
	if n == 0 {
		return nil
	}
	return n
}

func nullableInt(n int) interface{} {
	if n == 0 {
		return nil
	}
	return n
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
