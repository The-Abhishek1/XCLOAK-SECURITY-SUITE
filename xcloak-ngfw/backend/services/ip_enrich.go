package services

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"sort"
	"sync"
	"time"

	"xcloak-ngfw/database"
)

// ── Port info ─────────────────────────────────────────────────────────────────

type PortInfo struct {
	Service     string `json:"service"`
	Sensitivity string `json:"sensitivity"` // safe | neutral | sensitive | critical
	Note        string `json:"note"`
}

// GetPortInfo returns metadata for a port number string. Returns nil for unknown ports.
func GetPortInfo(port string) *PortInfo {
	if p, ok := portInfoMap[port]; ok {
		return &p
	}
	return nil
}

var portInfoMap = map[string]PortInfo{
	"20":    {Service: "FTP Data", Sensitivity: "critical", Note: "Cleartext file transfer data channel"},
	"21":    {Service: "FTP", Sensitivity: "critical", Note: "Cleartext auth — brute-forced at scale"},
	"22":    {Service: "SSH", Sensitivity: "sensitive", Note: "Encrypted admin shell — very high brute-force volume"},
	"23":    {Service: "Telnet", Sensitivity: "critical", Note: "Cleartext protocol banned by PCI-DSS & HIPAA"},
	"25":    {Service: "SMTP", Sensitivity: "sensitive", Note: "Mail relay — spam pivot if open relay"},
	"53":    {Service: "DNS", Sensitivity: "neutral", Note: "Name resolution"},
	"67":    {Service: "DHCP", Sensitivity: "neutral", Note: "IP assignment (server)"},
	"68":    {Service: "DHCP", Sensitivity: "neutral", Note: "IP assignment (client)"},
	"80":    {Service: "HTTP", Sensitivity: "neutral", Note: "Cleartext web — credentials visible on wire"},
	"110":   {Service: "POP3", Sensitivity: "sensitive", Note: "Cleartext email retrieval"},
	"123":   {Service: "NTP", Sensitivity: "neutral", Note: "Time synchronisation"},
	"143":   {Service: "IMAP", Sensitivity: "sensitive", Note: "Cleartext email access"},
	"161":   {Service: "SNMP", Sensitivity: "sensitive", Note: "Network mgmt — v1/v2c community strings in cleartext"},
	"179":   {Service: "BGP", Sensitivity: "sensitive", Note: "Border Gateway Protocol — route hijack if misconfigured"},
	"389":   {Service: "LDAP", Sensitivity: "critical", Note: "Directory service — cleartext credential exposure"},
	"443":   {Service: "HTTPS", Sensitivity: "safe", Note: "Encrypted web traffic"},
	"445":   {Service: "SMB", Sensitivity: "critical", Note: "Windows share — EternalBlue / WannaCry / ransomware pivot"},
	"465":   {Service: "SMTPS", Sensitivity: "neutral", Note: "Encrypted mail submission"},
	"512":   {Service: "rexec", Sensitivity: "critical", Note: "Legacy remote execution, no encryption"},
	"513":   {Service: "rlogin", Sensitivity: "critical", Note: "Legacy cleartext remote login"},
	"514":   {Service: "Syslog/rsh", Sensitivity: "critical", Note: "Syslog (UDP) or remote shell — no auth"},
	"587":   {Service: "SMTP TLS", Sensitivity: "neutral", Note: "Encrypted mail submission (STARTTLS)"},
	"636":   {Service: "LDAPS", Sensitivity: "sensitive", Note: "Encrypted directory — still a high-value target"},
	"993":   {Service: "IMAPS", Sensitivity: "neutral", Note: "Encrypted email (IMAP)"},
	"995":   {Service: "POP3S", Sensitivity: "neutral", Note: "Encrypted email (POP3)"},
	"1080":  {Service: "SOCKS", Sensitivity: "critical", Note: "Proxy port — common C2 pivot point"},
	"1433":  {Service: "MSSQL", Sensitivity: "critical", Note: "MS SQL Server — SA accounts brute-forced globally"},
	"1521":  {Service: "Oracle DB", Sensitivity: "critical", Note: "Oracle database — high-value exfil target"},
	"2375":  {Service: "Docker (unauth)", Sensitivity: "critical", Note: "Unauthenticated Docker API — full container host escape"},
	"2376":  {Service: "Docker TLS", Sensitivity: "sensitive", Note: "Docker API with TLS"},
	"3000":  {Service: "Dev HTTP", Sensitivity: "sensitive", Note: "Typically a dev server, should not be internet-exposed"},
	"3128":  {Service: "Squid Proxy", Sensitivity: "sensitive", Note: "HTTP proxy — may expose internal network"},
	"3306":  {Service: "MySQL", Sensitivity: "critical", Note: "Database — should never be reachable from the internet"},
	"3389":  {Service: "RDP", Sensitivity: "critical", Note: "Remote Desktop — #1 ransomware initial-access vector"},
	"4444":  {Service: "Metasploit", Sensitivity: "critical", Note: "Default Metasploit listener — active exploitation indicator"},
	"4445":  {Service: "C2 common", Sensitivity: "critical", Note: "Common C2 framework listener port"},
	"5432":  {Service: "PostgreSQL", Sensitivity: "critical", Note: "Database — should never be reachable from the internet"},
	"5900":  {Service: "VNC", Sensitivity: "critical", Note: "Screen sharing — frequently exploited, often no auth"},
	"5985":  {Service: "WinRM HTTP", Sensitivity: "critical", Note: "Windows remote management — lateral movement vector"},
	"5986":  {Service: "WinRM HTTPS", Sensitivity: "sensitive", Note: "Encrypted Windows remote management"},
	"6379":  {Service: "Redis", Sensitivity: "critical", Note: "In-memory DB — no-auth defaults caused countless breaches"},
	"6443":  {Service: "Kubernetes API", Sensitivity: "critical", Note: "K8s control plane — full cluster takeover if exposed"},
	"7001":  {Service: "WebLogic", Sensitivity: "critical", Note: "Oracle WebLogic — many unpatched RCE CVEs actively exploited"},
	"8080":  {Service: "HTTP Alt", Sensitivity: "neutral", Note: "Common alternative HTTP port"},
	"8443":  {Service: "HTTPS Alt", Sensitivity: "neutral", Note: "Common alternative HTTPS port"},
	"8888":  {Service: "Jupyter", Sensitivity: "critical", Note: "Notebook server — unauthenticated remote code execution"},
	"9200":  {Service: "Elasticsearch", Sensitivity: "critical", Note: "No-auth by default — massive data breach source"},
	"9300":  {Service: "ES Cluster", Sensitivity: "critical", Note: "Elasticsearch internal cluster transport"},
	"10250": {Service: "Kubelet API", Sensitivity: "critical", Note: "K8s node API — exec into pods without RBAC check"},
	"27017": {Service: "MongoDB", Sensitivity: "critical", Note: "Document DB — no-auth defaults caused 10k+ breaches"},
	"27018": {Service: "MongoDB Shard", Sensitivity: "critical", Note: "MongoDB sharding port"},
	"50070": {Service: "HDFS NameNode", Sensitivity: "critical", Note: "Hadoop filesystem — data exfiltration target"},
}

// ── IP Enrichment ─────────────────────────────────────────────────────────────

type IPEnrichment struct {
	IP      string `json:"ip"`
	IsPrivate bool  `json:"is_private"`

	// ip-api.com (free, no key)
	Country     string `json:"country,omitempty"`
	CountryCode string `json:"country_code,omitempty"`
	Region      string `json:"region,omitempty"`
	City        string `json:"city,omitempty"`
	Org         string `json:"org,omitempty"`
	ASN         string `json:"asn,omitempty"`
	IsProxy     bool   `json:"is_proxy"`
	IsHosting   bool   `json:"is_hosting"`

	// Local IOC DB
	IsIOC          bool   `json:"is_ioc"`
	IOCSeverity    string `json:"ioc_severity,omitempty"`
	IOCDescription string `json:"ioc_description,omitempty"`

	// AbuseIPDB (env: ABUSEIPDB_KEY)
	AbuseScore      *int     `json:"abuse_score,omitempty"`
	AbuseReports    *int     `json:"abuse_reports,omitempty"`
	AbuseCategories []string `json:"abuse_categories,omitempty"`

	// VirusTotal (env: VIRUSTOTAL_KEY)
	VTMalicious  *int `json:"vt_malicious,omitempty"`
	VTSuspicious *int `json:"vt_suspicious,omitempty"`
	VTTotal      *int `json:"vt_total,omitempty"`

	// Computed
	ThreatLevel string   `json:"threat_level"` // none | low | medium | high | critical
	ThreatTags  []string `json:"threat_tags"`
	Sources     []string `json:"sources"`
}

type enrichEntry struct {
	data    *IPEnrichment
	expires time.Time
}

var (
	enrichCache    sync.Map
	enrichCacheTTL = 2 * time.Hour
)

func EnrichIP(ip string, tenantID int) (*IPEnrichment, error) {
	cacheKey := fmt.Sprintf("%s:%d", ip, tenantID)
	if v, ok := enrichCache.Load(cacheKey); ok {
		e := v.(enrichEntry)
		if time.Now().Before(e.expires) {
			return e.data, nil
		}
		enrichCache.Delete(cacheKey)
	}

	result := &IPEnrichment{IP: ip, ThreatTags: []string{}, Sources: []string{}}

	parsed := net.ParseIP(ip)
	if parsed != nil && (parsed.IsPrivate() || parsed.IsLoopback() || parsed.IsLinkLocalUnicast()) {
		result.IsPrivate = true
		result.ThreatLevel = "none"
		enrichCache.Store(cacheKey, enrichEntry{data: result, expires: time.Now().Add(enrichCacheTTL)})
		return result, nil
	}

	// 1. Local IOC check (fast DB query, no network)
	if ioc := localIOCLookup(ip, tenantID); ioc != nil {
		result.IsIOC = true
		result.IOCSeverity = ioc.severity
		result.IOCDescription = ioc.description
		result.ThreatTags = append(result.ThreatTags, "IOC match")
		result.Sources = append(result.Sources, "local-ioc")
	}

	// 2. ip-api.com — free geolocation + proxy/hosting detection
	if geo := fetchIPAPI(ip); geo != nil {
		result.Country = geo.Country
		result.CountryCode = geo.CountryCode
		result.Region = geo.RegionName
		result.City = geo.City
		result.Org = geo.Org
		result.ASN = geo.AS
		result.IsProxy = geo.Proxy
		result.IsHosting = geo.Hosting
		result.Sources = append(result.Sources, "ip-api.com")
		if geo.Proxy {
			result.ThreatTags = append(result.ThreatTags, "VPN/Proxy")
		}
		if geo.Hosting {
			result.ThreatTags = append(result.ThreatTags, "Hosting/DC")
		}
	}

	// 3. AbuseIPDB — real-time abuse reports
	if key := os.Getenv("ABUSEIPDB_KEY"); key != "" {
		if abuse := fetchAbuseIPDB(ip, key); abuse != nil {
			result.AbuseScore = &abuse.Score
			result.AbuseReports = &abuse.Reports
			result.AbuseCategories = abuse.Categories
			result.Sources = append(result.Sources, "abuseipdb")
			if abuse.Score >= 25 {
				result.ThreatTags = append(result.ThreatTags, fmt.Sprintf("Abuse %d%%", abuse.Score))
			}
		}
	}

	// 4. VirusTotal — multi-AV reputation
	if key := os.Getenv("VIRUSTOTAL_KEY"); key != "" {
		if vt := fetchVirusTotal(ip, key); vt != nil {
			result.VTMalicious = &vt.Malicious
			result.VTSuspicious = &vt.Suspicious
			result.VTTotal = &vt.Total
			result.Sources = append(result.Sources, "virustotal")
			if vt.Malicious > 0 {
				result.ThreatTags = append(result.ThreatTags, fmt.Sprintf("VT %d/%d malicious", vt.Malicious, vt.Total))
			}
		}
	}

	sort.Strings(result.ThreatTags)
	result.ThreatLevel = computeThreatLevel(result)

	enrichCache.Store(cacheKey, enrichEntry{data: result, expires: time.Now().Add(enrichCacheTTL)})
	return result, nil
}

func computeThreatLevel(r *IPEnrichment) string {
	if r.IsIOC {
		switch r.IOCSeverity {
		case "critical":
			return "critical"
		case "high":
			return "high"
		case "medium":
			return "medium"
		default:
			return "low"
		}
	}
	if r.AbuseScore != nil {
		s := *r.AbuseScore
		switch {
		case s >= 75:
			return "critical"
		case s >= 50:
			return "high"
		case s >= 25:
			return "medium"
		case s >= 5:
			return "low"
		}
	}
	if r.VTMalicious != nil {
		switch {
		case *r.VTMalicious >= 5:
			return "high"
		case *r.VTMalicious >= 1:
			return "medium"
		}
	}
	if r.IsProxy {
		return "low"
	}
	return "none"
}

// ── Local IOC lookup ──────────────────────────────────────────────────────────

type iocRow struct{ severity, description string }

func localIOCLookup(indicator string, tenantID int) *iocRow {
	var sev, desc string
	err := database.DB.QueryRow(
		`SELECT severity, COALESCE(description,'') FROM iocs
		 WHERE tenant_id=$1 AND enabled=true AND type='ip' AND indicator=$2
		 LIMIT 1`,
		tenantID, indicator,
	).Scan(&sev, &desc)
	if err != nil {
		return nil
	}
	return &iocRow{severity: sev, description: desc}
}

// ── ip-api.com ────────────────────────────────────────────────────────────────

type ipAPIResponse struct {
	Status      string  `json:"status"`
	Country     string  `json:"country"`
	CountryCode string  `json:"countryCode"`
	RegionName  string  `json:"regionName"`
	City        string  `json:"city"`
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`
	Org         string  `json:"org"`
	AS          string  `json:"as"`
	Proxy       bool    `json:"proxy"`
	Hosting     bool    `json:"hosting"`
}

func fetchIPAPI(ip string) *ipAPIResponse {
	client := &http.Client{Timeout: 5 * time.Second}
	url := fmt.Sprintf("http://ip-api.com/json/%s?fields=status,country,countryCode,regionName,city,lat,lon,org,as,proxy,hosting", ip)
	resp, err := client.Get(url)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	var out ipAPIResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil
	}
	if out.Status != "success" {
		return nil
	}
	return &out
}

// ── AbuseIPDB ─────────────────────────────────────────────────────────────────

var abuseCategories = map[int]string{
	3: "Fraud Orders", 4: "DDoS Attack", 5: "FTP Brute-Force",
	6: "Ping of Death", 7: "Phishing", 8: "Fraud VoIP", 9: "Open Proxy",
	10: "Web Spam", 11: "Email Spam", 12: "Blog Spam", 13: "VPN IP",
	14: "Port Scan", 15: "Hacking", 16: "SQL Injection", 17: "Spoofing",
	18: "Brute-Force", 19: "Bad Web Bot", 20: "Exploited Host",
	21: "Web App Attack", 22: "SSH Attack", 23: "IoT Targeted",
}

type abuseResult struct {
	Score      int
	Reports    int
	Categories []string
}

func fetchAbuseIPDB(ip, key string) *abuseResult {
	client := &http.Client{Timeout: 8 * time.Second}
	req, err := http.NewRequest("GET",
		fmt.Sprintf("https://api.abuseipdb.com/api/v2/check?ipAddress=%s&maxAgeInDays=90&verbose", ip), nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Key", key)
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil
	}

	var out struct {
		Data struct {
			AbuseConfidenceScore int `json:"abuseConfidenceScore"`
			TotalReports         int `json:"totalReports"`
			Reports              []struct {
				Categories []int `json:"categories"`
			} `json:"reports"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil
	}

	catSet := map[string]bool{}
	for _, rep := range out.Data.Reports {
		for _, c := range rep.Categories {
			if name, ok := abuseCategories[c]; ok {
				catSet[name] = true
			}
		}
	}
	cats := make([]string, 0, len(catSet))
	for c := range catSet {
		cats = append(cats, c)
	}
	sort.Strings(cats)

	return &abuseResult{
		Score:      out.Data.AbuseConfidenceScore,
		Reports:    out.Data.TotalReports,
		Categories: cats,
	}
}

// ── VirusTotal ────────────────────────────────────────────────────────────────

type vtResult struct {
	Malicious  int
	Suspicious int
	Total      int
}

func fetchVirusTotal(ip, key string) *vtResult {
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET",
		fmt.Sprintf("https://www.virustotal.com/api/v3/ip_addresses/%s", ip), nil)
	if err != nil {
		return nil
	}
	req.Header.Set("x-apikey", key)
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil
	}

	var out struct {
		Data struct {
			Attributes struct {
				LastAnalysisStats struct {
					Malicious  int `json:"malicious"`
					Suspicious int `json:"suspicious"`
					Undetected int `json:"undetected"`
					Harmless   int `json:"harmless"`
				} `json:"last_analysis_stats"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil
	}
	s := out.Data.Attributes.LastAnalysisStats
	return &vtResult{
		Malicious:  s.Malicious,
		Suspicious: s.Suspicious,
		Total:      s.Malicious + s.Suspicious + s.Undetected + s.Harmless,
	}
}
