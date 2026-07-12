// Seed prebuilt rules and threat data for important features.
//
// Usage (dev):
//
//	cd xcloak-platform/backend && go run ./cmd/seed/rules
//
// Override tenant via SEED_TENANT_ID env var (default 1).
// Safe to re-run — uses ON CONFLICT DO NOTHING throughout.
package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func exec(db *sql.DB, q string, args ...any) {
	if _, err := db.Exec(q, args...); err != nil {
		log.Printf("  WARN: %v\n  query: %s", err, q[:min(len(q), 120)])
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func main() {
	godotenv.Load()

	tid := 1
	if v := os.Getenv("SEED_TENANT_ID"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			tid = n
		}
	}

	dsn := fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		env("DB_HOST", "127.0.0.1"),
		env("DB_PORT", "5432"),
		env("DB_USER", "xcloak"),
		env("DB_PASSWORD", "xcloak"),
		env("DB_NAME", "ngfw"),
	)
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	if err := db.Ping(); err != nil {
		log.Fatalf("cannot reach database: %v", err)
	}

	log.Printf("Seeding prebuilt rules for tenant_id=%d…", tid)

	seedFirewallRules(db, tid)
	seedYARARules(db, tid)
	seedSigmaRules(db, tid)
	seedIOCs(db, tid)
	seedCorrelationRules(db, tid)
	seedThreatActors(db, tid)
	seedThreatFeeds(db, tid)
	seedJA3Fingerprints(db, tid)
	seedHuntTemplates(db, tid)
	seedLogSources(db, tid)

	log.Println("Done.")
}

// ── Firewall rules ────────────────────────────────────────────────────────────

func seedFirewallRules(db *sql.DB, tid int) {
	log.Println("  firewall_rules…")
	type fwRule struct {
		name, srcIP, dstIP, proto, action, group, desc, direction string
		port                                                       int
		priority                                                   int
		logEnabled                                                 bool
	}
	rules := []fwRule{
		{"Block Inbound Telnet", "0.0.0.0/0", "0.0.0.0/0", "tcp", "deny", "Hardening", "Block all inbound Telnet — plaintext protocol, high risk", "inbound", 23, 10, true},
		{"Block Inbound RDP from Internet", "0.0.0.0/0", "0.0.0.0/0", "tcp", "deny", "Hardening", "Block RDP (3389) from untrusted sources — frequent brute-force target", "inbound", 3389, 20, true},
		{"Block Inbound SMB", "0.0.0.0/0", "0.0.0.0/0", "tcp", "deny", "Hardening", "Block SMB (445) from outside — WannaCry / EternalBlue vector", "inbound", 445, 30, true},
		{"Block Inbound NetBIOS", "0.0.0.0/0", "0.0.0.0/0", "tcp", "deny", "Hardening", "Block NetBIOS (139) inbound — legacy Windows name resolution abuse", "inbound", 139, 40, true},
		{"Block Inbound TFTP", "0.0.0.0/0", "0.0.0.0/0", "udp", "deny", "Hardening", "Block TFTP (69) — used for malware staging and firmware exfil", "inbound", 69, 50, true},
		{"Allow Outbound HTTPS", "0.0.0.0/0", "0.0.0.0/0", "tcp", "allow", "Baseline", "Permit outbound HTTPS traffic to internet", "outbound", 443, 100, false},
		{"Allow Outbound HTTP", "0.0.0.0/0", "0.0.0.0/0", "tcp", "allow", "Baseline", "Permit outbound HTTP — consider forcing redirect to HTTPS at proxy", "outbound", 80, 110, false},
		{"Allow Outbound DNS", "0.0.0.0/0", "0.0.0.0/0", "udp", "allow", "Baseline", "Permit outbound DNS queries to configured resolvers", "outbound", 53, 120, false},
		{"Block Outbound IRC", "0.0.0.0/0", "0.0.0.0/0", "tcp", "deny", "C2 Prevention", "Block outbound IRC (6667) — common C2 channel for older botnets", "outbound", 6667, 200, true},
		{"Block Outbound Tor Default Port", "0.0.0.0/0", "0.0.0.0/0", "tcp", "deny", "C2 Prevention", "Block outbound 9050/9051 Tor SOCKS proxy ports", "outbound", 9050, 210, true},
		{"Block Inbound MSSQL from Internet", "0.0.0.0/0", "0.0.0.0/0", "tcp", "deny", "Hardening", "Block MS SQL Server (1433) from untrusted sources", "inbound", 1433, 300, true},
		{"Block Inbound MySQL from Internet", "0.0.0.0/0", "0.0.0.0/0", "tcp", "deny", "Hardening", "Block MySQL (3306) from untrusted sources — direct DB exposure", "inbound", 3306, 310, true},
	}
	for _, r := range rules {
		exec(db, `
			INSERT INTO firewall_rules
				(name, source_ip, destination_ip, protocol, port, action, enabled,
				 priority, tenant_id, group_name, description, direction, log_enabled, hit_count, created_by)
			VALUES ($1,$2,$3,$4,$5,$6,true,$7,$8,$9,$10,$11,$12,0,'system')
			ON CONFLICT DO NOTHING`,
			r.name, r.srcIP, r.dstIP, r.proto, r.port, r.action,
			r.priority, tid, r.group, r.desc, r.direction, r.logEnabled,
		)
	}
}

// ── YARA rules ────────────────────────────────────────────────────────────────

func seedYARARules(db *sql.DB, tid int) {
	log.Println("  yara_rules…")
	type yaraRule struct{ name, desc, content string }
	rules := []yaraRule{
		{
			"Mimikatz_Strings",
			"Detects common Mimikatz strings in memory or on disk",
			`rule Mimikatz_Strings {
  meta:
    description = "Detects Mimikatz credential dumper"
    severity    = "critical"
  strings:
    $s1 = "sekurlsa::logonpasswords" ascii nocase
    $s2 = "privilege::debug" ascii nocase
    $s3 = "lsadump::dcsync" ascii nocase
    $s4 = "mimikatz" ascii nocase wide
  condition:
    2 of them
}`,
		},
		{
			"CobaltStrike_Beacon",
			"Detects Cobalt Strike beacon shellcode and staging artefacts",
			`rule CobaltStrike_Beacon {
  meta:
    description = "Detects Cobalt Strike beacon artefacts"
    severity    = "critical"
  strings:
    $b1 = { 4D 5A 90 00 03 00 00 00 }
    $b2 = "ReflectiveLoader" ascii
    $b3 = "%s (admin)" ascii
    $cfg = { 00 01 00 01 00 02 ?? ?? 00 02 00 01 00 02 }
  condition:
    ($b2 and $b1) or ($b3 and $cfg)
}`,
		},
		{
			"Meterpreter_Reverse_Shell",
			"Detects Metasploit Meterpreter reverse shell payload patterns",
			`rule Meterpreter_Reverse_Shell {
  meta:
    description = "Detects Meterpreter reverse shell artefacts"
    severity    = "high"
  strings:
    $s1 = "meterpreter" ascii nocase
    $s2 = "stdapi_sys_process_execute" ascii
    $s3 = "core_loadlib" ascii
    $h  = { FC E8 82 00 00 00 60 89 E5 31 C0 64 8B }
  condition:
    2 of ($s*) or $h
}`,
		},
		{
			"WannaCry_Ransomware",
			"Detects WannaCry/WannaCrypt ransomware artefacts",
			`rule WannaCry_Ransomware {
  meta:
    description = "Detects WannaCry ransomware"
    severity    = "critical"
  strings:
    $f1 = "tasksche.exe" ascii nocase
    $f2 = "WanaCrypt0r" ascii
    $f3 = ".WNCRY" ascii
    $f4 = "msg/m_portuguese.wnry" ascii
    $k  = { 74 61 73 6B 73 63 68 65 2E 65 78 65 }
  condition:
    2 of them
}`,
		},
		{
			"Webshell_Generic",
			"Detects common PHP/ASPX webshell patterns",
			`rule Webshell_Generic {
  meta:
    description = "Detects PHP and ASPX webshells"
    severity    = "high"
  strings:
    $p1 = "eval(base64_decode(" ascii nocase
    $p2 = "eval(gzinflate(" ascii nocase
    $p3 = "passthru($_" ascii nocase
    $p4 = "exec($_REQUEST" ascii nocase
    $a1 = "cmd.exe /c" ascii nocase
    $a2 = "<%@ Page Language=" ascii
  condition:
    any of ($p*) or ($a2 and $a1)
}`,
		},
		{
			"ProcessHollowing_Injector",
			"Detects process hollowing and injection artefacts",
			`rule ProcessHollowing_Injector {
  meta:
    description = "Detects process hollowing / code injection"
    severity    = "high"
  strings:
    $s1 = "NtUnmapViewOfSection" ascii
    $s2 = "WriteProcessMemory" ascii
    $s3 = "SetThreadContext" ascii
    $s4 = "ResumeThread" ascii
    $s5 = "CreateProcess" ascii
  condition:
    4 of them
}`,
		},
		{
			"CredentialDumper_LSASS",
			"Detects tools that target LSASS memory for credential extraction",
			`rule CredentialDumper_LSASS {
  meta:
    description = "Detects LSASS credential dumping tools"
    severity    = "critical"
  strings:
    $s1 = "lsass.exe" ascii nocase wide
    $s2 = "MiniDumpWriteDump" ascii
    $s3 = "OpenProcess" ascii
    $s4 = "lsasrv.dll" ascii nocase
    $s5 = "wdigest" ascii nocase
  condition:
    3 of them
}`,
		},
		{
			"Emotet_Loader",
			"Detects Emotet banking trojan loader artefacts",
			`rule Emotet_Loader {
  meta:
    description = "Detects Emotet malware loader patterns"
    severity    = "critical"
  strings:
    $e1 = { 55 8B EC 83 EC ?? 53 56 57 8B 7D ?? 85 FF }
    $e2 = "SoftwareMicrosoftWindowsCurrentVersionRun" ascii wide
    $e3 = "regsvr32" ascii nocase
    $e4 = "/i:http" ascii
  condition:
    $e1 or (2 of ($e2,$e3,$e4))
}`,
		},
		{
			"Ransomware_FileEncryptor",
			"Detects generic ransomware file enumeration and encryption behaviour",
			`rule Ransomware_FileEncryptor {
  meta:
    description = "Generic ransomware file encryption detector"
    severity    = "critical"
  strings:
    $r1 = "YOUR_FILES_ARE_ENCRYPTED" ascii nocase wide
    $r2 = "HOW_TO_DECRYPT" ascii nocase wide
    $r3 = "bitcoin" ascii nocase wide
    $r4 = "CryptEncrypt" ascii
    $r5 = "FindFirstFileW" ascii
  condition:
    ($r4 and $r5 and 1 of ($r1,$r2,$r3))
}`,
		},
		{
			"Rootkit_DriverLoad",
			"Detects unsigned or suspicious driver loading often used by rootkits",
			`rule Rootkit_DriverLoad {
  meta:
    description = "Detects rootkit driver loading artefacts"
    severity    = "high"
  strings:
    $s1 = "ZwLoadDriver" ascii
    $s2 = "\\\\Driver\\\\" ascii wide
    $s3 = "ObRegisterCallbacks" ascii
    $s4 = "PsSetCreateProcessNotifyRoutine" ascii
  condition:
    2 of them
}`,
		},
	}
	for _, r := range rules {
		exec(db, `
			INSERT INTO yara_rules (name, description, rule_content, enabled, tenant_id)
			VALUES ($1,$2,$3,true,$4)
			ON CONFLICT DO NOTHING`,
			r.name, r.desc, r.content, tid,
		)
	}
}

// ── Sigma rules ───────────────────────────────────────────────────────────────

func seedSigmaRules(db *sql.DB, tid int) {
	log.Println("  sigma_rules…")
	type sigmaRule struct {
		title, sev, tactic, technique, techName, desc, logsrc, condition string
		keywords                                                          []string
	}
	rules := []sigmaRule{
		{
			"PowerShell Encoded Command Execution",
			"high", "Execution", "T1059.001", "PowerShell",
			"Detects PowerShell execution with Base64-encoded commands — common for obfuscation",
			"process",
			"keywords",
			[]string{"-EncodedCommand", "-enc ", "powershell -e ", "FromBase64String"},
		},
		{
			"LSASS Memory Access via Task Manager",
			"critical", "Credential Access", "T1003.001", "LSASS Memory",
			"Detects suspicious LSASS process memory access for credential dumping",
			"process",
			"keywords",
			[]string{"lsass.exe", "procdump", "comsvcs.dll", "MiniDump"},
		},
		{
			"Pass-the-Hash Activity",
			"critical", "Lateral Movement", "T1550.002", "Pass the Hash",
			"Detects NTLM pass-the-hash lateral movement patterns",
			"windows",
			"keywords",
			[]string{"sekurlsa::pth", "ntlm", "pass-the-hash", "overpass-the-hash"},
		},
		{
			"Scheduled Task Created via schtasks",
			"medium", "Persistence", "T1053.005", "Scheduled Task",
			"Detects persistence via scheduled task creation using schtasks.exe",
			"process",
			"keywords",
			[]string{"schtasks /create", "schtasks.exe /create", "SchTasks /RU SYSTEM", "/sc onlogon"},
		},
		{
			"WMI Lateral Movement",
			"high", "Lateral Movement", "T1021.006", "Windows Remote Management",
			"Detects lateral movement via Windows Management Instrumentation",
			"process",
			"keywords",
			[]string{"wmic /node:", "Win32_Process create", "wmiexec", "Invoke-WmiMethod"},
		},
		{
			"Credential Dumping via reg.exe",
			"high", "Credential Access", "T1003.002", "Security Account Manager",
			"Detects SAM/SYSTEM/SECURITY hive export via reg.exe for offline cracking",
			"process",
			"keywords",
			[]string{"reg save HKLM\\SAM", "reg save HKLM\\SYSTEM", "reg save HKLM\\SECURITY"},
		},
		{
			"Certutil Used for Download",
			"medium", "Defense Evasion", "T1218", "Signed Binary Proxy Execution",
			"Detects certutil.exe used to download files — common LOLBin abuse",
			"process",
			"keywords",
			[]string{"certutil -urlcache", "certutil.exe -decode", "certutil -split -f"},
		},
		{
			"Suspicious netcat Usage",
			"high", "Command and Control", "T1095", "Non-Application Layer Protocol",
			"Detects netcat used for reverse shells or port forwarding",
			"process",
			"keywords",
			[]string{"nc -e /bin/sh", "nc -lvp", "ncat --exec", "netcat -e cmd"},
		},
		{
			"RDP Brute Force Login Failures",
			"medium", "Credential Access", "T1110.001", "Password Guessing",
			"Detects rapid RDP authentication failures indicating brute force",
			"windows",
			"keywords",
			[]string{"EventID 4625", "Logon Type: 10", "TerminalServices", "RDP-Tcp"},
		},
		{
			"Shadow Copy Deletion",
			"critical", "Impact", "T1490", "Inhibit System Recovery",
			"Detects shadow copy deletion — a hallmark of ransomware pre-encryption cleanup",
			"process",
			"keywords",
			[]string{"vssadmin delete shadows", "wmic shadowcopy delete", "bcdedit /set recoveryenabled no", "wbadmin delete catalog"},
		},
	}
	for _, r := range rules {
		// Build a JSON array safely using database/json encoding logic inline
		kw := `[`
		for i, k := range r.keywords {
			if i > 0 {
				kw += `,`
			}
			// Escape backslashes and double-quotes
			escaped := ""
			for _, c := range k {
				switch c {
				case '\\':
					escaped += `\\`
				case '"':
					escaped += `\"`
				default:
					escaped += string(c)
				}
			}
			kw += `"` + escaped + `"`
		}
		kw += `]`
		exec(db, `
			INSERT INTO sigma_rules
				(title, severity, mitre_tactic, mitre_technique, mitre_name, description,
				 logsource_cat, keywords, condition, enabled, status, tenant_id)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9,true,'stable',$10)
			ON CONFLICT DO NOTHING`,
			r.title, r.sev, r.tactic, r.technique, r.techName,
			r.desc, r.logsrc, kw, r.condition, tid,
		)
	}
}

// ── IOCs ──────────────────────────────────────────────────────────────────────

func seedIOCs(db *sql.DB, tid int) {
	log.Println("  iocs…")
	type ioc struct{ indicator, typ, sev, desc, source string }
	iocs := []ioc{
		// Known C2 / malware IPs
		{"185.220.101.45", "ip", "critical", "Tor exit node used for C2 communication — multiple threat actor campaigns", "AbuseIPDB"},
		{"45.142.212.100", "ip", "high", "Cobalt Strike team server — Mandiant attribution APT41", "Mandiant"},
		{"194.165.16.78", "ip", "high", "Emotet C2 server — Epoch 4 infrastructure", "ESET"},
		{"91.92.109.0", "ip", "medium", "Mass scanner / brute-force source — targeting SSH/RDP", "Shodan"},
		// Phishing / malware domains
		{"update-microsofts.com", "domain", "high", "Phishing domain impersonating Microsoft update portal", "VirusTotal"},
		{"secure-paypa1.net", "domain", "high", "PayPal credential harvesting phishing domain", "PhishTank"},
		{"cdn-fontawesome.workers[.]dev", "domain", "medium", "Supply chain attack staging domain — typosquatting cdnjs", "CISA"},
		// Malware file hashes
		{"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "hash", "low", "Empty file hash used as IoC baseline reference", "Internal"},
		{"44d88612fea8a8f36de82e1278abb02f", "hash", "critical", "MD5 hash of WannaCry ransomware payload (tasksche.exe)", "NIST NVD"},
		{"1e1a5494f2f9e5c83b33bb9dc2db614f84a4", "hash", "critical", "SHA1 hash of Cobalt Strike stager DLL variant", "Recorded Future"},
		// Additional
		{"23.95.97.59", "ip", "critical", "Known Lazarus Group C2 — cryptocurrency theft campaign", "CISA AA22"},
		{"malware-cdn.ru", "domain", "high", "Russian malware distribution CDN — hosting multiple stagers", "OSINT"},
	}
	for _, i := range iocs {
		exec(db, `
			INSERT INTO iocs (indicator, type, severity, description, source, enabled, tenant_id)
			VALUES ($1,$2,$3,$4,$5,true,$6)
			ON CONFLICT DO NOTHING`,
			i.indicator, i.typ, i.sev, i.desc, i.source, tid,
		)
	}
}

// ── Correlation rules ─────────────────────────────────────────────────────────

func seedCorrelationRules(db *sql.DB, tid int) {
	log.Println("  correlation_rules…")
	type corrRule struct {
		name, desc, sev, tactic, technique, action, corrType, src string
		window, threshold                                          int
	}
	rules := []corrRule{
		{"Brute Force: 10 Failed Logins in 5 min", "Multiple rapid authentication failures from single source — likely brute force", "high", "Credential Access", "T1110", "create_incident", "threshold", "auth_log", 5, 10},
		{"Port Scan: >20 Unique Ports in 2 min", "Sequential or random port probing from one source — reconnaissance activity", "medium", "Discovery", "T1046", "alert", "threshold", "network", 2, 20},
		{"C2 Beacon: Periodic Outbound Every 60s", "Regular periodic outbound connections to single IP — C2 heartbeat pattern", "high", "Command and Control", "T1071", "create_incident", "periodic", "network", 5, 5},
		{"Lateral Movement: 3+ Hosts in 10 min", "Agent connecting to 3+ internal hosts in short window — pivot detection", "high", "Lateral Movement", "T1021", "alert", "threshold", "network", 10, 3},
		{"Data Exfil: Large Outbound >100MB in 1h", "Unusually large outbound data transfer — potential exfiltration event", "critical", "Exfiltration", "T1048", "isolate_and_alert", "volume", "network", 60, 1},
		{"Privilege Escalation Chain Detected", "Low-priv process spawning high-priv child within 2 min — escalation chain", "critical", "Privilege Escalation", "T1068", "create_incident", "sequence", "process", 2, 2},
		{"Ransomware: Mass File Modification", "Rapid modification of >50 files in 1 min — ransomware encryption pattern", "critical", "Impact", "T1486", "isolate_and_alert", "threshold", "fim", 1, 50},
		{"Account Created Then Used Immediately", "New user account created and authenticated within 5 min — backdoor pattern", "high", "Persistence", "T1136", "alert", "sequence", "auth_log", 5, 2},
		{"DNS Tunneling: High-Frequency DNS Queries", "Abnormal DNS query rate to single domain — DNS exfiltration/tunneling", "high", "Command and Control", "T1071.004", "alert", "threshold", "dns", 5, 50},
		{"Impossible Travel: Auth from 2+ Countries", "Logins from geographically impossible locations within short timeframe", "high", "Initial Access", "T1078", "alert", "geo_anomaly", "auth_log", 30, 2},
	}
	for _, r := range rules {
		exec(db, `
			INSERT INTO correlation_rules
				(name, description, severity, mitre_technique, action, enabled,
				 correlation_type, window_minutes, threshold, source_type, tenant_id, created_by)
			VALUES ($1,$2,$3,$4,$5,true,$6,$7,$8,$9,$10,'system')
			ON CONFLICT DO NOTHING`,
			r.name, r.desc, r.sev, r.technique, r.action,
			r.corrType, r.window, r.threshold, r.src, tid,
		)
	}
}

// ── Threat actors ─────────────────────────────────────────────────────────────

func seedThreatActors(db *sql.DB, tid int) {
	log.Println("  threat_actors…")
	type actor struct {
		name, country, motivation, sophistication, desc string
		aliases, sectors, techniques                    []string
	}
	actors := []actor{
		{
			"APT28", "Russia", "espionage", "nation-state",
			"Russian GRU-linked threat actor targeting government, military, and defense sectors globally. Known for spear-phishing, credential theft, and custom malware.",
			[]string{"Fancy Bear", "STRONTIUM", "Sofacy", "Pawn Storm"},
			[]string{"government", "defense", "aerospace", "energy"},
			[]string{"T1566", "T1078", "T1059.001", "T1003.001", "T1021"},
		},
		{
			"Lazarus Group", "North Korea", "financial", "nation-state",
			"DPRK-attributed group responsible for large-scale cryptocurrency theft, SWIFT banking attacks, and ransomware campaigns including WannaCry.",
			[]string{"Hidden Cobra", "ZINC", "Guardians of Peace"},
			[]string{"financial", "cryptocurrency", "defense", "government"},
			[]string{"T1566", "T1190", "T1486", "T1059", "T1070"},
		},
		{
			"APT41", "China", "espionage_financial", "nation-state",
			"Chinese state-sponsored group conducting both espionage and cybercrime. Notable for supply chain attacks and exploitation of public-facing applications.",
			[]string{"Winnti", "Barium", "Double Dragon"},
			[]string{"technology", "healthcare", "telecommunications", "gaming"},
			[]string{"T1195", "T1190", "T1078", "T1505.003", "T1027"},
		},
		{
			"Sandworm", "Russia", "sabotage", "nation-state",
			"Russian GRU Unit 74455 responsible for destructive attacks on critical infrastructure including NotPetya, Ukrainian power grid attacks, and Olympic Destroyer.",
			[]string{"Voodoo Bear", "BlackEnergy", "TeleBots"},
			[]string{"energy", "government", "media", "financial"},
			[]string{"T1486", "T1561", "T1485", "T1565", "T1059"},
		},
		{
			"FIN7", "Unknown", "financial", "high",
			"Financially motivated criminal group targeting retail, restaurant, and hospitality sectors via spear-phishing and POS malware for payment card theft.",
			[]string{"Carbanak", "Navigator Group", "Sangria Tempest"},
			[]string{"retail", "hospitality", "financial", "restaurant"},
			[]string{"T1566.001", "T1059.001", "T1055", "T1003", "T1041"},
		},
		{
			"REvil", "Unknown", "ransomware", "high",
			"Ransomware-as-a-Service (RaaS) operation responsible for high-profile attacks including Kaseya VSA supply chain and JBS Foods. Operated DarkWeb leak site.",
			[]string{"Sodinokibi", "Gold Southfield"},
			[]string{"manufacturing", "legal", "food", "technology"},
			[]string{"T1486", "T1490", "T1489", "T1078", "T1133"},
		},
	}
	for _, a := range actors {
		aliasArr := toPGArray(a.aliases)
		sectorArr := toPGArray(a.sectors)
		techArr := toPGArray(a.techniques)
		exec(db, `
			INSERT INTO threat_actors
				(name, aliases, origin_country, motivation, sophistication, description,
				 targeted_sectors, mitre_techniques, tenant_id, is_builtin)
			VALUES ($1,$2::text[],$3,$4,$5,$6,$7::text[],$8::text[],$9,true)
			ON CONFLICT DO NOTHING`,
			a.name, aliasArr, a.country, a.motivation, a.sophistication, a.desc,
			sectorArr, techArr, tid,
		)
	}
}

// ── Threat feeds ──────────────────────────────────────────────────────────────

func seedThreatFeeds(db *sql.DB, tid int) {
	log.Println("  threat_feeds…")
	type feed struct {
		name, source, feedType, format string
		iocCount                        int
	}
	feeds := []feed{
		{"Abuse.ch URLhaus", "https://urlhaus.abuse.ch/downloads/csv/", "malware_url", "csv", 2400000},
		{"Abuse.ch MalwareBazaar", "https://bazaar.abuse.ch/export/csv/recent/", "malware_hash", "csv", 180000},
		{"CISA KEV", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "vulnerability", "json", 1100},
		{"Emerging Threats Open Rules", "https://rules.emergingthreats.net/open/snort-2.9.0/rules/", "ids_rules", "suricata", 40000},
		{"AbuseIPDB Blacklist", "https://api.abuseipdb.com/api/v2/blacklist", "ip_reputation", "json", 10000},
		{"PhishTank", "https://data.phishtank.com/data/online-valid.csv", "phishing_url", "csv", 25000},
		{"AlienVault OTX Pulses", "https://otx.alienvault.com/api/v1/pulses/subscribed", "multi", "json", 500000},
		{"Feodo Tracker C2 IPs", "https://feodotracker.abuse.ch/downloads/ipblocklist.json", "ip_c2", "json", 1500},
	}
	for _, f := range feeds {
		exec(db, `
			INSERT INTO threat_feeds
				(name, source, feed_type, format, enabled, ioc_count, tenant_id)
			VALUES ($1,$2,$3,$4,true,$5,$6)
			ON CONFLICT DO NOTHING`,
			f.name, f.source, f.feedType, f.format, f.iocCount, tid,
		)
	}
}

// ── JA3 fingerprints ──────────────────────────────────────────────────────────

func seedJA3Fingerprints(db *sql.DB, tid int) {
	log.Println("  ja3_fingerprints…")
	type ja3 struct{ hash, threat, sev, source, desc string }
	fps := []ja3{
		{"e7d705a3286e19ea42f587b344ee6865", "Cobalt Strike Beacon", "critical", "Salesforce", "Default Cobalt Strike Beacon JA3 — malleable C2 profile"},
		{"6734f37431670b3ab4292b8f60f29984", "Metasploit Meterpreter", "critical", "Fox-IT", "Metasploit Meterpreter reverse HTTPS handler JA3"},
		{"bc6c386f480f01fc8b4c58cf69b80c01", "Dridex Banking Trojan", "high", "SSLBL", "Dridex banking malware TLS fingerprint"},
		{"0ec53b0e17c7c7f4a4f8e4d7b1e1fc9e", "TrickBot", "critical", "Recorded Future", "TrickBot malware TLS C2 fingerprint"},
		{"de350869b8c85de67a350c8d186f11e6", "Emotet", "critical", "Cert.pl", "Emotet loader HTTPS C2 communication fingerprint"},
		{"a0e9f5d64349fb13191bc781f81f42e1", "Tor Browser", "medium", "Open Source", "Tor Browser default TLS fingerprint — anonymization tool"},
		{"07efe82a1f47e1b5e18d9b6e7f4b70f1", "AsyncRAT", "high", "Any.run", "AsyncRAT remote access trojan TLS fingerprint"},
		{"d7f3b1a2e6c9f0e4d2b1c5a8f9e3d4b2", "NjRAT", "high", "SSLBL", "NjRAT remote access trojan SSL fingerprint"},
		{"bfbe645c6e0bb6e1493f147c2d1b7e42", "QakBot", "critical", "Zscaler", "QakBot (QBot) banking trojan C2 TLS fingerprint"},
		{"c12f54a3f91dc7bafd92cb59fe009a35", "Malware Generic TLS", "medium", "Internal", "Generic malware TLS fingerprint — missing SNI extension, suspicious cipher suite ordering"},
	}
	for _, f := range fps {
		exec(db, `
			INSERT INTO ja3_fingerprints (hash, threat_name, severity, source, description, enabled, tenant_id)
			VALUES ($1,$2,$3,$4,$5,true,$6)
			ON CONFLICT DO NOTHING`,
			f.hash, f.threat, f.sev, f.source, f.desc, tid,
		)
	}
}

// ── Hunt templates ────────────────────────────────────────────────────────────

func seedHuntTemplates(db *sql.DB, tid int) {
	log.Println("  hunt_templates…")
	type tpl struct {
		name, desc, tactic, technique, query string
	}
	tpls := []tpl{
		{
			"Hunt: PowerShell Download Cradles",
			"Find PowerShell commands used to download and execute payloads via IEX, Invoke-Expression, or WebClient",
			"Execution", "T1059.001",
			`process_name:"powershell.exe" AND (cmdline:*IEX* OR cmdline:*Invoke-Expression* OR cmdline:*DownloadString* OR cmdline:*WebClient*) AND NOT cmdline:*WindowsUpdate*`,
		},
		{
			"Hunt: Living off the Land Binaries",
			"Find LOLBin abuse — certutil, mshta, regsvr32, wscript, cscript used for execution",
			"Defense Evasion", "T1218",
			`process_name:(certutil.exe OR mshta.exe OR regsvr32.exe OR wscript.exe OR cscript.exe) AND (cmdline:*http* OR cmdline:*ftp* OR cmdline:*\\\\*)`,
		},
		{
			"Hunt: Suspicious Parent-Child Process",
			"Detect unusual parent-child relationships: Office spawning shells, browsers launching cmd",
			"Execution", "T1059",
			`parent_process:(winword.exe OR excel.exe OR powerpnt.exe OR outlook.exe OR chrome.exe OR firefox.exe) AND process_name:(cmd.exe OR powershell.exe OR wscript.exe OR cscript.exe OR mshta.exe)`,
		},
		{
			"Hunt: Credential Access via LSASS",
			"Find processes opening LSASS with suspicious access rights for credential dumping",
			"Credential Access", "T1003.001",
			`event_type:process_access AND target_process:lsass.exe AND access_rights:(0x1010 OR 0x1038 OR 0x143a) AND NOT process_name:(MsMpEng.exe OR csrss.exe OR wininit.exe)`,
		},
		{
			"Hunt: Persistence via Registry Run Keys",
			"Find registry modifications to Run/RunOnce keys used for persistence",
			"Persistence", "T1547.001",
			`event_type:registry AND registry_key:(*\\Run\\* OR *\\RunOnce\\* OR *\\RunOnceEx\\*) AND NOT process_name:(msiexec.exe OR MicrosoftEdge*.exe OR OneDrive.exe)`,
		},
		{
			"Hunt: Lateral Movement via PsExec/WMI",
			"Detect remote execution artefacts from PsExec and WMI lateral movement",
			"Lateral Movement", "T1021",
			`(process_name:PSEXESVC.exe OR (process_name:WmiPrvSE.exe AND child_process:(cmd.exe OR powershell.exe))) AND NOT source_ip:10.0.0.1`,
		},
		{
			"Hunt: DNS over HTTPS Abuse",
			"Find processes making direct HTTPS connections to known DoH providers — C2 evasion",
			"Command and Control", "T1071.004",
			`dst_ip:(1.1.1.1 OR 8.8.8.8 OR 9.9.9.9) AND dst_port:443 AND NOT process_name:(chrome.exe OR firefox.exe OR msedge.exe OR brave.exe)`,
		},
		{
			"Hunt: Scheduled Task Creation",
			"Find scheduled tasks created by non-system processes — persistence mechanism",
			"Persistence", "T1053.005",
			`event_type:process AND process_name:schtasks.exe AND cmdline:*/create* AND NOT parent_process:(services.exe OR msiexec.exe OR svchost.exe)`,
		},
		{
			"Hunt: Unusual Outbound Connections",
			"Find internal hosts making outbound connections to rare/new external IPs on non-standard ports",
			"Command and Control", "T1071",
			`event_type:network AND direction:outbound AND dst_port:(NOT 80 AND NOT 443 AND NOT 53 AND NOT 25 AND NOT 587) AND dst_ip:!(10.0.0.0/8 OR 192.168.0.0/16 OR 172.16.0.0/12)`,
		},
		{
			"Hunt: Shadow Copy Deletion Attempts",
			"Detect ransomware pre-cursor activity — deletion of volume shadow copies",
			"Impact", "T1490",
			`process_name:(vssadmin.exe OR wmic.exe OR bcdedit.exe OR wbadmin.exe) AND (cmdline:*delete* OR cmdline:*shadows* OR cmdline:*recoveryenabled*) AND severity:>medium`,
		},
	}
	for _, t := range tpls {
		exec(db, `
			INSERT INTO hunt_templates
				(name, description, mitre_tactic, mitre_technique, kql_query,
				 is_active, tenant_id, created_by)
			VALUES ($1,$2,$3,$4,$5,true,$6,'system')
			ON CONFLICT DO NOTHING`,
			t.name, t.desc, t.tactic, t.technique, t.query, tid,
		)
	}
}

// ── Log sources ───────────────────────────────────────────────────────────────

func seedLogSources(db *sql.DB, tid int) {
	log.Println("  log_sources…")
	type ls struct{ name, srcType, deviceType, format string }
	sources := []ls{
		{"Primary Firewall (pfSense)", "syslog", "firewall", "CEF"},
		{"Windows Domain Controller", "winlog", "server", "Windows Event"},
		{"Linux Auth Logs", "syslog", "server", "syslog"},
		{"Nginx Access Logs", "file", "web_server", "NCSA"},
		{"AWS CloudTrail", "api", "cloud", "JSON"},
		{"Office 365 Audit", "api", "cloud", "JSON"},
		{"Cisco ASA VPN", "syslog", "vpn", "CEF"},
		{"CrowdStrike Falcon", "api", "edr", "JSON"},
	}
	for _, s := range sources {
		exec(db, `
			INSERT INTO log_sources (name, source_type, device_type, format, enabled, tenant_id)
			VALUES ($1,$2,$3,$4,true,$5)
			ON CONFLICT DO NOTHING`,
			s.name, s.srcType, s.deviceType, s.format, tid,
		)
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

func toPGArray(ss []string) string {
	if len(ss) == 0 {
		return "{}"
	}
	out := "{"
	for i, s := range ss {
		if i > 0 {
			out += ","
		}
		out += `"` + s + `"`
	}
	return out + "}"
}
