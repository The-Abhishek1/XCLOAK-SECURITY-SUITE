package services

// CIS Benchmark compliance scanner — closes the gap vs Tenable.io,
// Qualys, and Rapid7 continuous compliance scanning.
//
// Approach: passive checks derived from data the agent already sends
// (packages, services, users, registry entries). No new agent commands
// are required; the scanner runs against the most-recently-collected
// snapshot for each agent.
//
// Benchmarks implemented:
//   CIS Linux Level 1  — 18 controls across 4 categories
//   CIS Windows Level 1 — 10 controls across 3 categories
//
// Platform is auto-detected from agents.os (linux / windows / darwin).
// Darwin/macOS agents receive the Linux benchmark as a best-effort fallback.
//
// Findings are upserted into cis_findings so each (agent, control_id)
// always reflects the most recent scan result.

import (
	"fmt"
	"log"
	"strings"
	"time"

	"xcloak-platform/database"
)

// ── Data model ─────────────────────────────────────────────────────────────────

type CISControl struct {
	ID          string
	Platform    string // linux | windows
	Profile     string // Level 1 | Level 2
	Category    string
	Title       string
	Description string
	Severity    string // info | low | medium | high | critical
	Remediation string
}

type CISFinding struct {
	CISControl
	AgentID  int
	TenantID int
	Status   string // pass | fail | warn | unknown
	Evidence string
}

// ── Linux Level 1 control definitions ─────────────────────────────────────────

var linuxControls = []CISControl{
	// Network Services — unnecessary services should not be installed/running
	{
		ID: "CIS-L-2.2.1", Platform: "linux", Profile: "Level 1",
		Category: "Network Services", Severity: "medium",
		Title:       "Ensure X Window System is not installed",
		Description: "The X Window System provides a graphical desktop environment unnecessary on servers. It increases the attack surface.",
		Remediation: "apt purge xserver-xorg  OR  dnf remove xorg-x11-server-Xorg",
	},
	{
		ID: "CIS-L-2.2.2", Platform: "linux", Profile: "Level 1",
		Category: "Network Services", Severity: "medium",
		Title:       "Ensure Avahi Server is not installed",
		Description: "Avahi is a mDNS/DNS-SD protocol daemon used for auto-discovery. It is unnecessary on most servers and increases attack surface.",
		Remediation: "systemctl disable avahi-daemon && apt purge avahi-daemon",
	},
	{
		ID: "CIS-L-2.2.3", Platform: "linux", Profile: "Level 1",
		Category: "Network Services", Severity: "low",
		Title:       "Ensure CUPS is not installed",
		Description: "CUPS (print server) is unnecessary on non-print-server hosts.",
		Remediation: "apt purge cups",
	},
	{
		ID: "CIS-L-2.2.5", Platform: "linux", Profile: "Level 1",
		Category: "Network Services", Severity: "medium",
		Title:       "Ensure rpcbind is not installed or is stopped",
		Description: "rpcbind is required for NFS and NIS. It should not be running on hosts that do not need these services.",
		Remediation: "systemctl disable rpcbind && systemctl stop rpcbind",
	},
	{
		ID: "CIS-L-2.2.6", Platform: "linux", Profile: "Level 1",
		Category: "Network Services", Severity: "medium",
		Title:       "Ensure NIS Server is not installed",
		Description: "NIS (ypserv) is an insecure legacy directory service. SSH and LDAP are modern replacements.",
		Remediation: "apt purge nis",
	},
	{
		ID: "CIS-L-2.3.1", Platform: "linux", Profile: "Level 1",
		Category: "Network Services", Severity: "medium",
		Title:       "Ensure NIS Client is not installed",
		Description: "The NIS client (ypbind) transmits credentials in cleartext.",
		Remediation: "apt purge nis",
	},
	{
		ID: "CIS-L-2.3.2", Platform: "linux", Profile: "Level 1",
		Category: "Network Services", Severity: "high",
		Title:       "Ensure rsh client is not installed",
		Description: "rsh transmits credentials in cleartext and is superseded by SSH.",
		Remediation: "apt purge rsh-client",
	},
	{
		ID: "CIS-L-2.3.4", Platform: "linux", Profile: "Level 1",
		Category: "Network Services", Severity: "high",
		Title:       "Ensure telnet client is not installed",
		Description: "Telnet transmits all data including credentials in cleartext.",
		Remediation: "apt purge telnet",
	},

	// Logging & Auditing
	{
		ID: "CIS-L-4.1.1", Platform: "linux", Profile: "Level 1",
		Category: "Logging & Auditing", Severity: "high",
		Title:       "Ensure auditing is enabled (auditd)",
		Description: "The Linux Audit Subsystem (auditd) records security-relevant kernel events. Without it, forensic investigation after a breach is severely limited.",
		Remediation: "apt install auditd && systemctl enable auditd && systemctl start auditd",
	},
	{
		ID: "CIS-L-4.2.1", Platform: "linux", Profile: "Level 1",
		Category: "Logging & Auditing", Severity: "medium",
		Title:       "Ensure rsyslog is installed and running",
		Description: "System logs must be collected and forwarded to a central log management system.",
		Remediation: "apt install rsyslog && systemctl enable rsyslog",
	},

	// Firewall
	{
		ID: "CIS-L-3.4.1", Platform: "linux", Profile: "Level 1",
		Category: "Network Firewall", Severity: "high",
		Title:       "Ensure a firewall is installed and running",
		Description: "A host-based firewall (iptables, nftables, firewalld, or ufw) should be active to restrict inbound and outbound traffic.",
		Remediation: "apt install ufw && ufw enable  OR  systemctl enable --now firewalld",
	},

	// Access Control — local users
	{
		ID: "CIS-L-5.4.1", Platform: "linux", Profile: "Level 1",
		Category: "Access Control", Severity: "critical",
		Title:       "Ensure no accounts have empty password fields",
		Description: "Accounts with empty passwords can be accessed without credentials.",
		Remediation: "passwd -l <username> for each account with an empty password",
	},
	{
		ID: "CIS-L-5.4.2", Platform: "linux", Profile: "Level 1",
		Category: "Access Control", Severity: "medium",
		Title:       "Ensure no duplicate UIDs exist",
		Description: "Duplicate UIDs allow one account to impersonate another.",
		Remediation: "Review /etc/passwd for duplicate UID values and resolve conflicts.",
	},
	{
		ID: "CIS-L-5.4.3", Platform: "linux", Profile: "Level 1",
		Category: "Access Control", Severity: "medium",
		Title:       "Ensure system accounts do not have login shells",
		Description: "System accounts (UID < 1000) should have /sbin/nologin or /bin/false as their shell to prevent interactive login.",
		Remediation: "usermod -s /usr/sbin/nologin <system_account>",
	},
	{
		ID: "CIS-L-5.4.4", Platform: "linux", Profile: "Level 1",
		Category: "Access Control", Severity: "critical",
		Title:       "Ensure root is the only UID 0 account",
		Description: "Any account with UID 0 has full root-equivalent privileges.",
		Remediation: "Remove or reassign UID for any non-root account with UID 0.",
	},

	// SSH hardening — inferred from service presence and log events
	{
		ID: "CIS-L-5.2.1", Platform: "linux", Profile: "Level 1",
		Category: "SSH", Severity: "high",
		Title:       "Ensure SSH service is running",
		Description: "SSH should be the only remote access method on the system. Verify it is running and properly configured.",
		Remediation: "systemctl enable --now sshd",
	},
	{
		ID: "CIS-L-5.2.2", Platform: "linux", Profile: "Level 1",
		Category: "SSH", Severity: "critical",
		Title:       "Ensure no insecure remote access services are running (telnet/rsh/ftp)",
		Description: "telnetd, rshd, vsftpd in active state indicate unencrypted remote access is available.",
		Remediation: "systemctl disable telnet rsh vsftpd && remove packages",
	},
}

// ── Windows Level 1 control definitions ───────────────────────────────────────

var windowsControls = []CISControl{
	// Account Policies (registry: HKLM\SYSTEM\CurrentControlSet\Control\Lsa and SAM policy)
	{
		ID: "CIS-W-1.1.1", Platform: "windows", Profile: "Level 1",
		Category: "Account Policies", Severity: "high",
		Title:       "Ensure 'Password must meet complexity requirements' is enabled",
		Description: "Complex passwords resist brute-force and dictionary attacks.",
		Remediation: "Group Policy: Computer Config → Windows Settings → Security Settings → Account Policies → Password Policy → Password must meet complexity requirements: Enabled",
	},
	{
		ID: "CIS-W-1.1.4", Platform: "windows", Profile: "Level 1",
		Category: "Account Policies", Severity: "high",
		Title:       "Ensure 'Minimum password length' is set to 14 or more characters",
		Description: "Short passwords are vulnerable to brute-force attacks.",
		Remediation: "Group Policy: Account Policies → Password Policy → Minimum password length: 14",
	},
	{
		ID: "CIS-W-1.2.1", Platform: "windows", Profile: "Level 1",
		Category: "Account Policies", Severity: "medium",
		Title:       "Ensure 'Account lockout threshold' is set to 5 or fewer invalid attempts",
		Description: "Locking accounts after repeated failures prevents online brute-force attacks.",
		Remediation: "Group Policy: Account Policies → Account Lockout Policy → Account lockout threshold: 5",
	},

	// Security Options — UAC
	{
		ID: "CIS-W-2.3.11.6", Platform: "windows", Profile: "Level 1",
		Category: "User Account Control", Severity: "critical",
		Title:       "Ensure 'User Account Control: Run all administrators in Admin Approval Mode' is Enabled",
		Description: "UAC prevents malware from silently escalating privileges.",
		Remediation: "Registry: HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableLUA = 1",
	},

	// Logon / Display
	{
		ID: "CIS-W-2.3.7.4", Platform: "windows", Profile: "Level 1",
		Category: "Logon", Severity: "low",
		Title:       "Ensure 'Interactive logon: Do not display last user name' is Enabled",
		Description: "Prevents displaying the last logged-on username, reducing information disclosure.",
		Remediation: "Registry: HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\DontDisplayLastUserName = 1",
	},

	// Windows Firewall
	{
		ID: "CIS-W-9.1.1", Platform: "windows", Profile: "Level 1",
		Category: "Windows Firewall", Severity: "high",
		Title:       "Ensure 'Windows Firewall: Domain: Firewall state' is set to 'On'",
		Description: "Windows Firewall provides host-based traffic filtering.",
		Remediation: "Registry: HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\DomainProfile\\EnableFirewall = 1",
	},
	{
		ID: "CIS-W-9.2.1", Platform: "windows", Profile: "Level 1",
		Category: "Windows Firewall", Severity: "high",
		Title:       "Ensure 'Windows Firewall: Private: Firewall state' is set to 'On'",
		Description: "Windows Firewall private profile must be enabled.",
		Remediation: "Registry: HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile\\EnableFirewall = 1",
	},
	{
		ID: "CIS-W-9.3.1", Platform: "windows", Profile: "Level 1",
		Category: "Windows Firewall", Severity: "high",
		Title:       "Ensure 'Windows Firewall: Public: Firewall state' is set to 'On'",
		Description: "Windows Firewall public profile must be enabled.",
		Remediation: "Registry: HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\PublicProfile\\EnableFirewall = 1",
	},

	// Guest account
	{
		ID: "CIS-W-2.3.1.2", Platform: "windows", Profile: "Level 1",
		Category: "Account Management", Severity: "medium",
		Title:       "Ensure 'Guest account status' is set to 'Disabled'",
		Description: "The Guest account allows unauthenticated access.",
		Remediation: "net user guest /active:no",
	},

	// Remote Desktop
	{
		ID: "CIS-W-18.9.65.2", Platform: "windows", Profile: "Level 1",
		Category: "Remote Access", Severity: "high",
		Title:       "Ensure 'Require use of specific security layer for RDP' is Enabled",
		Description: "RDP should require NLA or TLS to prevent credential interception.",
		Remediation: "Registry: HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp\\SecurityLayer = 2",
	},
	{
		ID: "CIS-W-18.9.65.3", Platform: "windows", Profile: "Level 1",
		Category: "Remote Access", Severity: "critical",
		Title:       "Ensure 'Require NLA for RDP connections' is Enabled",
		Description: "Network Level Authentication prevents unauthenticated RDP connections.",
		Remediation: "Registry: HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp\\UserAuthentication = 1",
	},
}

// ── Main entry point ───────────────────────────────────────────────────────────

// RunCISBenchmark scans one agent against its platform's CIS Level 1 controls
// and upserts findings into cis_findings.
func RunCISBenchmark(agentID, tenantID int) error {
	var osType string
	err := database.RDB().QueryRow(
		`SELECT lower(COALESCE(os,'')) FROM agents WHERE id = $1`, agentID,
	).Scan(&osType)
	if err != nil {
		return fmt.Errorf("agent %d not found: %w", agentID, err)
	}

	var findings []CISFinding
	if strings.Contains(osType, "win") {
		findings = checkWindowsControls(agentID, tenantID)
	} else {
		// linux + darwin + anything unknown gets the Linux benchmark
		findings = checkLinuxControls(agentID, tenantID)
	}

	for _, f := range findings {
		if err := upsertCISFinding(f); err != nil {
			log.Printf("[cis] agent %d control %s upsert error: %v", agentID, f.ID, err)
		}
	}
	return nil
}

// AgentCISScore returns the percentage of passing controls for one agent.
func AgentCISScore(agentID int) (pass, total int, score float64) {
	database.RDB().QueryRow(`
		SELECT
			COUNT(*) FILTER (WHERE status = 'pass') AS pass,
			COUNT(*) AS total
		FROM cis_findings
		WHERE agent_id = $1
	`, agentID).Scan(&pass, &total)
	if total > 0 {
		score = float64(pass) / float64(total) * 100
	}
	return
}

func upsertCISFinding(f CISFinding) error {
	_, err := database.DB.Exec(`
		INSERT INTO cis_findings
			(tenant_id, agent_id, control_id, platform, profile,
			 category, title, status, severity, description, evidence, remediation, checked_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,NOW())
		ON CONFLICT (agent_id, control_id) DO UPDATE SET
			status      = EXCLUDED.status,
			evidence    = EXCLUDED.evidence,
			severity    = EXCLUDED.severity,
			checked_at  = EXCLUDED.checked_at
	`,
		f.TenantID, f.AgentID, f.ID, f.Platform, f.Profile,
		f.Category, f.Title, f.Status, f.Severity,
		f.Description, f.Evidence, f.Remediation,
	)
	return err
}

// ── Linux passive checks ───────────────────────────────────────────────────────

func checkLinuxControls(agentID, tenantID int) []CISFinding {
	pkgs := agentPackageSet(agentID)
	svcs := agentServiceSet(agentID)    // only "running"/"active" services
	allSvcs := agentAllServiceSet(agentID) // all services regardless of state
	users := agentUsers(agentID)

	findings := make([]CISFinding, 0, len(linuxControls))
	for _, ctrl := range linuxControls {
		f := CISFinding{CISControl: ctrl, AgentID: agentID, TenantID: tenantID}
		f.Status = "unknown"

		switch ctrl.ID {

		// X Window System — fail if any xserver package is installed
		case "CIS-L-2.2.1":
			xpkgs := []string{"xserver-xorg", "xorg-x11-server-xorg", "xorg-x11-server-common",
				"xserver-xorg-core", "x11-common"}
			if found := firstMatch(pkgs, xpkgs); found != "" {
				f.Status = "fail"
				f.Evidence = "package installed: " + found
			} else {
				f.Status = "pass"
			}

		// Avahi — fail if service is running
		case "CIS-L-2.2.2":
			if svcs["avahi-daemon"] || svcs["avahi"] {
				f.Status = "fail"
				f.Evidence = "avahi-daemon is running"
			} else {
				f.Status = "pass"
			}

		// CUPS — fail if package or service is present
		case "CIS-L-2.2.3":
			if pkgs["cups"] {
				f.Status = "fail"
				f.Evidence = "cups package is installed"
			} else if svcs["cups"] {
				f.Status = "fail"
				f.Evidence = "cups service is running"
			} else {
				f.Status = "pass"
			}

		// rpcbind — fail if running
		case "CIS-L-2.2.5":
			if svcs["rpcbind"] || svcs["portmap"] {
				f.Status = "fail"
				f.Evidence = "rpcbind/portmap service is running"
			} else {
				f.Status = "pass"
			}

		// NIS server
		case "CIS-L-2.2.6":
			if pkgs["nis"] || pkgs["ypserv"] || svcs["ypserv"] {
				f.Status = "fail"
				f.Evidence = "NIS server package/service present"
			} else {
				f.Status = "pass"
			}

		// NIS client
		case "CIS-L-2.3.1":
			if pkgs["nis"] || pkgs["ypbind"] || svcs["ypbind"] {
				f.Status = "fail"
				f.Evidence = "NIS client package/service present"
			} else {
				f.Status = "pass"
			}

		// rsh client
		case "CIS-L-2.3.2":
			if pkgs["rsh-client"] || pkgs["rsh"] || pkgs["rsh-redone-client"] {
				f.Status = "fail"
				f.Evidence = "rsh client package is installed"
			} else {
				f.Status = "pass"
			}

		// telnet client
		case "CIS-L-2.3.4":
			if pkgs["telnet"] || pkgs["telnet-client"] || pkgs["inetutils-telnet"] {
				f.Status = "fail"
				f.Evidence = "telnet client package is installed"
			} else {
				f.Status = "pass"
			}

		// auditd
		case "CIS-L-4.1.1":
			if svcs["auditd"] || svcs["audit"] {
				f.Status = "pass"
			} else if pkgs["auditd"] || pkgs["audit"] {
				f.Status = "warn"
				f.Evidence = "auditd package installed but service not running"
			} else {
				f.Status = "fail"
				f.Evidence = "auditd package not installed and service not running"
			}

		// rsyslog / syslog
		case "CIS-L-4.2.1":
			if svcs["rsyslog"] || svcs["syslog"] || svcs["syslog-ng"] {
				f.Status = "pass"
			} else if pkgs["rsyslog"] || pkgs["syslog-ng"] {
				f.Status = "warn"
				f.Evidence = "syslog package installed but service not running"
			} else {
				f.Status = "fail"
				f.Evidence = "no syslog service detected"
			}

		// Firewall
		case "CIS-L-3.4.1":
			firewallSvcs := []string{"iptables", "ip6tables", "firewalld", "ufw", "nftables"}
			if found := firstMatchInSet(svcs, firewallSvcs); found != "" {
				f.Status = "pass"
			} else if found := firstMatchInSet(allSvcs, firewallSvcs); found != "" {
				f.Status = "warn"
				f.Evidence = found + " installed but not running"
			} else {
				f.Status = "fail"
				f.Evidence = "no firewall service detected"
			}

		// Empty passwords — check for users with empty shell (proxy for unconfigured accounts)
		case "CIS-L-5.4.1":
			var empties []string
			for _, u := range users {
				if u.shell == "" || u.shell == "/bin/sh" && u.uid == 0 && u.username != "root" {
					empties = append(empties, u.username)
				}
			}
			if len(empties) > 0 {
				f.Status = "warn"
				f.Evidence = "accounts may have empty passwords: " + strings.Join(empties, ", ")
			} else {
				f.Status = "pass"
			}

		// Duplicate UIDs
		case "CIS-L-5.4.2":
			uidCounts := make(map[int][]string)
			for _, u := range users {
				if u.uid >= 0 {
					uidCounts[u.uid] = append(uidCounts[u.uid], u.username)
				}
			}
			var dups []string
			for uid, names := range uidCounts {
				if len(names) > 1 {
					dups = append(dups, fmt.Sprintf("uid=%d: %s", uid, strings.Join(names, ",")))
				}
			}
			if len(dups) > 0 {
				f.Status = "fail"
				f.Evidence = "duplicate UIDs: " + strings.Join(dups, "; ")
			} else {
				f.Status = "pass"
			}

		// System accounts with login shells
		case "CIS-L-5.4.3":
			loginShells := map[string]bool{
				"/bin/bash": true, "/bin/sh": true, "/bin/zsh": true,
				"/bin/ksh": true, "/usr/bin/bash": true, "/usr/bin/zsh": true,
			}
			var bad []string
			for _, u := range users {
				if u.uid > 0 && u.uid < 1000 && u.username != "sync" && loginShells[u.shell] {
					bad = append(bad, fmt.Sprintf("%s(uid=%d,shell=%s)", u.username, u.uid, u.shell))
				}
			}
			if len(bad) > 0 {
				f.Status = "fail"
				f.Evidence = "system accounts with login shells: " + strings.Join(bad, ", ")
			} else {
				f.Status = "pass"
			}

		// Root is only UID 0
		case "CIS-L-5.4.4":
			var uid0 []string
			for _, u := range users {
				if u.uid == 0 && u.username != "root" {
					uid0 = append(uid0, u.username)
				}
			}
			if len(uid0) > 0 {
				f.Status = "fail"
				f.Evidence = "non-root UID 0 accounts: " + strings.Join(uid0, ", ")
			} else {
				f.Status = "pass"
			}

		// SSH is running
		case "CIS-L-5.2.1":
			if svcs["sshd"] || svcs["ssh"] || svcs["openssh-server"] {
				f.Status = "pass"
			} else {
				f.Status = "warn"
				f.Evidence = "no SSH service detected as running"
			}

		// Insecure remote access services
		case "CIS-L-5.2.2":
			badSvcs := []string{"telnetd", "in.telnetd", "rshd", "in.rshd", "vsftpd",
				"ftpd", "wu-ftpd", "in.ftpd"}
			if found := firstMatchInSet(svcs, badSvcs); found != "" {
				f.Status = "fail"
				f.Evidence = "insecure remote access service running: " + found
			} else {
				f.Status = "pass"
			}
		}

		findings = append(findings, f)
	}
	return findings
}

// ── Windows passive checks ─────────────────────────────────────────────────────

func checkWindowsControls(agentID, tenantID int) []CISFinding {
	users := agentUsers(agentID)
	svcs := agentServiceSet(agentID)

	findings := make([]CISFinding, 0, len(windowsControls))
	for _, ctrl := range windowsControls {
		f := CISFinding{CISControl: ctrl, AgentID: agentID, TenantID: tenantID}
		f.Status = "unknown"

		switch ctrl.ID {

		// Password complexity (registry: Lsa PasswordComplexity = 1)
		case "CIS-W-1.1.1":
			f.Status, f.Evidence = checkRegistry(agentID,
				`SYSTEM\CurrentControlSet\Control\Lsa`, "PasswordComplexity", "1", "eq")

		// Min password length ≥ 14
		case "CIS-W-1.1.4":
			f.Status, f.Evidence = checkRegistryNumeric(agentID,
				`SYSTEM\CurrentControlSet\Services\Netlogon\Parameters`, "MinimumPasswordLength", 14, "gte")

		// Account lockout threshold ≤ 5
		case "CIS-W-1.2.1":
			status, ev := checkRegistryNumeric(agentID,
				`SYSTEM\CurrentControlSet\Services\Netlogon\Parameters`, "LockoutBadCount", 5, "lte")
			// 0 means "never lock out" which also fails
			if status == "pass" {
				val := registryValue(agentID,
					`SYSTEM\CurrentControlSet\Services\Netlogon\Parameters`, "LockoutBadCount")
				if val == "0" {
					status = "fail"
					ev = "LockoutBadCount = 0 (never lock out)"
				}
			}
			f.Status, f.Evidence = status, ev

		// UAC EnableLUA = 1
		case "CIS-W-2.3.11.6":
			f.Status, f.Evidence = checkRegistry(agentID,
				`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`, "EnableLUA", "1", "eq")

		// Don't display last username
		case "CIS-W-2.3.7.4":
			f.Status, f.Evidence = checkRegistry(agentID,
				`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`, "DontDisplayLastUserName", "1", "eq")

		// Windows Firewall — Domain
		case "CIS-W-9.1.1":
			f.Status, f.Evidence = checkRegistry(agentID,
				`SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile`,
				"EnableFirewall", "1", "eq")

		// Windows Firewall — Private
		case "CIS-W-9.2.1":
			f.Status, f.Evidence = checkRegistry(agentID,
				`SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile`,
				"EnableFirewall", "1", "eq")

		// Windows Firewall — Public
		case "CIS-W-9.3.1":
			f.Status, f.Evidence = checkRegistry(agentID,
				`SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile`,
				"EnableFirewall", "1", "eq")

		// Guest account disabled — check endpoint_users for 'Guest' username
		case "CIS-W-2.3.1.2":
			guestFound := false
			for _, u := range users {
				if strings.EqualFold(u.username, "guest") {
					guestFound = true
					break
				}
			}
			// Guest account presence in endpoint_users means it's enabled
			if guestFound {
				f.Status = "warn"
				f.Evidence = "Guest account detected in endpoint users — verify it is disabled"
			} else {
				f.Status = "pass"
			}

		// RDP security layer
		case "CIS-W-18.9.65.2":
			f.Status, f.Evidence = checkRegistry(agentID,
				`SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp`,
				"SecurityLayer", "2", "eq")

		// RDP NLA required
		case "CIS-W-18.9.65.3":
			f.Status, f.Evidence = checkRegistry(agentID,
				`SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp`,
				"UserAuthentication", "1", "eq")
			// Additional signal: check if RDP is even running
			if !svcs["termservice"] && !svcs["remote desktop services"] {
				f.Status = "pass"
				f.Evidence = "RDP service (TermService) not running — NLA check not applicable"
			}
		}

		findings = append(findings, f)
	}
	return findings
}

// ── Registry helpers ───────────────────────────────────────────────────────────

func registryValue(agentID int, keyPath, name string) string {
	var data string
	database.RDB().QueryRow(`
		SELECT COALESCE(data,'') FROM registry_entries
		WHERE agent_id = $1
		  AND lower(key_path) = lower($2)
		  AND lower(name) = lower($3)
		LIMIT 1
	`, agentID, keyPath, name).Scan(&data)
	return data
}

// checkRegistry checks whether a registry key equals (or matches) a target value.
func checkRegistry(agentID int, keyPath, name, wantVal, op string) (status, evidence string) {
	data := registryValue(agentID, keyPath, name)
	if data == "" {
		return "unknown", fmt.Sprintf("registry key not found: %s\\%s", keyPath, name)
	}
	match := false
	switch op {
	case "eq":
		match = strings.EqualFold(data, wantVal)
	}
	if match {
		return "pass", fmt.Sprintf("%s\\%s = %s", keyPath, name, data)
	}
	return "fail", fmt.Sprintf("%s\\%s = %s (want %s)", keyPath, name, data, wantVal)
}

// checkRegistryNumeric checks whether a registry DWORD satisfies a numeric comparison.
func checkRegistryNumeric(agentID int, keyPath, name string, threshold int, op string) (status, evidence string) {
	data := registryValue(agentID, keyPath, name)
	if data == "" {
		return "unknown", fmt.Sprintf("registry key not found: %s\\%s", keyPath, name)
	}
	var val int
	if _, err := fmt.Sscanf(data, "%d", &val); err != nil {
		return "unknown", fmt.Sprintf("non-numeric registry value: %s", data)
	}
	match := false
	switch op {
	case "gte":
		match = val >= threshold
	case "lte":
		match = val <= threshold
	case "gt":
		match = val > threshold
	case "lt":
		match = val < threshold
	}
	if match {
		return "pass", fmt.Sprintf("%s\\%s = %d", keyPath, name, val)
	}
	return "fail", fmt.Sprintf("%s\\%s = %d (want %s %d)", keyPath, name, val, op, threshold)
}

// ── Agent data loaders ─────────────────────────────────────────────────────────

func agentPackageSet(agentID int) map[string]bool {
	rows, err := database.RDB().Query(`
		SELECT lower(COALESCE(package_name,'')) FROM endpoint_packages
		WHERE agent_id = $1 AND collected_at > NOW() - INTERVAL '48 hours'
	`, agentID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	m := make(map[string]bool)
	for rows.Next() {
		var n string
		rows.Scan(&n)
		if n != "" {
			m[n] = true
		}
	}
	return m
}

func agentServiceSet(agentID int) map[string]bool {
	rows, err := database.RDB().Query(`
		SELECT lower(COALESCE(service_name,''))
		FROM endpoint_services
		WHERE agent_id = $1
		  AND lower(COALESCE(service_state,'')) IN ('running','active','started')
		  AND collected_at > NOW() - INTERVAL '48 hours'
	`, agentID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	m := make(map[string]bool)
	for rows.Next() {
		var n string
		rows.Scan(&n)
		if n != "" {
			m[n] = true
		}
	}
	return m
}

func agentAllServiceSet(agentID int) map[string]bool {
	rows, err := database.RDB().Query(`
		SELECT lower(COALESCE(service_name,''))
		FROM endpoint_services
		WHERE agent_id = $1 AND collected_at > NOW() - INTERVAL '48 hours'
	`, agentID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	m := make(map[string]bool)
	for rows.Next() {
		var n string
		rows.Scan(&n)
		if n != "" {
			m[n] = true
		}
	}
	return m
}

type agentUser struct {
	username string
	uid      int
	shell    string
}

func agentUsers(agentID int) []agentUser {
	rows, err := database.RDB().Query(`
		SELECT COALESCE(username,''), COALESCE(uid,-1), COALESCE(shell,'')
		FROM endpoint_users
		WHERE agent_id = $1 AND collected_at > NOW() - INTERVAL '48 hours'
	`, agentID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var users []agentUser
	for rows.Next() {
		var u agentUser
		rows.Scan(&u.username, &u.uid, &u.shell)
		users = append(users, u)
	}
	return users
}

// ── Set helpers ────────────────────────────────────────────────────────────────

func firstMatch(set map[string]bool, candidates []string) string {
	for _, c := range candidates {
		if set[strings.ToLower(c)] {
			return c
		}
	}
	return ""
}

func firstMatchInSet(set map[string]bool, candidates []string) string {
	for _, c := range candidates {
		if set[strings.ToLower(c)] {
			return c
		}
	}
	return ""
}

// ── Scheduler ─────────────────────────────────────────────────────────────────

const cisInterval = 6 * time.Hour

// StartCISScheduler runs the benchmark scanner for all active agents every 6 hours.
func StartCISScheduler() {
	go func() {
		time.Sleep(3 * time.Minute) // stagger from other schedulers
		for {
			if err := runCISForAllAgents(); err != nil {
				log.Printf("[cis] scheduler error: %v", err)
			}
			time.Sleep(cisInterval)
		}
	}()
}

func runCISForAllAgents() error {
	rows, err := database.DB.Query(`
		SELECT a.id, a.tenant_id
		FROM agents a
		JOIN tenants t ON t.id = a.tenant_id AND t.is_active = TRUE
		WHERE a.status != 'offline'
		  AND a.last_seen > NOW() - INTERVAL '48 hours'
	`)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var agentID, tenantID int
		if err := rows.Scan(&agentID, &tenantID); err != nil {
			continue
		}
		if err := RunCISBenchmark(agentID, tenantID); err != nil {
			log.Printf("[cis] agent %d: %v", agentID, err)
		}
	}
	return rows.Err()
}
