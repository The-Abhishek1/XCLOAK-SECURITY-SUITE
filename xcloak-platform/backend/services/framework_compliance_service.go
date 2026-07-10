package services

import (
	"xcloak-platform/database"
	"xcloak-platform/models"
)

// ── Framework control definitions ──────────────────────────────────────────
// Each control specifies what evidence proves coverage in XCloak's data model.

type controlDef struct {
	Ref      string
	Title    string
	Category string
	Severity string
	// Evidence check functions return (evidenceCount, source string)
	check func(tenantID int) (int, string)
}

var cisV8Controls = []controlDef{
	{Ref: "CIS-1.1", Title: "Establish and Maintain Detailed Enterprise Asset Inventory", Category: "Asset Management", Severity: "high",
		check: func(tid int) (int, string) { return countAssets(tid), "assets" }},
	{Ref: "CIS-2.1", Title: "Establish and Maintain a Software Inventory", Category: "Software Inventory", Severity: "medium",
		check: func(tid int) (int, string) { return countAgentsWithPackages(tid), "agent_packages" }},
	{Ref: "CIS-4.1", Title: "Establish and Maintain a Secure Configuration Process", Category: "Secure Configuration", Severity: "high",
		check: func(tid int) (int, string) { return countFirewallRules(tid), "firewall_rules" }},
	{Ref: "CIS-5.1", Title: "Establish and Maintain an Inventory of Accounts", Category: "Account Management", Severity: "high",
		check: func(tid int) (int, string) { return countAgentsWithUsers(tid), "agent_users" }},
	{Ref: "CIS-6.1", Title: "Establish an Access Granting Process", Category: "Access Control", Severity: "critical",
		check: func(tid int) (int, string) { return countRBACRoles(tid), "rbac_roles" }},
	{Ref: "CIS-7.1", Title: "Establish and Maintain a Vulnerability Management Process", Category: "Vulnerability Management", Severity: "critical",
		check: func(tid int) (int, string) { return countVulns(tid), "vulnerabilities" }},
	{Ref: "CIS-8.1", Title: "Establish and Maintain an Audit Log Management Process", Category: "Audit Log Management", Severity: "high",
		check: func(tid int) (int, string) { return countLogs(tid), "audit_logs" }},
	{Ref: "CIS-9.1", Title: "Ensure Use of Only Fully Supported Browsers and Email Clients", Category: "Email & Web Browser", Severity: "medium",
		check: func(tid int) (int, string) { return countSigmaByTactic(tid, "phishing"), "sigma_rules" }},
	{Ref: "CIS-10.1", Title: "Deploy and Maintain Anti-Malware Software", Category: "Malware Defenses", Severity: "critical",
		check: func(tid int) (int, string) { return countYARAActive(tid), "yara_rules" }},
	{Ref: "CIS-11.1", Title: "Establish and Maintain a Data Recovery Practice", Category: "Data Recovery", Severity: "medium",
		check: func(tid int) (int, string) { return countForensicCollections(tid), "dfir_collections" }},
	{Ref: "CIS-12.1", Title: "Ensure Network Infrastructure is Up-to-Date", Category: "Network Infrastructure Management", Severity: "high",
		check: func(tid int) (int, string) { return countFirewallRules(tid), "firewall_rules" }},
	{Ref: "CIS-13.1", Title: "Centralize Security Event Alerting", Category: "Network Monitoring", Severity: "critical",
		check: func(tid int) (int, string) { return countAlerts(tid), "alerts" }},
	{Ref: "CIS-14.1", Title: "Establish and Maintain a Security Awareness Program", Category: "Security Awareness", Severity: "medium",
		check: func(tid int) (int, string) { return countUEBAEvents(tid), "ueba_events" }},
	{Ref: "CIS-16.1", Title: "Establish and Maintain an Incident Response Process", Category: "Incident Response", Severity: "critical",
		check: func(tid int) (int, string) { return countIncidents(tid), "incidents" }},
	{Ref: "CIS-17.1", Title: "Designate Personnel to Manage Incident Handling", Category: "Incident Response", Severity: "high",
		check: func(tid int) (int, string) { return countPlaybooks(tid), "playbooks" }},
	{Ref: "CIS-18.1", Title: "Establish and Maintain a Penetration Testing Program", Category: "Penetration Testing", Severity: "medium",
		check: func(tid int) (int, string) { return countHuntRuns(tid), "hunt_workbench" }},
}

var nistCSFControls = []controlDef{
	{Ref: "NIST-ID.AM-1", Title: "Physical devices and systems are inventoried", Category: "Identify", Severity: "high",
		check: func(tid int) (int, string) { return countAssets(tid), "assets" }},
	{Ref: "NIST-ID.RA-1", Title: "Asset vulnerabilities are identified and documented", Category: "Identify", Severity: "critical",
		check: func(tid int) (int, string) { return countVulns(tid), "vulnerabilities" }},
	{Ref: "NIST-PR.AC-1", Title: "Identities and credentials are managed", Category: "Protect", Severity: "critical",
		check: func(tid int) (int, string) { return countRBACRoles(tid), "rbac_roles" }},
	{Ref: "NIST-PR.DS-1", Title: "Data-at-rest is protected", Category: "Protect", Severity: "high",
		check: func(tid int) (int, string) { return countEncryptionControls(tid), "api_keys" }},
	{Ref: "NIST-PR.IP-1", Title: "A baseline config is created for IT systems", Category: "Protect", Severity: "high",
		check: func(tid int) (int, string) { return countFirewallRules(tid), "firewall_rules" }},
	{Ref: "NIST-DE.AE-1", Title: "A baseline of network operations is established", Category: "Detect", Severity: "high",
		check: func(tid int) (int, string) { return countNetworkBaselines(tid), "nba_baselines" }},
	{Ref: "NIST-DE.CM-1", Title: "The network is monitored to detect potential events", Category: "Detect", Severity: "critical",
		check: func(tid int) (int, string) { return countAgents(tid), "agents" }},
	{Ref: "NIST-DE.CM-7", Title: "Monitoring for unauthorized personnel, connections, devices", Category: "Detect", Severity: "critical",
		check: func(tid int) (int, string) { return countSigmaRules(tid), "sigma_rules" }},
	{Ref: "NIST-RS.RP-1", Title: "Response plan is executed during or after an incident", Category: "Respond", Severity: "critical",
		check: func(tid int) (int, string) { return countPlaybooks(tid), "playbooks" }},
	{Ref: "NIST-RS.CO-2", Title: "Incidents are reported consistent with criteria", Category: "Respond", Severity: "high",
		check: func(tid int) (int, string) { return countIncidents(tid), "incidents" }},
	{Ref: "NIST-RC.RP-1", Title: "Recovery plan is executed during or after incident", Category: "Recover", Severity: "high",
		check: func(tid int) (int, string) { return countForensicCollections(tid), "dfir_collections" }},
}

var pciDSSControls = []controlDef{
	{Ref: "PCI-1.1", Title: "Establish firewall and router configuration standards", Category: "Network Security", Severity: "critical",
		check: func(tid int) (int, string) { return countFirewallRules(tid), "firewall_rules" }},
	{Ref: "PCI-2.1", Title: "Do not use vendor-supplied defaults for system passwords", Category: "Secure Defaults", Severity: "critical",
		check: func(tid int) (int, string) { return countSigmaByTactic(tid, "credential_access"), "sigma_rules" }},
	{Ref: "PCI-5.1", Title: "Deploy anti-virus software on all systems", Category: "Malware Protection", Severity: "critical",
		check: func(tid int) (int, string) { return countYARAActive(tid), "yara_rules" }},
	{Ref: "PCI-6.1", Title: "Protect systems against known vulnerabilities", Category: "Vulnerability Management", Severity: "critical",
		check: func(tid int) (int, string) { return countVulns(tid), "vulnerabilities" }},
	{Ref: "PCI-7.1", Title: "Restrict access to system components to only those who need it", Category: "Access Control", Severity: "critical",
		check: func(tid int) (int, string) { return countRBACRoles(tid), "rbac_roles" }},
	{Ref: "PCI-10.1", Title: "Implement audit trails to link access to individual users", Category: "Audit Logging", Severity: "critical",
		check: func(tid int) (int, string) { return countLogs(tid), "audit_logs" }},
	{Ref: "PCI-10.6", Title: "Review logs and security events daily", Category: "Audit Logging", Severity: "high",
		check: func(tid int) (int, string) { return countAlerts(tid), "alerts" }},
	{Ref: "PCI-11.2", Title: "Run internal and external network vulnerability scans", Category: "Security Testing", Severity: "high",
		check: func(tid int) (int, string) { return countVulns(tid), "vulnerabilities" }},
	{Ref: "PCI-12.10", Title: "Implement an incident response plan", Category: "Incident Response", Severity: "critical",
		check: func(tid int) (int, string) { return countPlaybooks(tid), "playbooks" }},
}

// ── Assessment ─────────────────────────────────────────────────────────────

var frameworkDefs = map[string][]controlDef{
	"CIS":     cisV8Controls,
	"NIST":    nistCSFControls,
	"PCI-DSS": pciDSSControls,
}

// AssessFramework computes coverage for all controls of a given framework.
func AssessFramework(framework string, tenantID int) (models.FrameworkAssessment, error) {
	defs, ok := frameworkDefs[framework]
	if !ok {
		return models.FrameworkAssessment{}, nil
	}

	var result models.FrameworkAssessment
	result.Framework = framework

	for _, def := range defs {
		evidenceCount, source := def.check(tenantID)
		status, score := coverageStatus(evidenceCount)
		result.Controls = append(result.Controls, models.ControlCoverage{
			ControlRef:     def.Ref,
			Framework:      framework,
			Title:          def.Title,
			Category:       def.Category,
			Severity:       def.Severity,
			Status:         status,
			CoverageScore:  score,
			EvidenceCount:  evidenceCount,
			EvidenceSource: source,
		})
		result.TotalControls++
		switch status {
		case "covered":
			result.Covered++
		case "partial":
			result.Partial++
		default:
			result.Gaps++
		}
	}

	if result.TotalControls > 0 {
		total := 0
		for _, c := range result.Controls {
			total += c.CoverageScore
		}
		result.OverallScore = total / result.TotalControls
	}
	return result, nil
}

// AssessAllFrameworks returns assessments for CIS, NIST, and PCI-DSS.
func AssessAllFrameworks(tenantID int) []models.FrameworkAssessment {
	var out []models.FrameworkAssessment
	for _, fw := range []string{"CIS", "NIST", "PCI-DSS"} {
		a, _ := AssessFramework(fw, tenantID)
		out = append(out, a)
	}
	return out
}

// ── Coverage helpers ────────────────────────────────────────────────────────

func coverageStatus(count int) (string, int) {
	switch {
	case count == 0:
		return "gap", 0
	case count < 5:
		return "partial", 40 + count*5
	default:
		score := 70 + count
		if score > 100 {
			score = 100
		}
		return "covered", score
	}
}

// ── Evidence counters ────────────────────────────────────────────────────────

func countAssets(tid int) int {
	var n int
	database.DB.QueryRow(`SELECT COUNT(*) FROM assets WHERE tenant_id=$1`, tid).Scan(&n)
	return n
}
func countAgents(tid int) int {
	var n int
	database.DB.QueryRow(`SELECT COUNT(*) FROM agents WHERE tenant_id=$1`, tid).Scan(&n)
	return n
}
func countVulns(tid int) int {
	var n int
	database.DB.QueryRow(`SELECT COUNT(*) FROM vulnerabilities WHERE tenant_id=$1`, tid).Scan(&n)
	return n
}
func countFirewallRules(tid int) int {
	var n int
	database.DB.QueryRow(`SELECT COUNT(*) FROM firewall_rules WHERE tenant_id=$1`, tid).Scan(&n)
	return n
}
func countAlerts(tid int) int {
	var n int
	database.DB.QueryRow(`SELECT COUNT(*) FROM alerts WHERE tenant_id=$1 AND created_at>NOW()-INTERVAL '30 days'`, tid).Scan(&n)
	return n
}
func countIncidents(tid int) int {
	var n int
	database.DB.QueryRow(`SELECT COUNT(*) FROM incidents WHERE tenant_id=$1`, tid).Scan(&n)
	return n
}
func countPlaybooks(tid int) int {
	var n int
	database.DB.QueryRow(`SELECT COUNT(*) FROM playbooks WHERE tenant_id=$1 AND is_active=true`, tid).Scan(&n)
	return n
}
func countSigmaRules(tid int) int {
	var n int
	database.DB.QueryRow(`SELECT COUNT(*) FROM sigma_rules WHERE tenant_id=$1 AND enabled=true`, tid).Scan(&n)
	return n
}
func countSigmaByTactic(tid int, tactic string) int {
	var n int
	database.DB.QueryRow(`SELECT COUNT(*) FROM sigma_rules WHERE tenant_id=$1 AND enabled=true AND tags ILIKE '%' || $2 || '%'`, tid, tactic).Scan(&n)
	return n
}
func countYARAActive(tid int) int {
	var n int
	database.DB.QueryRow(`SELECT COUNT(*) FROM yara_rules WHERE tenant_id=$1 AND enabled=true`, tid).Scan(&n)
	return n
}
func countLogs(tid int) int {
	var n int
	database.DB.QueryRow(`SELECT COUNT(*) FROM logs WHERE tenant_id=$1 AND collected_at>NOW()-INTERVAL '30 days'`, tid).Scan(&n)
	return n
}
func countRBACRoles(tid int) int {
	var n int
	database.DB.QueryRow(`SELECT COUNT(*) FROM roles WHERE tenant_id=$1`, tid).Scan(&n)
	return n
}
func countUEBAEvents(tid int) int {
	var n int
	database.DB.QueryRow(`SELECT COUNT(*) FROM ueba_events WHERE tenant_id=$1 AND timestamp>NOW()-INTERVAL '30 days'`, tid).Scan(&n)
	return n
}
func countHuntRuns(tid int) int {
	var n int
	database.DB.QueryRow(`SELECT COUNT(*) FROM hunt_runs WHERE tenant_id=$1`, tid).Scan(&n)
	return n
}
func countNetworkBaselines(tid int) int {
	var n int
	database.DB.QueryRow(`SELECT COUNT(DISTINCT agent_id) FROM network_baselines WHERE tenant_id=$1`, tid).Scan(&n)
	return n
}
func countForensicCollections(tid int) int {
	var n int
	database.DB.QueryRow(`SELECT COUNT(*) FROM forensic_collections WHERE tenant_id=$1`, tid).Scan(&n)
	return n
}
func countAgentsWithPackages(tid int) int {
	// Agents that have had collect_packages task completed
	var n int
	database.DB.QueryRow(`SELECT COUNT(DISTINCT agent_id) FROM agent_tasks WHERE tenant_id=$1 AND task_type='collect_packages' AND status='completed'`, tid).Scan(&n)
	return n
}
func countAgentsWithUsers(tid int) int {
	var n int
	database.DB.QueryRow(`SELECT COUNT(DISTINCT agent_id) FROM agent_tasks WHERE tenant_id=$1 AND task_type='collect_users' AND status='completed'`, tid).Scan(&n)
	return n
}
func countEncryptionControls(tid int) int {
	var n int
	database.DB.QueryRow(`SELECT COUNT(*) FROM api_keys WHERE tenant_id=$1 AND is_active=true`, tid).Scan(&n)
	return n
}
