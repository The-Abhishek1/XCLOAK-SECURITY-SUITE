package services

import (
	"encoding/json"
	"fmt"

	"xcloak-platform/database"
	"xcloak-platform/repositories"
)

type ComplianceCheck struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Category    string `json:"category"`
	Passed      bool   `json:"passed"`
	Detail      string `json:"detail"`
	Severity    string `json:"severity"` // critical, high, medium, low
}

type FrameworkScore struct {
	Framework string            `json:"framework"`
	Score     int               `json:"score"`
	Passed    int               `json:"passed"`
	Failed    int               `json:"failed"`
	Checks    []ComplianceCheck `json:"checks"`
}

// ComputeAllFrameworkScores computes scores for all 4 frameworks (scoped to
// tenantID's data) and persists them.
func ComputeAllFrameworkScores(reportID int, tenantID int) ([]FrameworkScore, error) {
	snapshot := buildDataSnapshot(tenantID)

	frameworks := []string{"SOC2", "NIST", "PCI-DSS", "ISO27001"}
	scores := []FrameworkScore{}

	for _, fw := range frameworks {
		fs := computeFrameworkScore(fw, snapshot)
		scores = append(scores, fs)

		checksJSON, _ := json.Marshal(fs.Checks)
		database.DB.Exec(`
			INSERT INTO compliance_scores (report_id, framework, score, passed, failed, checks, tenant_id)
			VALUES ($1,$2,$3,$4,$5,$6,$7)
		`, reportID, fw, fs.Score, fs.Passed, fs.Failed, checksJSON, tenantID)
	}

	return scores, nil
}

// GetFrameworkScores returns existing scores for a report, scoped to
// tenantID.
func GetFrameworkScores(reportID int, tenantID int) ([]FrameworkScore, error) {
	rows, err := database.DB.Query(`
		SELECT framework, score, passed, failed, checks
		FROM compliance_scores WHERE report_id=$1 AND tenant_id=$2 ORDER BY framework
	`, reportID, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	scores := []FrameworkScore{}
	for rows.Next() {
		var fs FrameworkScore
		checksJSON := []byte{}
		if err := rows.Scan(&fs.Framework, &fs.Score, &fs.Passed, &fs.Failed, &checksJSON); err == nil {
			json.Unmarshal(checksJSON, &fs.Checks)
			scores = append(scores, fs)
		}
	}
	return scores, nil
}

type platformSnapshot struct {
	agentCount     int
	onlineAgents   int
	mfaEnabled     bool // simplified: check if multiple users exist
	critAlerts     int
	openIncidents  int
	critVulns      int
	fim            bool // FIM has baseline entries
	auditEnabled   bool // audit_logs table has entries
	iocCount       int
	sigmaRules     int
	firewallRules  int
	supprRules     int
	yaraRules      int
	complianceReports int
	unresolvedIncidents int
}

func buildDataSnapshot(tenantID int) platformSnapshot {
	s := platformSnapshot{}

	agents, _ := repositories.GetAgents(tenantID)
	s.agentCount = len(agents)
	for _, a := range agents {
		if a.Status == "online" {
			s.onlineAgents++
		}
	}

	alerts, _ := repositories.GetAlerts(tenantID)
	for _, a := range alerts {
		if a.Severity == "critical" {
			s.critAlerts++
		}
	}

	incidents, _ := repositories.GetIncidents(tenantID)
	for _, i := range incidents {
		if i.Status == "open" || i.Status == "investigating" {
			s.openIncidents++
			s.unresolvedIncidents++
		}
	}

	vulns, _ := repositories.GetVulnerabilities(tenantID)
	for _, v := range vulns {
		if v.Severity == "critical" {
			s.critVulns++
		}
	}

	iocs, _ := repositories.GetIOCs(tenantID)
	s.iocCount = len(iocs)

	sigma, _ := repositories.GetRules(tenantID)
	s.sigmaRules = len(sigma)

	yara, _ := repositories.GetYaraRules(tenantID)
	s.yaraRules = len(yara)

	var fimCount int
	database.DB.QueryRow(`SELECT COUNT(*) FROM fim_baselines WHERE tenant_id=$1`, tenantID).Scan(&fimCount)
	s.fim = fimCount > 0
	var auditCount int
	database.DB.QueryRow(`SELECT COUNT(*) FROM audit_logs WHERE tenant_id=$1`, tenantID).Scan(&auditCount)
	s.auditEnabled = auditCount > 0
	database.DB.QueryRow(`SELECT COUNT(*) FROM firewall_rules WHERE enabled=TRUE AND tenant_id=$1`, tenantID).Scan(&s.firewallRules)
	database.DB.QueryRow(`SELECT COUNT(*) FROM suppression_rules WHERE enabled=TRUE AND tenant_id=$1`, tenantID).Scan(&s.supprRules)
	database.DB.QueryRow(`SELECT COUNT(*) FROM compliance_reports WHERE tenant_id=$1`, tenantID).Scan(&s.complianceReports)

	// MFA proxy: multiple users registered
	var userCount int
	database.DB.QueryRow(`SELECT COUNT(*) FROM users WHERE tenant_id=$1`, tenantID).Scan(&userCount)
	s.mfaEnabled = userCount >= 2

	return s
}

func computeFrameworkScore(framework string, s platformSnapshot) FrameworkScore {
	checks := []ComplianceCheck{}

	switch framework {
	case "SOC2":
		checks = soc2Checks(s)
	case "NIST":
		checks = nistChecks(s)
	case "PCI-DSS":
		checks = pciChecks(s)
	case "ISO27001":
		checks = iso27001Checks(s)
	}

	passed, failed := 0, 0
	for _, c := range checks {
		if c.Passed {
			passed++
		} else {
			failed++
		}
	}

	score := 0
	if passed+failed > 0 {
		score = (passed * 100) / (passed + failed)
	}

	return FrameworkScore{
		Framework: framework,
		Score:     score,
		Passed:    passed,
		Failed:    failed,
		Checks:    checks,
	}
}

func soc2Checks(s platformSnapshot) []ComplianceCheck {
	return []ComplianceCheck{
		{ID: "soc2-1", Name: "Agent monitoring active", Category: "Availability",
			Passed: s.onlineAgents > 0, Severity: "critical",
			Detail: fmt.Sprintf("%d/%d agents online", s.onlineAgents, s.agentCount)},
		{ID: "soc2-2", Name: "Audit logging enabled", Category: "Confidentiality",
			Passed: s.auditEnabled, Severity: "high",
			Detail: "Audit log table has entries"},
		{ID: "soc2-3", Name: "No unresolved critical alerts", Category: "Integrity",
			Passed: s.critAlerts == 0, Severity: "high",
			Detail: fmt.Sprintf("%d critical alerts", s.critAlerts)},
		{ID: "soc2-4", Name: "No open incidents", Category: "Integrity",
			Passed: s.openIncidents == 0, Severity: "medium",
			Detail: fmt.Sprintf("%d open incidents", s.openIncidents)},
		{ID: "soc2-5", Name: "File integrity monitoring", Category: "Integrity",
			Passed: s.fim, Severity: "medium",
			Detail: "FIM baseline established"},
		{ID: "soc2-6", Name: "Intrusion detection rules", Category: "Security",
			Passed: s.sigmaRules >= 5, Severity: "high",
			Detail: fmt.Sprintf("%d sigma rules active", s.sigmaRules)},
		{ID: "soc2-7", Name: "Multi-user access control", Category: "Security",
			Passed: s.mfaEnabled, Severity: "medium",
			Detail: "Multiple user accounts configured"},
		{ID: "soc2-8", Name: "Firewall rules enforced", Category: "Availability",
			Passed: s.firewallRules > 0, Severity: "high",
			Detail: fmt.Sprintf("%d active firewall rules", s.firewallRules)},
	}
}

func nistChecks(s platformSnapshot) []ComplianceCheck {
	return []ComplianceCheck{
		{ID: "nist-1", Name: "Asset inventory (IDENTIFY)", Category: "Identify",
			Passed: s.agentCount > 0, Severity: "high",
			Detail: fmt.Sprintf("%d endpoints inventoried", s.agentCount)},
		{ID: "nist-2", Name: "Vulnerability management (IDENTIFY)", Category: "Identify",
			Passed: s.critVulns == 0, Severity: "critical",
			Detail: fmt.Sprintf("%d critical vulnerabilities unpatched", s.critVulns)},
		{ID: "nist-3", Name: "IOC threat feed (PROTECT)", Category: "Protect",
			Passed: s.iocCount >= 10, Severity: "medium",
			Detail: fmt.Sprintf("%d IOCs in database", s.iocCount)},
		{ID: "nist-4", Name: "Access control policy (PROTECT)", Category: "Protect",
			Passed: s.firewallRules > 0, Severity: "high",
			Detail: fmt.Sprintf("%d firewall rules configured", s.firewallRules)},
		{ID: "nist-5", Name: "Continuous monitoring (DETECT)", Category: "Detect",
			Passed: s.sigmaRules >= 10, Severity: "high",
			Detail: fmt.Sprintf("%d detection rules active", s.sigmaRules)},
		{ID: "nist-6", Name: "Malware detection (DETECT)", Category: "Detect",
			Passed: s.yaraRules > 0, Severity: "high",
			Detail: fmt.Sprintf("%d YARA rules configured", s.yaraRules)},
		{ID: "nist-7", Name: "Incident response (RESPOND)", Category: "Respond",
			Passed: s.unresolvedIncidents == 0, Severity: "critical",
			Detail: fmt.Sprintf("%d unresolved incidents", s.unresolvedIncidents)},
		{ID: "nist-8", Name: "Audit trail (RECOVER)", Category: "Recover",
			Passed: s.auditEnabled, Severity: "medium",
			Detail: "Audit logs maintained"},
		{ID: "nist-9", Name: "Alert suppression policy (DETECT)", Category: "Detect",
			Passed: s.supprRules > 0, Severity: "low",
			Detail: fmt.Sprintf("%d active suppression rules", s.supprRules)},
	}
}

func pciChecks(s platformSnapshot) []ComplianceCheck {
	return []ComplianceCheck{
		{ID: "pci-1", Name: "Firewall installed (Req 1)", Category: "Network",
			Passed: s.firewallRules > 0, Severity: "critical",
			Detail: fmt.Sprintf("%d firewall rules", s.firewallRules)},
		{ID: "pci-2", Name: "No critical vulnerabilities (Req 6)", Category: "Vulnerability",
			Passed: s.critVulns == 0, Severity: "critical",
			Detail: fmt.Sprintf("%d critical CVEs", s.critVulns)},
		{ID: "pci-3", Name: "Malware protection (Req 5)", Category: "Malware",
			Passed: s.yaraRules > 0, Severity: "high",
			Detail: fmt.Sprintf("%d YARA rules", s.yaraRules)},
		{ID: "pci-4", Name: "Intrusion detection (Req 11)", Category: "Monitoring",
			Passed: s.sigmaRules >= 5, Severity: "high",
			Detail: fmt.Sprintf("%d sigma detection rules", s.sigmaRules)},
		{ID: "pci-5", Name: "Audit logging (Req 10)", Category: "Audit",
			Passed: s.auditEnabled, Severity: "critical",
			Detail: "Audit trail maintained"},
		{ID: "pci-6", Name: "Security testing (Req 11)", Category: "Testing",
			Passed: s.complianceReports >= 3, Severity: "medium",
			Detail: fmt.Sprintf("%d compliance reports generated", s.complianceReports)},
		{ID: "pci-7", Name: "No open incidents (Req 12)", Category: "Incidents",
			Passed: s.openIncidents == 0, Severity: "high",
			Detail: fmt.Sprintf("%d open incidents", s.openIncidents)},
	}
}

func iso27001Checks(s platformSnapshot) []ComplianceCheck {
	return []ComplianceCheck{
		{ID: "iso-1", Name: "Asset management (A.8)", Category: "Asset Management",
			Passed: s.agentCount > 0, Severity: "medium",
			Detail: fmt.Sprintf("%d assets tracked", s.agentCount)},
		{ID: "iso-2", Name: "Access control (A.9)", Category: "Access Control",
			Passed: s.mfaEnabled && s.firewallRules > 0, Severity: "high",
			Detail: "Multi-user access and firewall configured"},
		{ID: "iso-3", Name: "Cryptography/FIM (A.10)", Category: "Cryptography",
			Passed: s.fim, Severity: "medium",
			Detail: "File integrity monitoring active"},
		{ID: "iso-4", Name: "Operations security (A.12)", Category: "Operations",
			Passed: s.sigmaRules >= 5 && s.yaraRules > 0, Severity: "high",
			Detail: "Detection rules and malware scanning active"},
		{ID: "iso-5", Name: "Incident management (A.16)", Category: "Incident Management",
			Passed: s.openIncidents == 0, Severity: "critical",
			Detail: fmt.Sprintf("%d open incidents", s.openIncidents)},
		{ID: "iso-6", Name: "Vulnerability management (A.12)", Category: "Vulnerability",
			Passed: s.critVulns == 0, Severity: "critical",
			Detail: fmt.Sprintf("%d critical CVEs", s.critVulns)},
		{ID: "iso-7", Name: "Compliance monitoring (A.18)", Category: "Compliance",
			Passed: s.complianceReports >= 1, Severity: "medium",
			Detail: fmt.Sprintf("%d compliance reports generated", s.complianceReports)},
		{ID: "iso-8", Name: "Threat intelligence (A.12)", Category: "Threat Intel",
			Passed: s.iocCount >= 5, Severity: "medium",
			Detail: fmt.Sprintf("%d IOCs in threat feed", s.iocCount)},
	}
}
