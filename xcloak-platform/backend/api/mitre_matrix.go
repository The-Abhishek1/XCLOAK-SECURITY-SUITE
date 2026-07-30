package api

// Shared MITRE ATT&CK coverage matrix, extracted from GetHuntMITRECoverage
// (Hunt Workbench) so GetThreatHuntMITRECoverage (Threat Hunt) can report
// coverage against the same tactic/technique set without duplicating it —
// each caller supplies its own coveredSet (technique ID -> hit/run count)
// computed from whatever data model backs it.

type mitreTechnique struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Status   string `json:"status"` // covered | frequently_hunted | untested
	RunCount int    `json:"run_count"`
}

type mitreTactic struct {
	ID         string           `json:"id"`
	Name       string           `json:"name"`
	Techniques []mitreTechnique `json:"techniques"`
	Coverage   int              `json:"coverage"` // percentage
}

var mitreCoverageMatrix = []struct {
	ID         string
	Name       string
	Techniques []struct{ ID, Name string }
}{
	{"TA0001", "Initial Access", []struct{ ID, Name string }{
		{"T1566", "Phishing"}, {"T1190", "Exploit Public-Facing App"}, {"T1195", "Supply Chain Compromise"},
		{"T1078", "Valid Accounts"}, {"T1199", "Trusted Relationship"},
	}},
	{"TA0002", "Execution", []struct{ ID, Name string }{
		{"T1059", "Command & Scripting Interpreter"}, {"T1059.001", "PowerShell"}, {"T1204", "User Execution"},
		{"T1053", "Scheduled Task/Job"}, {"T1569", "System Services"},
	}},
	{"TA0003", "Persistence", []struct{ ID, Name string }{
		{"T1547", "Boot/Logon Autostart"}, {"T1098", "Account Manipulation"}, {"T1136", "Create Account"},
		{"T1505", "Server Software Component"}, {"T1053", "Scheduled Task/Job"},
	}},
	{"TA0004", "Privilege Escalation", []struct{ ID, Name string }{
		{"T1548", "Abuse Elevation Control"}, {"T1134", "Access Token Manipulation"}, {"T1068", "Exploit Vuln"},
		{"T1055", "Process Injection"}, {"T1078", "Valid Accounts"},
	}},
	{"TA0005", "Defense Evasion", []struct{ ID, Name string }{
		{"T1027", "Obfuscated Files/Info"}, {"T1055", "Process Injection"}, {"T1036", "Masquerading"},
		{"T1070", "Indicator Removal"}, {"T1562", "Impair Defenses"},
	}},
	{"TA0006", "Credential Access", []struct{ ID, Name string }{
		{"T1003", "OS Credential Dumping"}, {"T1003.001", "LSASS Memory"}, {"T1110", "Brute Force"},
		{"T1552", "Unsecured Credentials"}, {"T1558", "Steal/Forge Kerberos Tickets"},
	}},
	{"TA0007", "Discovery", []struct{ ID, Name string }{
		{"T1046", "Network Service Discovery"}, {"T1082", "System Info Discovery"}, {"T1083", "File Discovery"},
		{"T1057", "Process Discovery"}, {"T1016", "System Network Config"},
	}},
	{"TA0008", "Lateral Movement", []struct{ ID, Name string }{
		{"T1021", "Remote Services"}, {"T1021.001", "RDP"}, {"T1021.002", "SMB/Admin Shares"},
		{"T1550", "Use Alternate Auth"}, {"T1570", "Lateral Tool Transfer"},
	}},
	{"TA0009", "Collection", []struct{ ID, Name string }{
		{"T1560", "Archive Collected Data"}, {"T1115", "Clipboard Data"}, {"T1056", "Input Capture"},
		{"T1213", "Data from Info Repositories"}, {"T1039", "Data from Network Drive"},
	}},
	{"TA0011", "Command & Control", []struct{ ID, Name string }{
		{"T1071", "App Layer Protocol"}, {"T1071.001", "Web Protocols"}, {"T1573", "Encrypted Channel"},
		{"T1008", "Fallback Channels"}, {"T1095", "Non-App Layer Protocol"},
	}},
	{"TA0010", "Exfiltration", []struct{ ID, Name string }{
		{"T1048", "Exfiltration Over Alt Protocol"}, {"T1041", "Exfil Over C2"}, {"T1052", "Exfil Over Physical Medium"},
		{"T1011", "Exfil Over Other Network"}, {"T1030", "Data Transfer Size Limits"},
	}},
	{"TA0040", "Impact", []struct{ ID, Name string }{
		{"T1485", "Data Destruction"}, {"T1489", "Service Stop"}, {"T1486", "Data Encrypted for Impact"},
		{"T1490", "Inhibit System Recovery"}, {"T1495", "Firmware Corruption"},
	}},
}

// buildMITRECoverage renders coveredSet (technique ID -> weighted hit count)
// against the shared matrix into the tactics/techniques/overall-coverage
// shape both hunt pages return.
func buildMITRECoverage(coveredSet map[string]int) (tactics []mitreTactic, overallPct, coveredCount, totalCount int) {
	tactics = make([]mitreTactic, 0, len(mitreCoverageMatrix))
	for _, tac := range mitreCoverageMatrix {
		techs := make([]mitreTechnique, 0, len(tac.Techniques))
		covered := 0
		for _, tech := range tac.Techniques {
			cnt := coveredSet[tech.ID]
			status := "untested"
			if cnt >= 5 {
				status = "frequently_hunted"
				covered++
			} else if cnt > 0 {
				status = "covered"
				covered++
			}
			techs = append(techs, mitreTechnique{ID: tech.ID, Name: tech.Name, Status: status, RunCount: cnt})
		}
		coverage := 0
		if len(tac.Techniques) > 0 {
			coverage = covered * 100 / len(tac.Techniques)
		}
		tactics = append(tactics, mitreTactic{ID: tac.ID, Name: tac.Name, Techniques: techs, Coverage: coverage})
	}

	totalCount = len(mitreCoverageMatrix) * 5
	for range coveredSet {
		coveredCount++
	}
	if totalCount > 0 {
		overallPct = coveredCount * 100 / totalCount
	}
	return tactics, overallPct, coveredCount, totalCount
}
