package services

import (
	"log"
	"math"
	"strings"
	"time"

	"xcloak-platform/database"
)

// PatchSLADays maps severity to expected patch turnaround.
var PatchSLADays = map[string]int{
	"critical": 7,
	"high":     30,
	"medium":   90,
	"low":      180,
}

// ComputeVulnPriorityScore scores a vulnerability 0–1000.
//
// Breakdown:
//   CVSS (0-10)         → ×10  =    0–100
//   EPSS (0-1)          → ×200 =    0–200
//   KEV                 →          +300
//   KEV ransomware      →          +100
//   Asset criticality   →   0/25/50/100/150
//   Agent risk bonus    →    0/25/50
func ComputeVulnPriorityScore(cvss, epss float64, isKEV, isKEVRansomware bool, assetCriticality string, agentRiskScore int) int {
	score := cvss*10 + epss*200
	if isKEV {
		score += 300
	}
	if isKEVRansomware {
		score += 100
	}
	switch assetCriticality {
	case "critical":
		score += 150
	case "high":
		score += 100
	case "medium":
		score += 50
	case "low":
		score += 25
	}
	if agentRiskScore >= 70 {
		score += 50
	} else if agentRiskScore >= 40 {
		score += 25
	}
	return int(math.Round(math.Min(score, 1000)))
}

// RefreshVulnPriorityScores recomputes and persists priority_score + patch_sla_days
// for every open vulnerability in the given tenant. Run on demand and on schedule.
func RefreshVulnPriorityScores(tenantID int) {
	rows, err := database.DB.Query(`
		SELECT v.id, v.severity, v.cvss_score, v.epss_score, v.is_kev, v.kev_ransomware,
		       COALESCE(a.criticality, 'medium'), COALESCE(ag.risk_score, 0)
		FROM vulnerabilities v
		LEFT JOIN agents ag ON ag.id = v.agent_id
		LEFT JOIN assets a  ON a.agent_id = v.agent_id AND a.tenant_id = v.tenant_id
		WHERE v.tenant_id = $1 AND v.patch_status IN ('open','in_progress')`, tenantID)
	if err != nil {
		return
	}
	defer rows.Close()

	type row struct {
		id, sla, score int
	}
	updates := []row{}
	for rows.Next() {
		var id int
		var severity, criticality string
		var cvss, epss float64
		var isKEV, isRansomware bool
		var riskScore int
		rows.Scan(&id, &severity, &cvss, &epss, &isKEV, &isRansomware, &criticality, &riskScore)
		score := ComputeVulnPriorityScore(cvss, epss, isKEV, isRansomware, criticality, riskScore)
		sla := PatchSLADays[severity]
		if sla == 0 {
			sla = 90
		}
		updates = append(updates, row{id, sla, score})
	}
	rows.Close()

	for _, u := range updates {
		database.DB.Exec(`
			UPDATE vulnerabilities SET priority_score=$1, patch_sla_days=$2
			WHERE id=$3`, u.score, u.sla, u.id)
	}
}

type VulnQueueItem struct {
	ID               int     `json:"id"`
	AgentID          int     `json:"agent_id"`
	Hostname         string  `json:"hostname"`
	CVE              string  `json:"cve_id"`
	PackageName      string  `json:"package_name"`
	PackageVersion   string  `json:"package_version"`
	Severity         string  `json:"severity"`
	CVSSScore        float64 `json:"cvss_score"`
	EPSSScore        float64 `json:"epss_score"`
	IsKEV            bool    `json:"is_kev"`
	IsKEVRansomware  bool    `json:"kev_ransomware"`
	PriorityScore    int     `json:"priority_score"`
	PatchStatus      string  `json:"patch_status"`
	PatchNotes       string  `json:"patch_notes"`
	PatchSLADays     *int    `json:"patch_sla_days"`
	PatchedAt        *string `json:"patched_at"`
	AssetCriticality string  `json:"asset_criticality"`
	Name             string  `json:"name"`
	Remediation      string  `json:"remediation"`
}

func QueryVulnPriorityQueue(tenantID int, statuses string, limit, offset int) ([]VulnQueueItem, error) {
	// Build IN clause from comma-separated status filter
	var inClause string
	var args []interface{}
	args = append(args, tenantID)
	parts := splitCSVStatuses(statuses)
	if len(parts) == 0 {
		parts = []string{"open", "in_progress"}
	}
	for i, p := range parts {
		if i == 0 {
			inClause = "$2"
		} else {
			inClause += ", $" + itoa(i+2)
		}
		args = append(args, p)
	}
	args = append(args, limit, offset)
	limitN := len(args) - 1
	offsetN := len(args)

	rows, err := database.DB.Query(`
		SELECT v.id, COALESCE(v.agent_id,0), COALESCE(ag.hostname,''), v.cve_id, v.package_name, v.package_version,
		       v.severity, v.cvss_score, v.epss_score, v.is_kev, v.kev_ransomware, v.priority_score,
		       v.patch_status, v.patch_notes, v.patch_sla_days,
		       TO_CHAR(v.patched_at, 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
		       COALESCE(a.criticality, 'medium'), v.name, v.remediation
		FROM vulnerabilities v
		LEFT JOIN agents ag ON ag.id = v.agent_id
		LEFT JOIN assets a  ON a.agent_id = v.agent_id AND a.tenant_id = v.tenant_id
		WHERE v.tenant_id=$1 AND v.patch_status IN (`+inClause+`)
		ORDER BY v.priority_score DESC, v.cvss_score DESC
		LIMIT $`+itoa(limitN)+` OFFSET $`+itoa(offsetN),
		args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []VulnQueueItem{}
	for rows.Next() {
		var item VulnQueueItem
		rows.Scan(&item.ID, &item.AgentID, &item.Hostname, &item.CVE, &item.PackageName, &item.PackageVersion,
			&item.Severity, &item.CVSSScore, &item.EPSSScore, &item.IsKEV, &item.IsKEVRansomware,
			&item.PriorityScore, &item.PatchStatus, &item.PatchNotes, &item.PatchSLADays, &item.PatchedAt,
			&item.AssetCriticality, &item.Name, &item.Remediation)
		out = append(out, item)
	}
	return out, nil
}

func UpdateVulnPatchStatus(id, tenantID int, status, notes string) error {
	var patchedAt interface{}
	if status == "patched" {
		now := "NOW()"
		_ = now
		_, err := database.DB.Exec(`
			UPDATE vulnerabilities SET patch_status=$1, patch_notes=$2, patched_at=NOW()
			WHERE id=$3 AND tenant_id=$4`, status, notes, id, tenantID)
		return err
	}
	_ = patchedAt
	_, err := database.DB.Exec(`
		UPDATE vulnerabilities SET patch_status=$1, patch_notes=$2, patched_at=NULL
		WHERE id=$3 AND tenant_id=$4`, status, notes, id, tenantID)
	return err
}

func splitCSVStatuses(s string) []string {
	out := []string{}
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func itoa(n int) string {
	s := ""
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	if s == "" {
		return "0"
	}
	return s
}

// StartVulnPriorityScheduler refreshes scores every 6 hours and on startup.
func StartVulnPriorityScheduler() {
	go func() {
		run := func() {
			tenants, err := database.DB.Query(`SELECT id FROM tenants WHERE is_active=true`)
			if err != nil {
				return
			}
			defer tenants.Close()
			for tenants.Next() {
				var id int
				tenants.Scan(&id)
				RefreshVulnPriorityScores(id)
			}
		}
		run()
		ticker := time.NewTicker(6 * time.Hour)
		for range ticker.C {
			run()
		}
	}()
	log.Println("[VulnPriority] score scheduler started (6h interval)")
}
