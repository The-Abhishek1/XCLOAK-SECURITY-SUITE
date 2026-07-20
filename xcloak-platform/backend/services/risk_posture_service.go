package services

import (
	"encoding/json"
	"fmt"
	"log"
	"math"
	"strings"
	"time"

	"github.com/lib/pq"

	"xcloak-platform/database"
	"xcloak-platform/models"
)

// ComputeRiskPosture calculates a 0-100 risk score for a tenant.
// Higher = worse. Broken into sub-scores by category.
func ComputeRiskPosture(tenantID int) (models.RiskPostureSnapshot, error) {
	snap := models.RiskPostureSnapshot{TenantID: tenantID, SnapshotAt: time.Now()}

	// ── Vuln score (0-30): open critical/high vulns weighted by priority_score ──
	var vulnRaw float64
	database.DB.QueryRow(`
		SELECT COALESCE(SUM(LEAST(priority_score,1000)),0) / GREATEST(COUNT(*),1)
		FROM vulnerabilities
		WHERE tenant_id=$1 AND patch_status IN ('open','in_progress')
		  AND severity IN ('critical','high')`, tenantID,
	).Scan(&vulnRaw)
	snap.VulnScore = int(math.Min(30, vulnRaw/35))

	// ── UEBA score (0-20): avg risk of high-risk users ──
	var uebaRaw float64
	database.DB.QueryRow(`
		SELECT COALESCE(AVG(risk_score),0) FROM user_risk_profiles
		WHERE tenant_id=$1 AND risk_score>=30`, tenantID,
	).Scan(&uebaRaw)
	snap.UEBAScore = int(math.Min(20, uebaRaw/5))

	// ── Alert score (0-30): open, non-snoozed critical/high alerts in last 7d ──
	var criticalOpen, highOpen int
	database.DB.QueryRow(`
		SELECT COUNT(*) FILTER (WHERE severity='critical'),
		       COUNT(*) FILTER (WHERE severity='high')
		FROM alerts WHERE tenant_id=$1 AND status='open'
		  AND (suppressed_until IS NULL OR suppressed_until < NOW())
		  AND created_at > NOW()-INTERVAL '7 days'`, tenantID,
	).Scan(&criticalOpen, &highOpen)
	alertRaw := criticalOpen*5 + highOpen*2
	snap.AlertScore = int(math.Min(30, float64(alertRaw)))

	// ── IOC score (0-20): active high/critical IOC hits in last 30d ──
	var iocHits int
	database.DB.QueryRow(`
		SELECT COUNT(*) FROM alerts
		WHERE tenant_id=$1 AND rule_name='IOC Match'
		  AND severity IN ('critical','high')
		  AND created_at > NOW()-INTERVAL '30 days'`, tenantID,
	).Scan(&iocHits)
	snap.IOCScore = int(math.Min(20, float64(iocHits)*2))

	snap.Score = snap.VulnScore + snap.UEBAScore + snap.AlertScore + snap.IOCScore

	// ── Per-asset breakdown ──
	snap.AssetScores = computeAssetRisks(tenantID)

	// ── Live supplementary detail (snoozed count, identities, exposure, etc) ──
	EnrichRiskPostureLiveData(&snap, tenantID)

	// Persist
	assetJSON, _ := json.Marshal(snap.AssetScores)
	database.DB.QueryRow(`
		INSERT INTO risk_posture_snapshots
		  (tenant_id, score, vuln_score, ueba_score, alert_score, ioc_score, asset_scores)
		VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id`,
		tenantID, snap.Score, snap.VulnScore, snap.UEBAScore, snap.AlertScore, snap.IOCScore, assetJSON,
	).Scan(&snap.ID)

	return snap, nil
}

func computeAssetRisks(tenantID int) []models.AssetRisk {
	rows, err := database.DB.Query(`
		SELECT a.id, a.hostname, a.criticality,
		       COALESCE(v.vuln_count,0), COALESCE(al.alert_count,0)
		FROM assets a
		LEFT JOIN (
			SELECT ag.id as agent_id, COUNT(*) as vuln_count
			FROM agents ag JOIN vulnerabilities v ON v.agent_id=ag.id
			WHERE v.tenant_id=$1 AND v.patch_status='open' AND v.severity IN ('critical','high')
			GROUP BY ag.id
		) v ON v.agent_id=a.agent_id
		LEFT JOIN (
			SELECT agent_id, COUNT(*) as alert_count
			FROM alerts WHERE tenant_id=$1 AND status='open'
			  AND (suppressed_until IS NULL OR suppressed_until < NOW())
			  AND created_at>NOW()-INTERVAL '7 days'
			GROUP BY agent_id
		) al ON al.agent_id=a.agent_id
		WHERE a.tenant_id=$1
		ORDER BY (COALESCE(v.vuln_count,0)*3 + COALESCE(al.alert_count,0)) DESC
		LIMIT 10`, tenantID)
	if err != nil {
		return nil
	}
	defer rows.Close()

	critMap := map[string]int{"critical": 30, "high": 20, "medium": 10, "low": 5, "": 0}
	out := []models.AssetRisk{}
	for rows.Next() {
		var ar models.AssetRisk
		var vulnCount, alertCount int
		rows.Scan(&ar.AssetID, &ar.Hostname, &ar.Criticality, &vulnCount, &alertCount)
		base := critMap[ar.Criticality]
		ar.Score = int(math.Min(100, float64(base+vulnCount*4+alertCount*2)))
		switch {
		case vulnCount > 0:
			ar.TopReason = "Open vulnerabilities"
		case alertCount > 0:
			ar.TopReason = "Active alerts"
		default:
			ar.TopReason = "Asset criticality"
		}
		out = append(out, ar)
	}
	return out
}

// GetRiskPostureHistory returns the last N snapshots for trend display.
func GetRiskPostureHistory(tenantID, limit int) ([]models.RiskPostureSnapshot, error) {
	rows, err := database.DB.Query(`
		SELECT id, tenant_id, score, vuln_score, ueba_score, alert_score, ioc_score,
		       asset_scores::text, snapshot_at
		FROM risk_posture_snapshots
		WHERE tenant_id=$1 ORDER BY snapshot_at DESC LIMIT $2`, tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []models.RiskPostureSnapshot{}
	for rows.Next() {
		var s models.RiskPostureSnapshot
		var assetJSON string
		rows.Scan(&s.ID, &s.TenantID, &s.Score, &s.VulnScore, &s.UEBAScore,
			&s.AlertScore, &s.IOCScore, &assetJSON, &s.SnapshotAt)
		json.Unmarshal([]byte(assetJSON), &s.AssetScores)
		out = append(out, s)
	}
	return out, nil
}

// StartRiskPostureScheduler runs a posture computation every hour for all active tenants.
func StartRiskPostureScheduler() {
	go func() {
		for {
			rows, err := database.DB.Query(`SELECT id FROM tenants WHERE is_active=true`)
			if err == nil {
				for rows.Next() {
					var tid int
					rows.Scan(&tid)
					if _, err := ComputeRiskPosture(tid); err != nil {
						log.Printf("[RiskPosture] tenant %d: %v", tid, err)
					}
				}
				rows.Close()
			}
			time.Sleep(1 * time.Hour)
		}
	}()
}

// ── Live supplementary detail ──────────────────────────────────────────────
//
// These fields back the drill-down sections of the Risk Posture page
// (identities, network exposure, patch backlog, misconfigurations, etc).
// They reflect current state, not a point-in-time score, so — like
// SnoozedAlertCount — they're computed fresh on every read rather than
// persisted to risk_posture_snapshots. EnrichRiskPostureLiveData must be
// called by every code path that returns a snapshot to the frontend
// (GetRiskPosture's cached-snapshot branch included), or these fields come
// back empty even though the score fields are populated.

var eolOperatingSystems = []struct{ pattern, eol string }{
	{"windows 7", "2020-01-14"},
	{"windows server 2008", "2020-01-14"},
	{"windows server 2012", "2023-10-10"},
	{"windows 8", "2016-01-12"},
	{"centos 8", "2021-12-31"},
	{"centos 7", "2024-06-30"},
	{"centos linux 7", "2024-06-30"},
	{"ubuntu 16.04", "2021-04-30"},
	{"ubuntu 18.04", "2023-05-31"},
	{"debian 9", "2022-06-30"},
	{"debian 10", "2024-06-30"},
}

func EnrichRiskPostureLiveData(snap *models.RiskPostureSnapshot, tenantID int) {
	database.DB.QueryRow(`
		SELECT COUNT(*) FROM alerts
		WHERE tenant_id=$1 AND status='open'
		  AND suppressed_until IS NOT NULL AND suppressed_until >= NOW()`, tenantID,
	).Scan(&snap.SnoozedAlertCount)

	snap.UserRisk = computeUserRisk(tenantID)
	snap.HighRiskIdentities = computeHighRiskIdentities(tenantID)
	snap.MissingPatches = computeMissingPatches(tenantID)
	snap.UnsupportedOS = computeUnsupportedOS(tenantID)
	snap.Misconfigurations = computeMisconfigurations(tenantID)
	snap.HighRiskApps = computeHighRiskApps(tenantID)
	snap.InternetExposure = computeInternetExposure(tenantID)
	snap.DepartmentRisk = computeDepartmentRisk(tenantID)
}

func computeUserRisk(tenantID int) []models.UserRisk {
	out := []models.UserRisk{}
	rows, err := database.DB.Query(`
		SELECT username, risk_score, flags, failed_logins, off_hours_events, COALESCE(last_seen_ip,'')
		FROM user_risk_profiles
		WHERE tenant_id=$1
		ORDER BY risk_score DESC LIMIT 20`, tenantID)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var u models.UserRisk
		var flags pq.StringArray
		if rows.Scan(&u.Username, &u.RiskScore, &flags, &u.FailedLogins, &u.OffHours, &u.LastSeenIP) == nil {
			u.Flags = []string(flags)
			if u.Flags == nil {
				u.Flags = []string{}
			}
			out = append(out, u)
		}
	}
	return out
}

func computeHighRiskIdentities(tenantID int) []models.HighRiskIdentity {
	out := []models.HighRiskIdentity{}
	rows, err := database.DB.Query(`
		SELECT identity, identity_type, finding_type, severity, COALESCE(mitre_technique,''), description
		FROM itdr_findings
		WHERE tenant_id=$1 AND status='open'
		ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END
		LIMIT 20`, tenantID)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var h models.HighRiskIdentity
		if rows.Scan(&h.Identity, &h.IdentityType, &h.FindingType, &h.Severity, &h.MitreTechnique, &h.Description) == nil {
			out = append(out, h)
		}
	}
	return out
}

func computeMissingPatches(tenantID int) models.MissingPatches {
	var mp models.MissingPatches
	database.DB.QueryRow(`
		SELECT
			COUNT(*) FILTER (WHERE severity='critical'),
			COUNT(*) FILTER (WHERE severity='high'),
			COUNT(*) FILTER (WHERE severity='medium'),
			COUNT(*),
			COUNT(*) FILTER (WHERE detected_at < NOW() - INTERVAL '30 days')
		FROM vulnerabilities
		WHERE tenant_id=$1 AND patch_status IN ('open','in_progress')`, tenantID,
	).Scan(&mp.Critical, &mp.High, &mp.Medium, &mp.Total, &mp.Overdue)
	return mp
}

func computeUnsupportedOS(tenantID int) []models.UnsupportedOS {
	out := []models.UnsupportedOS{}
	rows, err := database.DB.Query(`SELECT id, hostname, COALESCE(os,'') FROM agents WHERE tenant_id=$1`, tenantID)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var id int
		var hostname, os string
		if rows.Scan(&id, &hostname, &os) != nil {
			continue
		}
		lower := strings.ToLower(os)
		for _, e := range eolOperatingSystems {
			if strings.Contains(lower, e.pattern) {
				agentID := id
				out = append(out, models.UnsupportedOS{Hostname: hostname, OS: os, EOL: e.eol, AgentID: &agentID})
				break
			}
		}
	}
	return out
}

func computeMisconfigurations(tenantID int) []models.Misconfiguration {
	out := []models.Misconfiguration{}
	rows, err := database.DB.Query(`
		SELECT f.id, f.title, f.severity, a.hostname, f.category
		FROM cis_findings f
		JOIN agents a ON a.id = f.agent_id
		WHERE f.tenant_id=$1 AND f.status='fail'
		ORDER BY CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END
		LIMIT 30`, tenantID)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var m models.Misconfiguration
		var cisCategory string
		if rows.Scan(&m.ID, &m.Title, &m.Severity, &m.Asset, &cisCategory) != nil {
			continue
		}
		lower := strings.ToLower(cisCategory)
		switch {
		case strings.Contains(lower, "firewall"), strings.Contains(lower, "network"), strings.Contains(lower, "ssh"):
			m.Category = "network"
		default:
			m.Category = "host"
		}
		out = append(out, m)
	}
	return out
}

// computeHighRiskApps flags sideloaded mobile apps (installer=” means not
// from the Play Store) as the one real "risky app" signal this schema
// currently tracks — there's no desktop package vulnerability feed wired up.
func computeHighRiskApps(tenantID int) []models.HighRiskApp {
	out := []models.HighRiskApp{}
	rows, err := database.DB.Query(`
		SELECT app_name, version, COUNT(DISTINCT device_id) AS devices
		FROM mdm_device_apps
		WHERE tenant_id=$1 AND installer=''
		GROUP BY app_name, version
		ORDER BY devices DESC LIMIT 20`, tenantID)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var a models.HighRiskApp
		if rows.Scan(&a.Name, &a.Version, &a.Assets) == nil {
			a.Risk = "high"
			a.Reason = "Sideloaded — not installed from the Play Store"
			out = append(out, a)
		}
	}
	return out
}

// computeInternetExposure counts enabled inbound-allow firewall rules with a
// wildcard source as real exposure signal. firewall_rules is a tenant-wide
// policy (not bound to individual agents), so exposed_hosts lists the
// online fleet the policy applies to rather than claiming host-specific
// port bindings that aren't tracked anywhere.
func computeInternetExposure(tenantID int) models.InternetExposure {
	exp := models.InternetExposure{ExposedHosts: []models.ExposedHost{}}
	var ports pq.Int64Array
	database.DB.QueryRow(`
		SELECT COUNT(*), COALESCE(array_agg(DISTINCT port) FILTER (WHERE port IS NOT NULL), '{}')
		FROM firewall_rules
		WHERE tenant_id=$1 AND enabled=true AND action='allow'
		  AND direction IN ('in','both')
		  AND (source_ip IS NULL OR source_ip IN ('', 'any', '0.0.0.0/0', '*'))`, tenantID,
	).Scan(&exp.ExposedCount, &ports)
	if exp.ExposedCount == 0 {
		return exp
	}
	openPorts := make([]int, len(ports))
	for i, p := range ports {
		openPorts[i] = int(p)
	}
	rows, err := database.DB.Query(`
		SELECT hostname, ip_address FROM agents
		WHERE tenant_id=$1 AND status='online' LIMIT 10`, tenantID)
	if err != nil {
		return exp
	}
	defer rows.Close()
	for rows.Next() {
		var h models.ExposedHost
		if rows.Scan(&h.Hostname, &h.IP) == nil {
			h.OpenPorts = openPorts
			h.Services = []string{}
			exp.ExposedHosts = append(exp.ExposedHosts, h)
		}
	}
	return exp
}

// computeDepartmentRisk groups by assets.business_unit — the only real
// organizational-unit field in the schema (there's no department concept
// tied to users, so "users" per department is intentionally left at 0
// rather than fabricating a mapping that doesn't exist).
func computeDepartmentRisk(tenantID int) []models.DepartmentRisk {
	out := []models.DepartmentRisk{}
	rows, err := database.DB.Query(`
		SELECT COALESCE(NULLIF(business_unit,''),'Unassigned') AS dept,
		       COUNT(*),
		       COUNT(*) FILTER (WHERE criticality='critical')
		FROM assets WHERE tenant_id=$1
		GROUP BY dept ORDER BY dept`, tenantID)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var d models.DepartmentRisk
		var assetCount, critCount int
		if rows.Scan(&d.Name, &assetCount, &critCount) != nil {
			continue
		}
		d.Assets = assetCount
		d.Score = int(math.Min(100, float64(critCount*25+assetCount*2)))
		if critCount > 0 {
			d.TopIssue = fmt.Sprintf("%d critical asset(s)", critCount)
		} else {
			d.TopIssue = "No critical assets"
		}
		out = append(out, d)
	}
	return out
}
