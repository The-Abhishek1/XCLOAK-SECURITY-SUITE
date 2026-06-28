package services

import (
	"encoding/json"
	"log"
	"math"
	"time"

	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
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

	// ── Alert score (0-30): open critical/high alerts in last 7d ──
	var criticalOpen, highOpen int
	database.DB.QueryRow(`
		SELECT COUNT(*) FILTER (WHERE severity='critical'),
		       COUNT(*) FILTER (WHERE severity='high')
		FROM alerts WHERE tenant_id=$1 AND status='open'
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
	var out []models.AssetRisk
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
	var out []models.RiskPostureSnapshot
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
