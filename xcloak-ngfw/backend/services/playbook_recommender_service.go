package services

import (
	"fmt"
	"log"
	"strings"

	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
)

type pbScored struct {
	id, score    int
	name, reason string
}

// RecommendPlaybooks scores all tenant playbooks for a given alert and persists
// the top recommendations. Returns them sorted by score descending.
func RecommendPlaybooks(alertID, tenantID int) ([]models.PlaybookRecommendation, error) {
	// Fetch alert context
	var ruleName, severity, mitreTechnique, mitreTactic, logMessage string
	err := database.DB.QueryRow(`
		SELECT COALESCE(rule_name,''), COALESCE(severity,''), COALESCE(mitre_technique,''),
		       COALESCE(mitre_tactic,''), COALESCE(log_message,'')
		FROM alerts WHERE id=$1 AND tenant_id=$2`, alertID, tenantID,
	).Scan(&ruleName, &severity, &mitreTechnique, &mitreTactic, &logMessage)
	if err != nil {
		return nil, fmt.Errorf("alert not found")
	}

	// Fetch IOC hit count from investigation cache
	var iocHits int
	database.DB.QueryRow(`
		SELECT jsonb_array_length(ioc_hits) FROM alert_investigation_cache
		WHERE alert_id=$1`, alertID,
	).Scan(&iocHits)

	// Fetch actor confidence for this alert
	var actorConfidence int
	database.DB.QueryRow(`
		SELECT COALESCE(MAX(confidence),0) FROM actor_alert_tags WHERE alert_id=$1`, alertID,
	).Scan(&actorConfidence)

	// Fetch all playbooks for the tenant
	rows, err := database.DB.Query(`
		SELECT id, name, description FROM playbooks WHERE tenant_id=$1 AND is_active=true`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var scored []pbScored

	for rows.Next() {
		var pbID int
		var name, desc string
		rows.Scan(&pbID, &name, &desc)

		score := 0
		var reasons []string

		nameLower := strings.ToLower(name)
		descLower := strings.ToLower(desc)
		combined := nameLower + " " + descLower

		// MITRE technique exact match
		if mitreTechnique != "" && strings.Contains(combined, strings.ToLower(mitreTechnique)) {
			score += 40
			reasons = append(reasons, fmt.Sprintf("MITRE %s match", mitreTechnique))
		}

		// Tactic keywords
		tacticKeywords := map[string][]string{
			"credential_access": {"credential", "brute", "password", "auth"},
			"execution":         {"execute", "process", "shell", "script"},
			"persistence":       {"persist", "cron", "startup", "registry"},
			"defense_evasion":   {"evasion", "obfuscat", "canary"},
			"lateral_movement":  {"lateral", "smb", "rdp", "pivot"},
			"command_and_control": {"c2", "c&c", "beacon", "reverse shell"},
			"exfiltration":      {"exfil", "data transfer", "upload"},
			"impact":            {"ransom", "wipe", "destroy", "encrypt"},
			"discovery":         {"scan", "recon", "discovery", "enum"},
		}
		if keywords, ok := tacticKeywords[mitreTactic]; ok {
			for _, kw := range keywords {
				if strings.Contains(combined, kw) {
					score += 20
					reasons = append(reasons, fmt.Sprintf("tactic keyword '%s'", kw))
					break
				}
			}
		}

		// Severity boost
		switch severity {
		case "critical":
			score += 20
			reasons = append(reasons, "critical severity")
		case "high":
			score += 10
		}

		// IOC hits
		if iocHits > 0 {
			score += 15
			reasons = append(reasons, fmt.Sprintf("%d IOC matches", iocHits))
		}

		// Actor confidence boost
		if actorConfidence >= 70 {
			score += 15
			reasons = append(reasons, "high-confidence actor attribution")
		}

		// Historical effectiveness — playbooks chosen before for same rule
		var prevExec int
		database.DB.QueryRow(`
			SELECT COUNT(*) FROM playbook_outcome_feedback
			WHERE tenant_id=$1 AND alert_rule_name=$2 AND playbook_id=$3 AND was_effective=true`,
			tenantID, ruleName, pbID,
		).Scan(&prevExec)
		if prevExec > 0 {
			score += 10 + prevExec*2
			reasons = append(reasons, fmt.Sprintf("effective %dx for this rule", prevExec))
		}

		// Rule name keyword match
		ruleWords := strings.Fields(strings.ToLower(ruleName))
		for _, w := range ruleWords {
			if len(w) > 4 && strings.Contains(combined, w) {
				score += 5
				break
			}
		}

		if score > 0 {
			reason := strings.Join(reasons, "; ")
			if reason == "" {
				reason = "general match"
			}
			scored = append(scored, pbScored{id: pbID, score: min100(score), name: name, reason: reason})
		}
	}

	if len(scored) == 0 {
		return []models.PlaybookRecommendation{}, nil
	}

	// Sort descending
	sortPBScored(scored)
	if len(scored) > 5 {
		scored = scored[:5]
	}

	// Upsert recommendations
	var out []models.PlaybookRecommendation
	for _, s := range scored {
		var rec models.PlaybookRecommendation
		err := database.DB.QueryRow(`
			INSERT INTO playbook_recommendations (alert_id, tenant_id, playbook_id, score, reason)
			VALUES ($1,$2,$3,$4,$5)
			ON CONFLICT (alert_id, playbook_id) DO UPDATE SET score=$4, reason=$5
			RETURNING id, alert_id, tenant_id, playbook_id, score, reason, executed, executed_by, executed_at, created_at`,
			alertID, tenantID, s.id, s.score, s.reason,
		).Scan(&rec.ID, &rec.AlertID, &rec.TenantID, &rec.PlaybookID, &rec.Score,
			&rec.Reason, &rec.Executed, &rec.ExecutedBy, &rec.ExecutedAt, &rec.CreatedAt)
		if err != nil {
			log.Printf("[PBRecommend] upsert error: %v", err)
			continue
		}
		rec.PlaybookName = s.name
		out = append(out, rec)
	}
	return out, nil
}

// GetPlaybookRecommendations returns cached recommendations for an alert.
func GetPlaybookRecommendations(alertID, tenantID int) ([]models.PlaybookRecommendation, error) {
	rows, err := database.DB.Query(`
		SELECT pr.id, pr.alert_id, pr.tenant_id, pr.playbook_id, p.name,
		       pr.score, pr.reason, pr.executed, pr.executed_by, pr.executed_at, pr.created_at
		FROM playbook_recommendations pr
		JOIN playbooks p ON p.id=pr.playbook_id
		WHERE pr.alert_id=$1 AND pr.tenant_id=$2
		ORDER BY pr.score DESC`, alertID, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.PlaybookRecommendation
	for rows.Next() {
		var r models.PlaybookRecommendation
		rows.Scan(&r.ID, &r.AlertID, &r.TenantID, &r.PlaybookID, &r.PlaybookName,
			&r.Score, &r.Reason, &r.Executed, &r.ExecutedBy, &r.ExecutedAt, &r.CreatedAt)
		out = append(out, r)
	}
	return out, nil
}

// ExecuteRecommendedPlaybook marks a recommendation executed and runs the playbook.
func ExecuteRecommendedPlaybook(recID, alertID, tenantID int, username string) error {
	var pbID int
	err := database.DB.QueryRow(`
		SELECT playbook_id FROM playbook_recommendations
		WHERE id=$1 AND alert_id=$2 AND tenant_id=$3`, recID, alertID, tenantID,
	).Scan(&pbID)
	if err != nil {
		return fmt.Errorf("recommendation not found")
	}

	// Mark executed
	database.DB.Exec(`
		UPDATE playbook_recommendations
		SET executed=true, executed_by=$1, executed_at=NOW()
		WHERE id=$2`, username, recID)

	// Fetch alert rule name for feedback tracking
	var ruleName, mitreTech string
	database.DB.QueryRow(`SELECT COALESCE(rule_name,''), COALESCE(mitre_technique,'') FROM alerts WHERE id=$1`, alertID).
		Scan(&ruleName, &mitreTech)

	// Record outcome feedback (assume effective until user marks otherwise)
	database.DB.Exec(`
		INSERT INTO playbook_outcome_feedback (tenant_id, alert_rule_name, mitre_technique, playbook_id, was_effective, feedback_by)
		VALUES ($1,$2,$3,$4,true,$5)`, tenantID, ruleName, mitreTech, pbID, username)

	// Execute playbook via existing engine
	go func() {
		alert := models.Alert{ID: alertID, TenantID: tenantID}
		if err := ExecutePlaybookByID(pbID, tenantID, alert); err != nil {
			log.Printf("[PBRecommend] playbook %d execution error: %v", pbID, err)
		}
	}()
	return nil
}

// ── helpers ────────────────────────────────────────────────────────────────

func min100(v int) int {
	if v > 100 {
		return 100
	}
	return v
}

func sortPBScored(s []pbScored) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j].score > s[j-1].score; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
