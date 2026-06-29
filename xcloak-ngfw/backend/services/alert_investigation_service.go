package services

import (
	"encoding/json"
	"regexp"
	"strings"

	"xcloak-ngfw/database"
)

type IOCHit struct {
	Indicator string `json:"indicator"`
	Type      string `json:"type"`
	Severity  string `json:"severity"`
}

type SimilarAlert struct {
	ID        int    `json:"id"`
	RuleName  string `json:"rule_name"`
	Severity  string `json:"severity"`
	AgentID   int    `json:"agent_id"`
	Hostname  string `json:"hostname"`
	CreatedAt string `json:"created_at"`
	Status    string `json:"status"`
}

type MITREContext struct {
	Tactic    string `json:"tactic"`
	Technique string `json:"technique"`
	Name      string `json:"name"`
}

type SuggestedCase struct {
	ID       int    `json:"id"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	Status   string `json:"status"`
}

type InvestigationContext struct {
	IOCHits        []IOCHit       `json:"ioc_hits"`
	SimilarAlerts  []SimilarAlert `json:"similar_alerts"`
	MITREContext   MITREContext   `json:"mitre_context"`
	SuggestedCases []SuggestedCase `json:"suggested_cases"`
	CorrelatedRules []string      `json:"correlated_rules"`
	ThreatScore    int            `json:"threat_score"`
}

var (
	reIP     = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	reDomain = regexp.MustCompile(`\b([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b`)
	reURL    = regexp.MustCompile(`https?://[^\s"'<>]+`)
	reHash   = regexp.MustCompile(`\b[a-fA-F0-9]{32,64}\b`)
)

// BuildInvestigationContext generates enrichment data for an alert.
func BuildInvestigationContext(alertID, tenantID int) (InvestigationContext, error) {
	ctx := InvestigationContext{
		IOCHits:         []IOCHit{},
		SimilarAlerts:   []SimilarAlert{},
		SuggestedCases:  []SuggestedCase{},
		CorrelatedRules: []string{},
	}

	// Load alert basics
	var logMsg, ruleName, severity, mitreTactic, mitreTechnique, mitreName string
	var agentID int
	err := database.DB.QueryRow(`
		SELECT log_message, rule_name, severity, COALESCE(mitre_tactic,''),
		       COALESCE(mitre_technique,''), COALESCE(mitre_name,''), COALESCE(agent_id,0)
		FROM alerts WHERE id=$1 AND tenant_id=$2`, alertID, tenantID).
		Scan(&logMsg, &ruleName, &severity, &mitreTactic, &mitreTechnique, &mitreName, &agentID)
	if err != nil {
		return ctx, err
	}

	ctx.MITREContext = MITREContext{
		Tactic:    mitreTactic,
		Technique: mitreTechnique,
		Name:      mitreName,
	}

	// ── Extract indicators from log_message ────────────────────────────────
	var candidates []struct{ indicator, iocType string }
	for _, ip := range reIP.FindAllString(logMsg, 10) {
		candidates = append(candidates, struct{ indicator, iocType string }{ip, "ip"})
	}
	for _, u := range reURL.FindAllString(logMsg, 5) {
		candidates = append(candidates, struct{ indicator, iocType string }{u, "url"})
	}
	for _, h := range reHash.FindAllString(logMsg, 5) {
		iocType := "hash"
		if len(h) == 64 {
			iocType = "sha256"
		} else if len(h) == 32 {
			iocType = "md5"
		}
		candidates = append(candidates, struct{ indicator, iocType string }{h, iocType})
	}

	// Check each extracted indicator against IOC table
	for _, c := range candidates {
		var sev string
		err := database.DB.QueryRow(`
			SELECT severity FROM iocs WHERE indicator=$1 AND type=$2 AND enabled=true
			LIMIT 1`, c.indicator, c.iocType).Scan(&sev)
		if err == nil {
			ctx.IOCHits = append(ctx.IOCHits, IOCHit{
				Indicator: c.indicator, Type: c.iocType, Severity: sev,
			})
		}
	}

	// ── Similar alerts (same rule, last 7 days) ────────────────────────────
	simRows, err := database.DB.Query(`
		SELECT a.id, a.rule_name, a.severity, COALESCE(a.agent_id,0), COALESCE(ag.hostname,''), a.created_at, a.status
		FROM alerts a LEFT JOIN agents ag ON ag.id = a.agent_id
		WHERE a.tenant_id=$1 AND a.rule_name=$2 AND a.id != $3
		  AND a.created_at > NOW() - INTERVAL '7 days'
		ORDER BY a.created_at DESC LIMIT 5`, tenantID, ruleName, alertID)
	if err == nil {
		defer simRows.Close()
		for simRows.Next() {
			var s SimilarAlert
			var ts interface{}
			simRows.Scan(&s.ID, &s.RuleName, &s.Severity, &s.AgentID, &s.Hostname, &ts, &s.Status)
			if t, ok := ts.(interface{ String() string }); ok {
				s.CreatedAt = t.String()
			}
			ctx.SimilarAlerts = append(ctx.SimilarAlerts, s)
		}
	}

	// ── Suggested cases (same severity + open status + same agent) ─────────
	caseRows, err := database.DB.Query(`
		SELECT c.id, c.title, c.severity, c.status
		FROM cases c
		WHERE c.tenant_id=$1
		  AND c.status NOT IN ('closed')
		  AND (c.severity=$2 OR (SELECT COUNT(*) FROM case_alerts ca WHERE ca.case_id=c.id AND ca.alert_id=$3)>0)
		ORDER BY c.created_at DESC LIMIT 5`, tenantID, severity, alertID)
	if err == nil {
		defer caseRows.Close()
		for caseRows.Next() {
			var s SuggestedCase
			caseRows.Scan(&s.ID, &s.Title, &s.Severity, &s.Status)
			ctx.SuggestedCases = append(ctx.SuggestedCases, s)
		}
	}

	// ── Correlated rules that match this agent recently ─────────────────────
	corrRows, err := database.DB.Query(`
		SELECT DISTINCT cr.name FROM correlation_matches cm
		JOIN correlation_rules cr ON cr.id = cm.rule_id
		WHERE cm.tenant_id=$1 AND cm.agent_id=$2
		  AND cm.matched_at > NOW() - INTERVAL '24 hours'
		LIMIT 5`, tenantID, agentID)
	if err == nil {
		defer corrRows.Close()
		for corrRows.Next() {
			var name string
			corrRows.Scan(&name)
			ctx.CorrelatedRules = append(ctx.CorrelatedRules, name)
		}
	}

	// ── Threat score ───────────────────────────────────────────────────────
	score := 0
	switch severity {
	case "critical":
		score += 40
	case "high":
		score += 30
	case "medium":
		score += 15
	}
	score += len(ctx.IOCHits) * 20
	score += len(ctx.SimilarAlerts) * 5
	score += len(ctx.CorrelatedRules) * 10
	if strings.Contains(strings.ToLower(logMsg), "ransomware") {
		score += 30
	}
	if score > 100 {
		score = 100
	}
	ctx.ThreatScore = score

	// ── Persist to cache ────────────────────────────────────────────────────
	go func() {
		iocJSON, _ := json.Marshal(ctx.IOCHits)
		simJSON, _ := json.Marshal(ctx.SimilarAlerts)
		mitreJSON, _ := json.Marshal(ctx.MITREContext)
		caseJSON, _ := json.Marshal(ctx.SuggestedCases)
		database.DB.Exec(`
			INSERT INTO alert_investigation_cache
				(alert_id, tenant_id, ioc_hits, similar_alerts, mitre_context, suggested_cases, enriched_at)
			VALUES ($1,$2,$3,$4,$5,$6,NOW())
			ON CONFLICT (alert_id) DO UPDATE SET
				ioc_hits=EXCLUDED.ioc_hits, similar_alerts=EXCLUDED.similar_alerts,
				mitre_context=EXCLUDED.mitre_context, suggested_cases=EXCLUDED.suggested_cases,
				enriched_at=NOW()`,
			alertID, tenantID, iocJSON, simJSON, mitreJSON, caseJSON)
	}()

	return ctx, nil
}
