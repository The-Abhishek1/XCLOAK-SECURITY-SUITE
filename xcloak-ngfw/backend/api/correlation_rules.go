package api

import (
	"fmt"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
	"xcloak-ngfw/repositories"
)

// CorrelationStageWire is one stage of a temporal/temporal_ordered rule's
// chain, as exchanged over the API — mirrors repositories.CorrelationStage.
type CorrelationStageWire struct {
	Pattern    string `json:"pattern"`
	SourceType string `json:"source_type"`
}

// CorrelationRule is the API wire format. CorrelationType selects the
// evaluation mode (see services/correlation_service.go for what each does):
//
//	"simple" (default)  — single-alert condition match, no window
//	"event_count"        — N+ matching alerts within WindowMinutes
//	"temporal"            — every Stages pattern seen within WindowMinutes
//	"temporal_ordered"    — same, but Stages must occur in that time order
//
// Stages is only meaningful for the two temporal types — at least 2
// ordered patterns describing the steps of an attack chain.
//
// SourceType/ConditionValue let "simple"/"event_count" rules (and each
// individual stage's SourceType) condition on data beyond the alerts table:
// "vulnerability" (EPSS/KEV), "network_connect" (eBPF connect events,
// zone-aware), or "risk_score" — see services/correlation_service.go's
// stageMatchTime for the matching logic per type. "alert" (default) is the
// original alerts-only behavior, fully backward compatible.
type CorrelationRule struct {
	ID              int                    `json:"id"`
	Name            string                 `json:"name"`
	Description     string                 `json:"description"`
	Severity        string                 `json:"severity"`
	RuleName        string                 `json:"rule_name"`
	MitreTechnique  string                 `json:"mitre_technique"`
	AgentID         int                    `json:"agent_id"`
	Action          string                 `json:"action"`
	PlaybookID      int                    `json:"playbook_id"`
	Enabled         bool                   `json:"enabled"`
	MatchCount      int                    `json:"match_count"`
	CreatedBy       string                 `json:"created_by"`
	CreatedAt       time.Time              `json:"created_at"`
	CorrelationType string                 `json:"correlation_type"`
	WindowMinutes   int                    `json:"window_minutes"`
	Threshold       int                    `json:"threshold"`
	SourceType      string                 `json:"source_type"`
	ConditionValue  string                 `json:"condition_value"`
	Stages          []CorrelationStageWire `json:"stages"`
}

// stagesToWire/stagesFromWire convert between the repository's internal
// stage type and the API's wire type — same fields, kept as separate types
// so the repository package doesn't need to import the API package.
func stagesToWire(stages []repositories.CorrelationStage) []CorrelationStageWire {
	out := make([]CorrelationStageWire, len(stages))
	for i, s := range stages {
		out[i] = CorrelationStageWire{Pattern: s.Pattern, SourceType: s.SourceType}
	}
	return out
}

func stagesFromWire(stages []CorrelationStageWire) []repositories.CorrelationStage {
	out := make([]repositories.CorrelationStage, len(stages))
	for i, s := range stages {
		out[i] = repositories.CorrelationStage{Pattern: s.Pattern, SourceType: s.SourceType}
	}
	return out
}

func GetCorrelationRules(c *gin.Context) {
	rows, err := database.DB.Query(`
		SELECT id, name, description, severity, rule_name, mitre_technique,
		       agent_id, action, playbook_id, enabled, match_count, created_by,
		       created_at AT TIME ZONE 'UTC', correlation_type, window_minutes, threshold,
		       source_type, condition_value
		FROM correlation_rules WHERE tenant_id=$1 ORDER BY created_at DESC
	`, tenantIDFromContext(c))
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	var rules []CorrelationRule
	for rows.Next() {
		var r CorrelationRule
		if err := rows.Scan(&r.ID, &r.Name, &r.Description, &r.Severity,
			&r.RuleName, &r.MitreTechnique, &r.AgentID, &r.Action,
			&r.PlaybookID, &r.Enabled, &r.MatchCount, &r.CreatedBy, &r.CreatedAt,
			&r.CorrelationType, &r.WindowMinutes, &r.Threshold,
			&r.SourceType, &r.ConditionValue); err == nil {
			rules = append(rules, r)
		}
	}
	if rules == nil {
		rules = []CorrelationRule{}
	}

	for i := range rules {
		if rules[i].CorrelationType == "temporal" || rules[i].CorrelationType == "temporal_ordered" {
			stages, err := repositories.GetCorrelationRuleStages(rules[i].ID)
			if err == nil {
				rules[i].Stages = stagesToWire(stages)
			}
		}
	}

	c.JSON(200, rules)
}

func CreateCorrelationRule(c *gin.Context) {
	var r CorrelationRule
	if err := c.ShouldBindJSON(&r); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	username, _ := c.Get("username")
	r.CreatedBy = fmt.Sprintf("%v", username)

	if err := validateCorrelationRule(&r); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	// AgentID==0 means "any agent" (matches suppression rules' convention) —
	// only validate ownership when a specific agent was named, otherwise a
	// caller could scope a rule to another tenant's agent.
	if r.AgentID != 0 && !agentOwnedBy404(c, strconv.Itoa(r.AgentID)) {
		return
	}

	err := database.DB.QueryRow(`
		INSERT INTO correlation_rules
		(name, description, severity, rule_name, mitre_technique,
		 agent_id, action, playbook_id, enabled, created_by, tenant_id,
		 correlation_type, window_minutes, threshold, source_type, condition_value)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,TRUE,$9,$10,$11,$12,$13,$14,$15)
		RETURNING id, created_at AT TIME ZONE 'UTC'
	`, r.Name, r.Description, r.Severity, r.RuleName, r.MitreTechnique,
		r.AgentID, r.Action, r.PlaybookID, r.CreatedBy, tenantIDFromContext(c),
		r.CorrelationType, r.WindowMinutes, r.Threshold, r.SourceType, r.ConditionValue).
		Scan(&r.ID, &r.CreatedAt)

	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	if r.CorrelationType == "temporal" || r.CorrelationType == "temporal_ordered" {
		if err := repositories.ReplaceCorrelationRuleStages(r.ID, stagesFromWire(r.Stages)); err != nil {
			c.JSON(500, gin.H{"error": "rule created but failed to save stages: " + err.Error()})
			return
		}
	}

	c.JSON(200, r)
}

// UpdateCorrelationRule — PUT /api/correlation/rules/:id
// Full update, scoped to tenantID — lets an admin tune window/threshold/
// stages without deleting and recreating the rule (which would reset
// match_count and created_at).
func UpdateCorrelationRule(c *gin.Context) {
	id := c.Param("id")

	var r CorrelationRule
	if err := c.ShouldBindJSON(&r); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	if err := validateCorrelationRule(&r); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	if r.AgentID != 0 && !agentOwnedBy404(c, strconv.Itoa(r.AgentID)) {
		return
	}

	res, err := database.DB.Exec(`
		UPDATE correlation_rules SET
			name=$1, description=$2, severity=$3, rule_name=$4, mitre_technique=$5,
			agent_id=$6, action=$7, playbook_id=$8, correlation_type=$9,
			window_minutes=$10, threshold=$11, source_type=$12, condition_value=$13
		WHERE id=$14 AND tenant_id=$15
	`, r.Name, r.Description, r.Severity, r.RuleName, r.MitreTechnique,
		r.AgentID, r.Action, r.PlaybookID, r.CorrelationType, r.WindowMinutes, r.Threshold,
		r.SourceType, r.ConditionValue, id, tenantIDFromContext(c))
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		c.JSON(404, gin.H{"error": "correlation rule not found"})
		return
	}

	ruleID, _ := strconv.Atoi(id)
	if r.CorrelationType == "temporal" || r.CorrelationType == "temporal_ordered" {
		if err := repositories.ReplaceCorrelationRuleStages(ruleID, stagesFromWire(r.Stages)); err != nil {
			c.JSON(500, gin.H{"error": "rule updated but failed to save stages: " + err.Error()})
			return
		}
	} else {
		_ = repositories.ReplaceCorrelationRuleStages(ruleID, nil) // clear stale stages if type changed away from temporal
	}

	c.JSON(200, gin.H{"message": "updated"})
}

func validateSourceType(s string) bool {
	switch s {
	case "", "alert", "vulnerability", "network_connect", "risk_score":
		return true
	default:
		return false
	}
}

func validateCorrelationRule(r *CorrelationRule) error {
	if r.SourceType == "" {
		r.SourceType = "alert"
	}
	if !validateSourceType(r.SourceType) {
		return fmt.Errorf("unknown source_type %q", r.SourceType)
	}

	switch r.CorrelationType {
	case "", "simple":
		r.CorrelationType = "simple"
		if r.SourceType != "alert" && r.ConditionValue == "" {
			return fmt.Errorf("source_type %q requires a non-empty condition_value", r.SourceType)
		}
	case "event_count":
		if r.WindowMinutes <= 0 {
			return fmt.Errorf("event_count rules require window_minutes > 0")
		}
		if r.Threshold <= 1 {
			return fmt.Errorf("event_count rules require threshold > 1 (use 'simple' for single-event matches)")
		}
		// event_count's count query (CountRecentMatchingAlerts) only ever
		// scans the alerts table — a cross-source condition here would
		// validate fine but the count would just always be 0, since
		// there's no analogous "count of vulnerability/connect/risk_score
		// occurrences" query. Keep it alert-only until that's built.
		if r.SourceType != "alert" {
			return fmt.Errorf("event_count rules only support source_type \"alert\"")
		}
	case "temporal", "temporal_ordered":
		if r.WindowMinutes <= 0 {
			return fmt.Errorf("%s rules require window_minutes > 0", r.CorrelationType)
		}
		nonEmpty := 0
		for _, s := range r.Stages {
			if s.Pattern == "" {
				continue
			}
			nonEmpty++
			if !validateSourceType(s.SourceType) {
				return fmt.Errorf("stage %q has unknown source_type %q", s.Pattern, s.SourceType)
			}
		}
		if nonEmpty < 2 {
			return fmt.Errorf("%s rules require at least 2 non-empty stages", r.CorrelationType)
		}
	default:
		return fmt.Errorf("unknown correlation_type %q", r.CorrelationType)
	}

	switch r.Action {
	case "create_incident", "notify":
	default:
		return fmt.Errorf("unknown action %q", r.Action)
	}

	return nil
}

// GetCorrelationMatches — GET /api/correlation/matches?rule_id=
// Per-firing audit trail — match_count alone never showed which alert
// triggered a rule, whether it opened an incident, or how confident the
// match was.
func GetCorrelationMatches(c *gin.Context) {
	ruleID := 0
	if v := c.Query("rule_id"); v != "" {
		ruleID, _ = strconv.Atoi(v)
	}

	matches, err := repositories.GetCorrelationMatches(tenantIDFromContext(c), ruleID, 100)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	if matches == nil {
		matches = []models.CorrelationMatch{}
	}
	c.JSON(200, matches)
}

func ToggleCorrelationRule(c *gin.Context) {
	var body struct {
		Enabled bool `json:"enabled"`
	}
	c.ShouldBindJSON(&body)
	_, err := database.DB.Exec(
		`UPDATE correlation_rules SET enabled=$1 WHERE id=$2 AND tenant_id=$3`, body.Enabled, c.Param("id"), tenantIDFromContext(c))
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"message": "updated"})
}

func DeleteCorrelationRule(c *gin.Context) {
	_, err := database.DB.Exec(`DELETE FROM correlation_rules WHERE id=$1 AND tenant_id=$2`, c.Param("id"), tenantIDFromContext(c))
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"message": "deleted"})
}

// GetAgentAuthLogs — GET /api/agents/:id/auth-logs
func GetAgentAuthLogs(c *gin.Context) {
	agentID := c.Param("id")
	if !agentOwnedBy404(c, agentID) {
		return
	}

	rows, err := database.DB.Query(`
		SELECT id, agent_id, log_source, log_message,
		       collected_at AT TIME ZONE 'UTC'
		FROM endpoint_logs
		WHERE agent_id = $1
		ORDER BY id DESC LIMIT 500
	`, agentID)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	type LogEntry struct {
		ID         int       `json:"id"`
		AgentID    int       `json:"agent_id"`
		LogSource  string    `json:"log_source"`
		LogMessage string    `json:"log_message"`
		CreatedAt  time.Time `json:"created_at"`
	}

	var logs []LogEntry
	for rows.Next() {
		var l LogEntry
		err := rows.Scan(&l.ID, &l.AgentID, &l.LogSource, &l.LogMessage, &l.CreatedAt)
		if err != nil {
			c.JSON(500, gin.H{"error": "scan: " + err.Error()})
			return
		}
		logs = append(logs, l)
	}
	if logs == nil {
		logs = []LogEntry{}
	}
	c.JSON(200, logs)
}
