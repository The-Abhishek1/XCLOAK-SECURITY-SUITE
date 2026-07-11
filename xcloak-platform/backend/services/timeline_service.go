package services

import (
	"sort"

	"xcloak-platform/database"
	"xcloak-platform/models"
	"xcloak-platform/repositories"
)

func GetAgentTimeline(agentID int) ([]models.TimelineEvent, error) {
	var timeline []models.TimelineEvent

	alerts, _ := repositories.GetAlertsByAgentID(agentID)
	for _, a := range alerts {
		msg := a.RuleName
		if a.MitreTactic != "" {
			msg += " [" + a.MitreTactic + "]"
		}
		timeline = append(timeline, models.TimelineEvent{
			ID:        a.ID,
			AgentID:   a.AgentID,
			EventType: "alert",
			Message:   msg,
			Severity:  a.Severity,
			CreatedAt: a.CreatedAt,
		})
	}

	incidents, _ := repositories.GetIncidentsByAgentID(agentID)
	for _, inc := range incidents {
		timeline = append(timeline, models.TimelineEvent{
			ID:        inc.ID,
			AgentID:   inc.AgentID,
			EventType: "incident",
			Message:   inc.Title,
			Severity:  inc.Severity,
			CreatedAt: inc.CreatedAt,
		})
	}

	executions, _ := repositories.GetPlaybookExecutionsByAgentID(agentID)
	for _, ex := range executions {
		msg := ex.ActionType
		if ex.AlertRule != "" {
			msg = ex.AlertRule + " → " + ex.ActionType
		}
		timeline = append(timeline, models.TimelineEvent{
			ID:        ex.ID,
			AgentID:   ex.AgentID,
			EventType: "playbook",
			Message:   msg,
			CreatedAt: ex.CreatedAt,
		})
	}

	sort.Slice(timeline, func(i, j int) bool {
		return timeline[i].CreatedAt.After(timeline[j].CreatedAt)
	})

	return timeline, nil
}

// GetTenantTimeline returns the most recent `limit` timeline events across all
// agents in a tenant — single UNION ALL query instead of N per-agent requests.
func GetTenantTimeline(tenantID, limit int) ([]models.TimelineEvent, error) {
	if limit <= 0 {
		limit = 200
	}

	rows, err := database.DB.Query(`
		SELECT id, agent_id, event_type, message, severity, created_at FROM (
			SELECT id, agent_id, 'alert'    AS event_type,
			       rule_name                AS message,
			       severity,
			       created_at
			FROM alerts WHERE tenant_id = $1
			UNION ALL
			SELECT id, agent_id, 'incident' AS event_type,
			       title                    AS message,
			       severity,
			       created_at
			FROM incidents WHERE tenant_id = $1
			UNION ALL
			SELECT pe.id, pe.agent_id, 'playbook' AS event_type,
			       CASE WHEN pe.alert_rule <> ''
			            THEN pe.alert_rule || ' → ' || pe.action_type
			            ELSE pe.action_type END AS message,
			       ''     AS severity,
			       pe.created_at
			FROM playbook_executions pe
			JOIN agents a ON a.id = pe.agent_id WHERE a.tenant_id = $1
		) t
		ORDER BY created_at DESC
		LIMIT $2
	`, tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []models.TimelineEvent
	for rows.Next() {
		var e models.TimelineEvent
		if err := rows.Scan(&e.ID, &e.AgentID, &e.EventType, &e.Message, &e.Severity, &e.CreatedAt); err == nil {
			out = append(out, e)
		}
	}
	return out, nil
}
