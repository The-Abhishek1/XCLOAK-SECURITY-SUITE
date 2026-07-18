package services

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"xcloak-platform/database"
	"xcloak-platform/models"
)

// TimelineFilter holds optional query filters for timeline endpoints.
type TimelineFilter struct {
	EventTypes []string
	Severity   string
	AgentID    int
	Search     string
	From       time.Time
	To         time.Time
	Limit      int
	Offset     int
}

// timelineUnionSQL is the UNION ALL pulling from all event sources for a tenant.
// $1 = tenantID.  All other filter params are appended by GetTenantTimeline.
const timelineUnionSQL = `
SELECT id, agent_id, event_type, message, severity, created_at,
       hostname, username, process_name, mitre_technique, mitre_name, source, details_json
FROM (
    -- Alerts (detection engine)
    SELECT a.id, a.agent_id,
           'alert'            AS event_type,
           a.rule_name        AS message,
           a.severity,
           a.created_at,
           COALESCE(ag.hostname,'')      AS hostname,
           ''                            AS username,
           ''                            AS process_name,
           COALESCE(a.mitre_technique,'') AS mitre_technique,
           COALESCE(a.mitre_name,'')      AS mitre_name,
           'detection_engine'             AS source,
           json_build_object(
               'log_message', a.log_message,
               'mitre_tactic', a.mitre_tactic,
               'status', a.status,
               'fingerprint', a.fingerprint
           )::text AS details_json
    FROM alerts a
    LEFT JOIN agents ag ON ag.id = a.agent_id
    WHERE a.tenant_id = $1

    UNION ALL

    -- Incidents
    SELECT inc.id, inc.agent_id,
           'incident' AS event_type,
           inc.title  AS message,
           inc.severity,
           inc.created_at,
           COALESCE(ag.hostname,'') AS hostname,
           '' AS username, '' AS process_name,
           '' AS mitre_technique, '' AS mitre_name,
           'incident_engine' AS source,
           json_build_object('status', inc.status)::text AS details_json
    FROM incidents inc
    LEFT JOIN agents ag ON ag.id = inc.agent_id
    WHERE inc.tenant_id = $1

    UNION ALL

    -- Playbook executions (SOAR response)
    SELECT pe.id, pe.agent_id,
           'playbook_action' AS event_type,
           CASE WHEN COALESCE(pe.alert_rule,'') <> ''
                THEN pe.alert_rule || ' → ' || pe.action_type
                ELSE pe.action_type
           END AS message,
           '' AS severity,
           pe.created_at,
           COALESCE(ag.hostname,'') AS hostname,
           '' AS username, '' AS process_name,
           '' AS mitre_technique, '' AS mitre_name,
           'playbook_engine' AS source,
           json_build_object('action_type', pe.action_type, 'alert_rule', pe.alert_rule)::text AS details_json
    FROM playbook_executions pe
    JOIN agents ag ON ag.id = pe.agent_id
    WHERE ag.tenant_id = $1

    UNION ALL

    -- Process / audit events (EDR agent telemetry)
    SELECT ae.id, ae.agent_id,
           'process' AS event_type,
           COALESCE(ae.comm,'') || CASE WHEN COALESCE(ae.cmdline,'') <> '' THEN ': ' || ae.cmdline ELSE '' END AS message,
           CASE WHEN COALESCE(ae.threat_tag,'') <> '' THEN 'high' ELSE 'info' END AS severity,
           ae.created_at,
           COALESCE(ag.hostname,'') AS hostname,
           COALESCE(ae.username,'') AS username,
           COALESCE(ae.comm,'')     AS process_name,
           '' AS mitre_technique, '' AS mitre_name,
           'edr_agent' AS source,
           json_build_object(
               'exe', ae.exe,
               'cmdline', ae.cmdline,
               'pid', ae.pid,
               'ppid', ae.ppid,
               'uid', ae.uid,
               'threat_tag', ae.threat_tag,
               'username', ae.username
           )::text AS details_json
    FROM audit_events ae
    JOIN agents ag ON ag.id = ae.agent_id
    WHERE ag.tenant_id = $1

    UNION ALL

    -- File integrity (FIM) events
    SELECT fa.id, fa.agent_id,
           'file' AS event_type,
           fa.change_type || ': ' || fa.file_path AS message,
           'medium' AS severity,
           fa.created_at,
           COALESCE(ag.hostname,'') AS hostname,
           '' AS username, '' AS process_name,
           '' AS mitre_technique, '' AS mitre_name,
           'fim' AS source,
           json_build_object(
               'file_path', fa.file_path,
               'change_type', fa.change_type,
               'new_hash', fa.new_hash,
               'old_hash', fa.old_hash,
               'new_mode', fa.new_mode,
               'old_mode', fa.old_mode
           )::text AS details_json
    FROM fim_alerts fa
    JOIN agents ag ON ag.id = fa.agent_id
    WHERE ag.tenant_id = $1

    UNION ALL

    -- Network connection events
    SELECT ce.id, ce.agent_id,
           'network' AS event_type,
           COALESCE(ce.comm,'') || ' ' || ce.protocol || ' → ' || ce.remote_address AS message,
           'info' AS severity,
           ce.created_at,
           COALESCE(ag.hostname,'') AS hostname,
           '' AS username,
           COALESCE(ce.comm,'') AS process_name,
           '' AS mitre_technique, '' AS mitre_name,
           'edr_agent' AS source,
           json_build_object(
               'protocol', ce.protocol,
               'local_address', ce.local_address,
               'remote_address', ce.remote_address,
               'state', ce.state,
               'pid', ce.pid,
               'comm', ce.comm
           )::text AS details_json
    FROM network_connect_events ce
    JOIN agents ag ON ag.id = ce.agent_id
    WHERE ag.tenant_id = $1
) t
`

func scanRows(rows interface {
	Next() bool
	Scan(...any) error
	Close() error
}) ([]models.TimelineEvent, error) {
	defer rows.Close()
	var out []models.TimelineEvent
	for rows.Next() {
		var e models.TimelineEvent
		var detailsJSON string
		if err := rows.Scan(
			&e.ID, &e.AgentID, &e.EventType, &e.Message, &e.Severity, &e.CreatedAt,
			&e.Hostname, &e.Username, &e.ProcessName,
			&e.MitreTechnique, &e.MitreName, &e.Source, &detailsJSON,
		); err != nil {
			continue
		}
		if detailsJSON != "" && detailsJSON != "{}" {
			e.Details = json.RawMessage(detailsJSON)
		}
		out = append(out, e)
	}
	return out, rows.Close()
}

// GetTenantTimeline returns filtered timeline events across all agents for a tenant.
func GetTenantTimeline(tenantID int, f TimelineFilter) ([]models.TimelineEvent, error) {
	if f.Limit <= 0 {
		f.Limit = 200
	}
	if f.Limit > 2000 {
		f.Limit = 2000
	}

	args := []any{tenantID}
	where := []string{}
	n := 2

	if len(f.EventTypes) > 0 {
		placeholders := make([]string, len(f.EventTypes))
		for i, et := range f.EventTypes {
			args = append(args, et)
			placeholders[i] = fmt.Sprintf("$%d", n)
			n++
		}
		where = append(where, "event_type IN ("+strings.Join(placeholders, ",")+")")
	}

	if f.Severity != "" {
		args = append(args, f.Severity)
		where = append(where, fmt.Sprintf("severity = $%d", n))
		n++
	}

	if f.AgentID > 0 {
		args = append(args, f.AgentID)
		where = append(where, fmt.Sprintf("agent_id = $%d", n))
		n++
	}

	if !f.From.IsZero() {
		args = append(args, f.From)
		where = append(where, fmt.Sprintf("created_at >= $%d", n))
		n++
	}

	if !f.To.IsZero() {
		args = append(args, f.To)
		where = append(where, fmt.Sprintf("created_at <= $%d", n))
		n++
	}

	if f.Search != "" {
		args = append(args, "%"+f.Search+"%")
		// $n used 4 times — PostgreSQL reuses the same binding
		where = append(where, fmt.Sprintf(
			"(message ILIKE $%d OR hostname ILIKE $%d OR username ILIKE $%d OR process_name ILIKE $%d)",
			n, n, n, n,
		))
		n++
	}

	q := timelineUnionSQL
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	args = append(args, f.Limit, f.Offset)
	q += fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d OFFSET $%d", n, n+1)

	rows, err := database.DB.Query(q, args...)
	if err != nil {
		return nil, err
	}
	return scanRows(rows)
}

// GetTenantTimelineStats returns event counts per type over the last 7 days.
func GetTenantTimelineStats(tenantID int) (map[string]int, error) {
	q := `SELECT event_type, COUNT(*) FROM (` + timelineUnionSQL +
		`) s WHERE created_at >= NOW() - INTERVAL '7 days' GROUP BY event_type`

	rows, err := database.DB.Query(q, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	counts := map[string]int{}
	for rows.Next() {
		var et string
		var cnt int
		if err := rows.Scan(&et, &cnt); err == nil {
			counts[et] = cnt
		}
	}
	return counts, nil
}

// GetAgentTimeline returns timeline events for a single agent (up to 500).
func GetAgentTimeline(agentID int) ([]models.TimelineEvent, error) {
	q := `
SELECT id, agent_id, event_type, message, severity, created_at,
       hostname, username, process_name, mitre_technique, mitre_name, source, details_json
FROM (
    SELECT a.id, a.agent_id, 'alert' AS event_type, a.rule_name AS message, a.severity, a.created_at,
           COALESCE(ag.hostname,'') AS hostname, '' AS username, '' AS process_name,
           COALESCE(a.mitre_technique,'') AS mitre_technique, COALESCE(a.mitre_name,'') AS mitre_name,
           'detection_engine' AS source,
           json_build_object('log_message', a.log_message, 'status', a.status)::text AS details_json
    FROM alerts a LEFT JOIN agents ag ON ag.id = a.agent_id WHERE a.agent_id = $1

    UNION ALL

    SELECT inc.id, inc.agent_id, 'incident', inc.title, inc.severity, inc.created_at,
           COALESCE(ag.hostname,''), '', '', '', '', 'incident_engine',
           json_build_object('status', inc.status)::text
    FROM incidents inc LEFT JOIN agents ag ON ag.id = inc.agent_id WHERE inc.agent_id = $1

    UNION ALL

    SELECT pe.id, pe.agent_id, 'playbook_action',
           CASE WHEN COALESCE(pe.alert_rule,'') <> '' THEN pe.alert_rule || ' → ' || pe.action_type ELSE pe.action_type END,
           '', pe.created_at, COALESCE(ag.hostname,''), '', '', '', '', 'playbook_engine',
           json_build_object('action_type', pe.action_type)::text
    FROM playbook_executions pe JOIN agents ag ON ag.id = pe.agent_id WHERE pe.agent_id = $1

    UNION ALL

    SELECT ae.id, ae.agent_id, 'process',
           COALESCE(ae.comm,'') || CASE WHEN COALESCE(ae.cmdline,'') <> '' THEN ': ' || ae.cmdline ELSE '' END,
           CASE WHEN COALESCE(ae.threat_tag,'') <> '' THEN 'high' ELSE 'info' END,
           ae.created_at, COALESCE(ag.hostname,''), COALESCE(ae.username,''), COALESCE(ae.comm,''),
           '', '', 'edr_agent',
           json_build_object('exe', ae.exe, 'cmdline', ae.cmdline, 'pid', ae.pid, 'ppid', ae.ppid, 'threat_tag', ae.threat_tag)::text
    FROM audit_events ae JOIN agents ag ON ag.id = ae.agent_id WHERE ae.agent_id = $1

    UNION ALL

    SELECT fa.id, fa.agent_id, 'file',
           fa.change_type || ': ' || fa.file_path,
           'medium', fa.created_at, COALESCE(ag.hostname,''), '', '',
           '', '', 'fim',
           json_build_object('file_path', fa.file_path, 'change_type', fa.change_type, 'new_hash', fa.new_hash)::text
    FROM fim_alerts fa JOIN agents ag ON ag.id = fa.agent_id WHERE fa.agent_id = $1

    UNION ALL

    SELECT ce.id, ce.agent_id, 'network',
           COALESCE(ce.comm,'') || ' ' || ce.protocol || ' → ' || ce.remote_address,
           'info', ce.created_at, COALESCE(ag.hostname,''), '', COALESCE(ce.comm,''),
           '', '', 'edr_agent',
           json_build_object('protocol', ce.protocol, 'remote_address', ce.remote_address, 'local_address', ce.local_address, 'state', ce.state)::text
    FROM network_connect_events ce JOIN agents ag ON ag.id = ce.agent_id WHERE ce.agent_id = $1
) t
ORDER BY created_at DESC LIMIT 500
`
	rows, err := database.DB.Query(q, agentID)
	if err != nil {
		return nil, err
	}
	return scanRows(rows)
}
