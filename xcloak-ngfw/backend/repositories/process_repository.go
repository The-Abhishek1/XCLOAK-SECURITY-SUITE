package repositories

import (
	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
)

// SaveProcesses replaces the current process snapshot for an agent.
// The endpoint_processes table is a rolling snapshot (latest state), not a
// history table — so we delete and re-insert every collection cycle.
func SaveProcesses(processes []models.Process) error {

	if len(processes) == 0 {
		return nil
	}

	tx, err := database.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	agentID := processes[0].AgentID

	_, err = tx.Exec(`DELETE FROM endpoint_processes WHERE agent_id = $1`, agentID)
	if err != nil {
		return err
	}

	for _, p := range processes {
		_, err := tx.Exec(`
			INSERT INTO endpoint_processes
			  (agent_id, pid, ppid, process_name, cmdline,
			   username, cpu_percent, mem_percent, exe_path)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		`,
			p.AgentID, p.PID, p.PPID, p.ProcessName, p.Cmdline,
			p.Username, p.CPUPercent, p.MemPercent, p.ExePath,
		)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

// SaveAuditEvents appends execve events to audit_events and runs threat
// detection on each one. Unlike processes, audit events are append-only —
// they build a forensic history rather than a snapshot.
func SaveAuditEvents(events []models.AuditEvent) error {
	if len(events) == 0 {
		return nil
	}

	tx, err := database.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for i := range events {
		// Tag known-bad patterns before inserting.
		events[i].ThreatTag = classifyCmdline(events[i].Cmdline, events[i].Exe)

		_, err := tx.Exec(`
			INSERT INTO audit_events
			  (agent_id, event_id, ts, pid, ppid, uid, euid,
			   username, comm, exe, cmdline, success, threat_tag)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
		`,
			events[i].AgentID, events[i].EventID, events[i].Timestamp,
			events[i].PID, events[i].PPID, events[i].UID, events[i].EUID,
			events[i].Username, events[i].Comm, events[i].Exe,
			events[i].Cmdline, events[i].Success, events[i].ThreatTag,
		)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

// GetAuditEventsByAgent returns the most recent audit events for an agent.
func GetAuditEventsByAgent(agentID string, limit int) ([]models.AuditEvent, error) {
	if limit <= 0 {
		limit = 200
	}

	rows, err := database.DB.Query(`
		SELECT id, agent_id, event_id, ts, pid, ppid, uid, euid,
		       username, comm, exe, cmdline, success, threat_tag, created_at
		FROM audit_events
		WHERE agent_id = $1
		ORDER BY created_at DESC
		LIMIT $2
	`, agentID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []models.AuditEvent
	for rows.Next() {
		var e models.AuditEvent
		err := rows.Scan(
			&e.ID, &e.AgentID, &e.EventID, &e.Timestamp, &e.PID, &e.PPID,
			&e.UID, &e.EUID, &e.Username, &e.Comm, &e.Exe,
			&e.Cmdline, &e.Success, &e.ThreatTag, &e.CreatedAt,
		)
		if err == nil {
			out = append(out, e)
		}
	}
	return out, nil
}

// GetThreatAuditEvents returns only audit events tagged as threats (any agent).
func GetThreatAuditEvents(limit int) ([]models.AuditEvent, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := database.DB.Query(`
		SELECT id, agent_id, event_id, ts, pid, ppid, uid, euid,
		       username, comm, exe, cmdline, success, threat_tag, created_at
		FROM audit_events
		WHERE threat_tag <> ''
		ORDER BY created_at DESC
		LIMIT $1
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []models.AuditEvent
	for rows.Next() {
		var e models.AuditEvent
		rows.Scan(
			&e.ID, &e.AgentID, &e.EventID, &e.Timestamp, &e.PID, &e.PPID,
			&e.UID, &e.EUID, &e.Username, &e.Comm, &e.Exe,
			&e.Cmdline, &e.Success, &e.ThreatTag, &e.CreatedAt,
		)
		out = append(out, e)
	}
	return out, nil
}
