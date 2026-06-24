package repositories

import (
	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
)

// SaveConnectEvents appends eBPF-sourced connection events — unlike
// SaveConnections (a destructive replace-all for the periodic ss snapshot),
// this is a pure append, matching SaveAuditEvents' semantics for the same
// reason: these are individual real-time events, not a point-in-time
// inventory to overwrite.
func SaveConnectEvents(events []models.ConnectEvent) error {
	if len(events) == 0 {
		return nil
	}

	tx, err := database.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for _, ev := range events {
		_, err := tx.Exec(`
			INSERT INTO network_connect_events
			  (agent_id, pid, comm, uid, protocol, local_address,
			   remote_address, state, event_ts, tenant_id)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9, (SELECT tenant_id FROM agents WHERE id = $1))
		`,
			ev.AgentID, ev.PID, ev.Comm, ev.UID, ev.Protocol,
			ev.LocalAddress, ev.RemoteAddress, ev.State, ev.EventTS,
		)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

// GetConnectEventsByAgent returns the most recent connect events for an
// agent, newest first.
func GetConnectEventsByAgent(agentID int, limit int) ([]models.ConnectEvent, error) {
	if limit <= 0 {
		limit = 200
	}

	rows, err := database.DB.Query(`
		SELECT id, agent_id, pid, comm, uid, protocol, local_address,
		       remote_address, state, event_ts, created_at
		FROM network_connect_events
		WHERE agent_id = $1
		ORDER BY id DESC
		LIMIT $2
	`, agentID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []models.ConnectEvent
	for rows.Next() {
		var ev models.ConnectEvent
		if err := rows.Scan(
			&ev.ID, &ev.AgentID, &ev.PID, &ev.Comm, &ev.UID, &ev.Protocol,
			&ev.LocalAddress, &ev.RemoteAddress, &ev.State, &ev.EventTS, &ev.CreatedAt,
		); err == nil {
			out = append(out, ev)
		}
	}
	return out, nil
}
