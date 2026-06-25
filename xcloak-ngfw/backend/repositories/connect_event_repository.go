package repositories

import (
	"time"

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

// GetConnectEventsByTenant returns connect events for every agent in a
// tenant inserted since `since`, newest first. Filters on created_at (the
// server-side insert time), not event_ts — event_ts is bpf_ktime_get_ns(),
// a per-host CLOCK_MONOTONIC nanosecond reading since boot, not a wall-clock
// timestamp, so it can't be compared across agents or against time.Now().
// Used to build the fleet-wide network map rather than a single agent's view.
func GetConnectEventsByTenant(tenantID int, since time.Time, limit int) ([]models.ConnectEvent, error) {
	if limit <= 0 {
		limit = 5000
	}

	rows, err := database.DB.Query(`
		SELECT id, agent_id, pid, comm, uid, protocol, local_address,
		       remote_address, state, event_ts, created_at
		FROM network_connect_events
		WHERE tenant_id = $1 AND created_at >= $2
		ORDER BY id DESC
		LIMIT $3
	`, tenantID, since, limit)
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
