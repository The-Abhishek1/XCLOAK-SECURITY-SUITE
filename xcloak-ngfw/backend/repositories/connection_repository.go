package repositories

import (
	"time"

	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
)

// GetEndpointConnectionsByTenant returns the most recent endpoint_connections
// rows for all agents in a tenant. These are the periodic ss-snapshot
// connections collected by the agent — used as a fallback / supplement when
// eBPF network_connect_events are not available.
func GetEndpointConnectionsByTenant(tenantID int, limit int) ([]models.ConnectEvent, error) {
	if limit <= 0 {
		limit = 5000
	}
	rows, err := database.DB.Query(`
		SELECT ec.agent_id, ec.protocol, ec.local_address, ec.remote_address,
		       ec.state, COALESCE(ec.collected_at, NOW())
		FROM endpoint_connections ec
		WHERE ec.tenant_id = $1
		ORDER BY ec.collected_at DESC
		LIMIT $2
	`, tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.ConnectEvent
	for rows.Next() {
		var ev models.ConnectEvent
		if err := rows.Scan(
			&ev.AgentID, &ev.Protocol, &ev.LocalAddress,
			&ev.RemoteAddress, &ev.State, &ev.CreatedAt,
		); err == nil {
			out = append(out, ev)
		}
	}
	return out, nil
}

// GetEndpointConnectionsUpdatedAt returns the latest collected_at timestamp
// for any endpoint_connection in the tenant (used to decide data freshness).
func GetEndpointConnectionsUpdatedAt(tenantID int) (time.Time, error) {
	var t time.Time
	err := database.DB.QueryRow(
		`SELECT MAX(collected_at) FROM endpoint_connections WHERE tenant_id=$1`, tenantID,
	).Scan(&t)
	return t, err
}

func SaveConnections(
	connections []models.Connection,
) error {

	tx, err := database.DB.Begin()

	if err != nil {
		return err
	}

	defer tx.Rollback()

	if len(connections) == 0 {
		return nil
	}

	agentID := connections[0].AgentID

	_, err = tx.Exec(`
		DELETE FROM endpoint_connections
		WHERE agent_id = $1
	`, agentID)

	if err != nil {
		return err
	}

	for _, c := range connections {

		_, err := tx.Exec(`
			INSERT INTO endpoint_connections
			(agent_id, protocol, local_address,
			 remote_address, state)
			VALUES ($1,$2,$3,$4,$5)
		`,
			c.AgentID,
			c.Protocol,
			c.LocalAddress,
			c.RemoteAddress,
			c.State,
		)

		if err != nil {
			return err
		}
	}

	return tx.Commit()
}
