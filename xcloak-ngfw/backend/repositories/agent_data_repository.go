package repositories

import (
	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
)

// GetProcessesByAgent returns the most recent 200 processes for an agent,
// including cmdline, exe_path, username, cpu and mem percentages.
func GetProcessesByAgent(agentID string) ([]models.Process, error) {

	rows, err := database.DB.Query(`
		SELECT id, agent_id, pid,
		       COALESCE(ppid, 0),
		       process_name,
		       COALESCE(cmdline, ''),
		       COALESCE(username, ''),
		       COALESCE(cpu_percent, ''),
		       COALESCE(mem_percent, ''),
		       COALESCE(exe_path, ''),
		       collected_at
		FROM endpoint_processes
		WHERE agent_id = $1
		ORDER BY id DESC
		LIMIT 500
	`, agentID)

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []models.Process
	for rows.Next() {
		var p models.Process
		if err := rows.Scan(
			&p.ID, &p.AgentID, &p.PID, &p.PPID, &p.ProcessName,
			&p.Cmdline, &p.Username, &p.CPUPercent, &p.MemPercent,
			&p.ExePath, &p.CollectedAt,
		); err == nil {
			out = append(out, p)
		}
	}
	return out, nil
}

// GetConnectionsByAgent returns the most recent 200 connections for an agent.
func GetConnectionsByAgent(agentID string) ([]models.Connection, error) {

	rows, err := database.DB.Query(`
		SELECT id, agent_id, protocol, local_address, remote_address, state, collected_at
		FROM endpoint_connections
		WHERE agent_id = $1
		ORDER BY id DESC
		LIMIT 200
	`, agentID)

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []models.Connection
	for rows.Next() {
		var c models.Connection
		if err := rows.Scan(&c.ID, &c.AgentID, &c.Protocol, &c.LocalAddress, &c.RemoteAddress, &c.State, &c.CollectedAt); err == nil {
			out = append(out, c)
		}
	}
	return out, nil
}

// GetServicesByAgent returns all services for an agent.
func GetServicesByAgent(agentID string) ([]models.Service, error) {

	rows, err := database.DB.Query(`
		SELECT id, agent_id, service_name, service_state, collected_at
		FROM endpoint_services
		WHERE agent_id = $1
		ORDER BY service_name ASC
	`, agentID)

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []models.Service
	for rows.Next() {
		var s models.Service
		if err := rows.Scan(&s.ID, &s.AgentID, &s.ServiceName, &s.ServiceState, &s.CollectedAt); err == nil {
			out = append(out, s)
		}
	}
	return out, nil
}

// GetUsersByAgent returns all OS users for an agent.
func GetUsersByAgent(agentID string) ([]models.Users, error) {

	rows, err := database.DB.Query(`
		SELECT id, agent_id, username, uid, shell, collected_at
		FROM endpoint_users
		WHERE agent_id = $1
		ORDER BY uid ASC
	`, agentID)

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []models.Users
	for rows.Next() {
		var u models.Users
		if err := rows.Scan(&u.ID, &u.AgentID, &u.Username, &u.UID, &u.Shell, &u.CollectedAt); err == nil {
			out = append(out, u)
		}
	}
	return out, nil
}

// GetAgentPackagesList returns all packages for an agent (paginated to 500).
func GetAgentPackagesList(agentID string) ([]models.Package, error) {

	rows, err := database.DB.Query(`
		SELECT id, agent_id, package_name, version, collected_at
		FROM endpoint_packages
		WHERE agent_id = $1
		ORDER BY package_name ASC
		LIMIT 500
	`, agentID)

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []models.Package
	for rows.Next() {
		var p models.Package
		if err := rows.Scan(&p.ID, &p.AgentID, &p.PackageName, &p.Version, &p.CollectedAt); err == nil {
			out = append(out, p)
		}
	}
	return out, nil
}
