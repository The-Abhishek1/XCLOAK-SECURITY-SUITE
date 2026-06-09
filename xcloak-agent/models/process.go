package models

type Process struct {
	AgentID int    `json:"agent_id"`
	PID     int    `json:"pid"`
	Name    string `json:"process_name"`
}
