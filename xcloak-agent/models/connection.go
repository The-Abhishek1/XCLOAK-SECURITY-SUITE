package models

type Connection struct {
	AgentID       int    `json:"agent_id"`
	Protocol      string `json:"protocol"`
	LocalAddress  string `json:"local_address"`
	RemoteAddress string `json:"remote_address"`
	State         string `json:"state"`
	PID           int    `json:"pid,omitempty"`
	ProcessName   string `json:"process_name,omitempty"`
	ProcessPath   string `json:"process_path,omitempty"`
}
