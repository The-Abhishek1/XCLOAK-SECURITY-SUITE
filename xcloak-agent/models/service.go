package models

type Service struct {
	AgentID      int    `json:"agent_id"`
	ServiceName  string `json:"service_name"`
	ServiceState string `json:"service_state"`
}
