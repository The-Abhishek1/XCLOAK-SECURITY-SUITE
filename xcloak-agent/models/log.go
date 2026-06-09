package models

type Log struct {
	AgentID    int    `json:"agent_id"`
	LogSource  string `json:"log_source"`
	LogMessage string `json:"log_message"`
}
