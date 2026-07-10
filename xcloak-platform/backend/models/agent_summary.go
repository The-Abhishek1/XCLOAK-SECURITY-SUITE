package models

type AgentSummary struct {
	AgentID  int    `json:"agent_id"`
	Hostname string `json:"hostname"`
	Status   string `json:"status"`

	Processes   int `json:"processes"`
	Connections int `json:"connections"`
	Services    int `json:"services"`
	Packages    int `json:"packages"`
	Users       int `json:"users"`
}
