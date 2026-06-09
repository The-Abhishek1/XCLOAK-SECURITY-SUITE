package models

type AgentRegistration struct {
	Hostname  string `json:"hostname"`
	OS        string `json:"os"`
	IPAddress string `json:"ip_address"`
}

type RegistrationResponse struct {
	AgentID int    `json:"agent_id"`
	Message string `json:"message"`
}
