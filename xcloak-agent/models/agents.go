package models

type AgentRegistration struct {
	MachineID string `json:"machine_id"`
	Hostname  string `json:"hostname"`
	OS        string `json:"os"`
	IPAddress string `json:"ip_address"`
}

type RegistrationResponse struct {
	AgentID int    `json:"agent_id"`
	Token   string `json:"token"`
	Message string `json:"message"`
}
