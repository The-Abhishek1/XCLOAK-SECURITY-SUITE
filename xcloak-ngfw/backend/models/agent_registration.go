package models

// AgentRegistration is the payload the agent sends on startup.
// Must include machine_id so the backend can upsert by stable identity.
type AgentRegistration struct {
	MachineID    string `json:"machine_id"`
	Hostname     string `json:"hostname"`
	OS           string `json:"os"`
	IPAddress    string `json:"ip_address"`
	InstallToken string `json:"install_token"`
}
