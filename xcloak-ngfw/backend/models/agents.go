package models

import "time"

type Agent struct {
	ID        int       `json:"id"`
	MachineID string    `json:"machine_id"` // stable hardware fingerprint
	Hostname  string    `json:"hostname"`
	OS        string    `json:"os"`
	IPAddress string    `json:"ip_address"`
	Status    string    `json:"status"`
	Token     string    `json:"token,omitempty"` // only sent on first registration
	LastSeen  time.Time `json:"last_seen"`
	CreatedAt time.Time `json:"created_at"`
}
