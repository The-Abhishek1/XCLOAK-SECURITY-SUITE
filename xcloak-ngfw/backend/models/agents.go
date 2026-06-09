package models

import "time"

type Agent struct {
	ID        int       `json:"id"`
	Hostname  string    `json:"hostname"`
	OS        string    `json:"os"`
	IPAddress string    `json:"ip_address"`
	Status    string    `json:"status"`
	LastSeen  time.Time `json:"last_seen"`
	CreatedAt time.Time `json:"created_At"`
}
