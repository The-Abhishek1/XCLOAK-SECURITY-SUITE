package models

import "time"

// RegistryEntry represents a single Windows registry value.
type RegistryEntry struct {
	ID        int       `json:"id"`
	AgentID   int       `json:"agent_id"`
	Hive      string    `json:"hive"`
	KeyPath   string    `json:"key_path"`
	Name      string    `json:"name"`
	Type      string    `json:"type"`
	Data      string    `json:"data"`
	ThreatTag string    `json:"threat_tag,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}
