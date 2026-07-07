package models

type Package struct {
	AgentID     int    `json:"agent_id"`
	PackageName string `json:"package_name"`
	Version     string `json:"version"`
	Source      string `json:"source,omitempty"` // dpkg, rpm, pip, snap, flatpak, winget, registry
}
