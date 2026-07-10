package models

type User struct {
	AgentID       int      `json:"agent_id"`
	Username      string   `json:"username"`
	UID           int      `json:"uid"`
	GID           int      `json:"gid,omitempty"`
	Shell         string   `json:"shell"`
	HomeDir       string   `json:"home_dir,omitempty"`
	Groups        []string `json:"groups,omitempty"`
	SudoAccess    bool     `json:"sudo_access,omitempty"`
	HasSSHKey     bool     `json:"has_ssh_key,omitempty"`
	LastLogin     string   `json:"last_login,omitempty"`
	PasswordExpiry string  `json:"password_expiry,omitempty"`
	Enabled       bool     `json:"enabled"`
}
