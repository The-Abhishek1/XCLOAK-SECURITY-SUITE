package models

type User struct {
	AgentID  int    `json:"agent_id"`
	Username string `json:"username"`
	UID      int    `json:"uid"`
	Shell    string `json:"shell"`
}
