package models

// ConnectEvent mirrors the backend's models.ConnectEvent — one real-time
// outbound TCP connect() attempt, sourced from the agent's eBPF collector
// (see agent/connect_events_linux.go), as opposed to Connection's periodic
// ss-based snapshot.
type ConnectEvent struct {
	AgentID       int    `json:"agent_id"`
	PID           int    `json:"pid"`
	Comm          string `json:"comm"`
	UID           int    `json:"uid"`
	Protocol      string `json:"protocol"`
	LocalAddress  string `json:"local_address"`
	RemoteAddress string `json:"remote_address"`
	State         string `json:"state"`
	EventTS       int64  `json:"event_ts"`
}
