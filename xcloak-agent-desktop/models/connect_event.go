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

	// DPI fields — passively extracted from /proc/net or raw socket reads.
	// Empty when the OS doesn't support the extraction or when the agent
	// doesn't have the required capabilities.
	SNI          string `json:"sni,omitempty"`
	HTTPHost     string `json:"http_host,omitempty"`
	HTTPMethod   string `json:"http_method,omitempty"`
	HTTPPath     string `json:"http_path,omitempty"`
	HTTPUserAgent string `json:"http_user_agent,omitempty"`
	TLSVersion   string `json:"tls_version,omitempty"`
	TLSCipher    string `json:"tls_cipher,omitempty"`
	DPIProto     string `json:"dpi_proto,omitempty"`
	EntropyScore int    `json:"entropy_score,omitempty"`
}
