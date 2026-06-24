package models

import "time"

// ConnectEvent is a single outbound-connection event sourced from the
// agent's eBPF module (kprobe on tcp_v4_connect). Unlike
// Connection (a periodic ss-based snapshot, replaced wholesale on every
// poll), ConnectEvent rows are append-only — a forensic stream of every
// connection that happened, including ones that opened and closed faster
// than the snapshot poll interval. Carries pid/comm/uid, which the
// snapshot collector can't reliably attribute to a process at all.
type ConnectEvent struct {
	ID            int       `json:"id"`
	AgentID       int       `json:"agent_id"`
	PID           int       `json:"pid"`
	Comm          string    `json:"comm"`
	UID           int       `json:"uid"`
	Protocol      string    `json:"protocol"`
	LocalAddress  string    `json:"local_address"`
	RemoteAddress string    `json:"remote_address"`
	State         string    `json:"state"`
	EventTS       int64     `json:"event_ts"`
	CreatedAt     time.Time `json:"created_at"`
}
