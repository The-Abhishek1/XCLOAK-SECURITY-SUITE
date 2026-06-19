package models

import "time"

type Process struct {
	ID          int       `json:"id"`
	AgentID     int       `json:"agent_id"`
	PID         int       `json:"pid"`
	PPID        int       `json:"ppid"`
	ProcessName string    `json:"process_name"`
	Cmdline     string    `json:"cmdline"`
	Username    string    `json:"username"`
	CPUPercent  string    `json:"cpu_percent"`
	MemPercent  string    `json:"mem_percent"`
	ExePath     string    `json:"exe_path"`
	CollectedAt time.Time `json:"collected_at"`
}

// AuditEvent represents a single execve recorded by auditd on Linux.
type AuditEvent struct {
	ID        int       `json:"id"`
	AgentID   int       `json:"agent_id"`
	EventID   string    `json:"event_id"`
	Timestamp string    `json:"timestamp"`
	PID       int       `json:"pid"`
	PPID      int       `json:"ppid"`
	UID       int       `json:"uid"`
	EUID      int       `json:"euid"`
	Username  string    `json:"username"`
	Comm      string    `json:"comm"`
	Exe       string    `json:"exe"`
	Cmdline   string    `json:"cmdline"`
	Success   string    `json:"success"`
	ThreatTag string    `json:"threat_tag,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}
