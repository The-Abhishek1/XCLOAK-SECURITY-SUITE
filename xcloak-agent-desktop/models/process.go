package models

// Process represents a running process captured from an endpoint.
// Fields are a superset of what ps/wmic/procfs expose — the collector
// fills what it can; zero values mean "not available on this platform".
type Process struct {
	AgentID     int    `json:"agent_id"`
	PID         int    `json:"pid"`
	PPID        int    `json:"ppid"`          // parent PID (0 = unknown)
	Name        string `json:"process_name"`  // short executable name (comm)
	Cmdline     string `json:"cmdline"`       // full command line with args
	Username    string `json:"username"`      // owning user (empty if unavailable)
	CPUPercent  string `json:"cpu_percent"`   // e.g. "0.3" — string to avoid float drift
	MemPercent  string `json:"mem_percent"`   // e.g. "1.2"
	ExePath     string `json:"exe_path"`      // absolute path to binary
}
