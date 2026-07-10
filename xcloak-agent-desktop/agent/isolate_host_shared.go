package agent

// IsolatePayload is the wire format for an isolate_host task, shared by
// both the Linux (isolate_host.go, iptables) and Windows
// (isolate_host_windows.go, Windows Defender Firewall) implementations.
type IsolatePayload struct {
	AllowIPs []string `json:"allow_ips"` // IPs to keep reachable (e.g. XCloak server)
	Duration int      `json:"duration"`  // seconds; 0 = permanent until manual rollback
}
