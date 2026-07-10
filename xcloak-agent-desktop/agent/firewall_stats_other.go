//go:build windows

package agent

// StartFirewallStatsCollector is a no-op on Windows; WDF has its own
// logging mechanism and the iptables parser doesn't apply.
func StartFirewallStatsCollector() {}
