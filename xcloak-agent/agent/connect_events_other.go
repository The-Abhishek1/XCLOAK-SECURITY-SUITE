//go:build !linux

package agent

// StartConnectEventStream is a no-op outside Linux — eBPF connect-event
// attribution is Linux-only. Other platforms still get outbound-connection
// visibility from the periodic ss/netstat-based CollectConnections snapshot.
func StartConnectEventStream(agentID int) {}
