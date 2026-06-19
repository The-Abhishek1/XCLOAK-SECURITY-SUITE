//go:build windows

package agent

// CollectAuditEvents is a no-op on Windows.
// Windows command-line monitoring uses a different mechanism:
// Security Event Log (Event ID 4688 — Process Creation) or Sysmon Event ID 1.
// That is handled by the auth log collector reading the Security event log.
// A dedicated Sysmon/4688 collector is a future improvement.
func CollectAuditEvents(agentID int) {}
