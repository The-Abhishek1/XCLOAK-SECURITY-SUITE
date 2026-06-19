//go:build !windows

package agent

// CollectRegistryPersistence is a no-op on Linux/macOS.
// Registry monitoring is Windows-only. Linux persistence is covered by
// the FIM watcher (crontab, systemd units, rc.local) and the auditd collector.
func CollectRegistryPersistence(agentID int) {}
