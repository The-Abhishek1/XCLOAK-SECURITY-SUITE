//go:build !linux

package agent

import "xcloak-agent-desktop/models"

// EnrichConnectEventDPI is a no-op stub on non-Linux platforms.
// Full passive DPI requires /proc/net and /proc/<pid>/fd access.
func EnrichConnectEventDPI(ev models.ConnectEvent) models.ConnectEvent {
	return ev
}
