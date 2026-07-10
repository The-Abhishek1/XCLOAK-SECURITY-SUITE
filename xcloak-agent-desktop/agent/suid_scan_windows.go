//go:build windows

package agent

// SUIDBinary is defined here on Windows to satisfy any shared code that
// references the type. SUID/SGID is a UNIX concept; this is a no-op stub.
type SUIDBinary struct {
	AgentID  int    `json:"agent_id"`
	FilePath string `json:"file_path"`
	Mode     string `json:"mode"`
	UID      int    `json:"uid"`
	GID      int    `json:"gid"`
}

// CollectSUIDBinaries is a no-op on Windows.
func CollectSUIDBinaries(_ int) {}

func fillSUIDStat(_ *SUIDBinary, _ string) {}
