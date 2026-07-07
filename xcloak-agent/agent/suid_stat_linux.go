//go:build !windows

package agent

import (
	"os"
	"syscall"
)

func fillSUIDStat(entry *SUIDBinary, path string) {
	info, err := os.Lstat(path)
	if err != nil {
		return
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		entry.UID = int(stat.Uid)
		entry.GID = int(stat.Gid)
	}
}
