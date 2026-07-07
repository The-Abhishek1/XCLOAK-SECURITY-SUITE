//go:build !windows

package agent

import (
	"os"
	"syscall"
)

// fimFillStat populates UID/GID from the file's syscall.Stat_t on Linux/macOS.
func fimFillStat(entry *fimFileEntry, path string) {
	info, err := os.Lstat(path)
	if err != nil {
		return
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		entry.UID = int(stat.Uid)
		entry.GID = int(stat.Gid)
	}
}
