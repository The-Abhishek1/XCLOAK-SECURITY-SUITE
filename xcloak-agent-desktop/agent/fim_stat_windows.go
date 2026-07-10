//go:build windows

package agent

// fimFillStat is a no-op on Windows — UID/GID aren't meaningful on NTFS;
// file ownership comes from ACLs which require separate Win32 API calls.
func fimFillStat(entry *fimFileEntry, path string) {}
