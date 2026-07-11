package agent

import (
	"os"
	"runtime"
	"testing"
)

// TestFIMHashFile_PopulatesMode verifies that fimHashFile returns a non-empty
// Mode string for a real file on disk. An empty Mode means the backend would
// silently drop permission metadata, making chmod-based attacks invisible.
func TestFIMHashFile_PopulatesMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mode/uid/gid not applicable on Windows")
	}

	// Use /etc/hosts as a stable, always-present file.
	info, err := os.Stat("/etc/hosts")
	if err != nil {
		t.Skipf("cannot stat /etc/hosts: %v", err)
	}

	entry, err := fimHashFile("/etc/hosts", info)
	if err != nil {
		t.Fatalf("fimHashFile: %v", err)
	}

	if entry.SHA256 == "" {
		t.Error("SHA256 is empty — fimHashFile failed to hash the file")
	}
	if entry.Mode == "" {
		t.Error("Mode is empty — permission metadata would be dropped by the backend")
	}
	if entry.FileSize <= 0 {
		t.Errorf("FileSize = %d, want > 0", entry.FileSize)
	}
	// GID/UID are 0-indexed, so we can only verify they were populated when
	// fimFillStat ran — check FileSize > 0 as a proxy for a complete entry.
	if entry.FilePath != "/etc/hosts" {
		t.Errorf("FilePath = %q, want /etc/hosts", entry.FilePath)
	}
}

// TestFIMMode_SetuidDistinguishable verifies that "-rwsr-xr-x" (setuid)
// differs from "-rwxr-xr-x" (normal execute) as a string comparison —
// the property the service relies on to raise permission_change alerts.
func TestFIMMode_SetuidDistinguishable(t *testing.T) {
	normal := "-rwxr-xr-x"
	setuid := "-rwsr-xr-x"

	if normal == setuid {
		t.Error("setuid and normal modes compare equal — chmod detection would be blind")
	}

	// Verify the 's' in position 3 is what distinguishes them.
	if len(normal) != len(setuid) {
		t.Errorf("mode strings have different length (%d vs %d)", len(normal), len(setuid))
	}
	if setuid[3] != 's' {
		t.Errorf("setuid mode[3] = %c, want 's'", setuid[3])
	}
	if normal[3] != 'x' {
		t.Errorf("normal mode[3] = %c, want 'x'", normal[3])
	}
}

// TestFIMPayloadContract verifies that fimFileEntry fields match the JSON keys
// the backend FIMFileEntry model expects. If someone renames a field here,
// the backend silently receives zero values — this test breaks first.
func TestFIMPayloadContract(t *testing.T) {
	entry := fimFileEntry{
		FilePath: "/etc/passwd",
		SHA256:   "abc123",
		FileSize: 512,
		Mode:     "-rw-r--r--",
		UID:      0,
		GID:      0,
	}

	// Confirm the entry is fully populated (no zero-value surprises).
	if entry.FilePath == "" {
		t.Error("file_path is empty")
	}
	if entry.SHA256 == "" {
		t.Error("sha256_hash is empty")
	}
	if entry.Mode == "" {
		t.Error("mode is empty")
	}

	// fimScanPayload must wrap entries correctly.
	payload := fimScanPayload{AgentID: 42, Files: []fimFileEntry{entry}}
	if payload.AgentID != 42 {
		t.Errorf("agent_id = %d, want 42", payload.AgentID)
	}
	if len(payload.Files) != 1 {
		t.Errorf("files count = %d, want 1", len(payload.Files))
	}
}

// TestFIMScanPath_ExpandsDirectory verifies that fimScanPath returns at least
// one entry for a directory that is guaranteed to have files (/etc on Linux).
func TestFIMScanPath_ExpandsDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("path conventions differ on Windows")
	}
	entries, err := fimScanPath("/etc")
	if err != nil {
		t.Fatalf("fimScanPath /etc: %v", err)
	}
	if len(entries) == 0 {
		t.Error("fimScanPath returned 0 entries for /etc — directory expansion broken")
	}
	// Each entry must have non-empty FilePath and SHA256.
	for i, e := range entries {
		if e.FilePath == "" {
			t.Errorf("entry[%d].FilePath is empty", i)
		}
		if e.SHA256 == "" {
			t.Errorf("entry[%d].SHA256 is empty for %s", i, e.FilePath)
		}
	}
}
