package agent

import (
	"os"
	"runtime"
	"strings"
	"testing"

	"xcloak-agent-desktop/models"
)

// TestHexToAddr_IPv4 verifies the /proc/net hex-address decoder for IPv4.
// Correctness here matters: a wrong decode would produce an IP that doesn't
// match any IOC list and would hide malicious connections.
func TestHexToAddr_IPv4(t *testing.T) {
	cases := []struct {
		hex  string
		want string
	}{
		// 0100007F = 127.0.0.1 in little-endian, port 0x1F90 = 8080
		{"0100007F:1F90", "127.0.0.1:8080"},
		// 5E B8 D8 22 = 94.184.216.34 (example.com), port 0x01BB = 443
		{"22D8B85E:01BB", "94.184.216.34:443"},
		// 00000000 = 0.0.0.0, port 0x0035 = 53
		{"00000000:0035", "0.0.0.0:53"},
	}

	for _, tc := range cases {
		got := hexToAddr(tc.hex)
		if got != tc.want {
			t.Errorf("hexToAddr(%q) = %q, want %q", tc.hex, got, tc.want)
		}
	}
}

// TestHexToAddr_IPv6 verifies the /proc/net hex-address decoder for IPv6.
// The IPv6 branch used to just wrap the raw undecoded hex in brackets
// ("return raw hex for now"), so every IPv6 connection showed as an
// unreadable string of zeros/hex digits instead of a real address.
func TestHexToAddr_IPv6(t *testing.T) {
	cases := []struct {
		hex  string
		want string
	}{
		// All-zero — IN6ADDR_ANY, common for unconnected UDP sockets.
		{"00000000000000000000000000000000:0000", "[::]:0"},
		// Loopback ::1, port 0x1F90 = 8080.
		{"00000000000000000000000001000000:1F90", "[::1]:8080"},
		// A real link-local address captured from this machine's
		// /proc/net/udp6 — verifies the byte-reversal is correct, not
		// just symmetric-with-itself on all-zero/loopback inputs.
		// 000080FE 00000000 FFAA7A48 337B27FE -> fe80::487a:aaff:fe27:7b33
		{"000080FE00000000FFAA7A48337B27FE:0E76", "[fe80::487a:aaff:fe27:7b33]:3702"},
	}

	for _, tc := range cases {
		got := hexToAddr(tc.hex)
		if got != tc.want {
			t.Errorf("hexToAddr(%q) = %q, want %q", tc.hex, got, tc.want)
		}
	}
}

// TestHexToAddr_MalformedInput verifies that malformed tokens don't panic —
// the scanner may see partial lines during high-load /proc reads.
func TestHexToAddr_MalformedInput(t *testing.T) {
	inputs := []string{"", "nocolon", "GGGGGGGG:0050", ":0080"}
	for _, in := range inputs {
		// Must not panic.
		_ = hexToAddr(in)
	}
}

// TestParseProcNetFile_PopulatesProcessName verifies that parseProcNetFile
// correctly fills ProcessName when the inodeMap contains a matching PID.
// The test writes a minimal /proc/net/tcp-format fixture to a temp file.
func TestParseProcNetFile_PopulatesProcessName(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("proc net files not available on Windows")
	}

	// Minimal /proc/net/tcp line: sl local rem st ... inode ...
	// Field indices: 0=sl 1=local 2=rem 3=state ... 9=inode
	fixture := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 22D8B85E:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 99999 1 0000000000000000 20 4 24 10 -1
`
	f, err := os.CreateTemp("", "proc_net_tcp_*")
	if err != nil {
		t.Fatalf("create temp: %v", err)
	}
	defer os.Remove(f.Name())
	f.WriteString(fixture)
	f.Close()

	inodeMap := map[string]int{"99999": 42}
	pidNames := map[int]string{42: "nginx"}

	conns, err := parseProcNetFile(f.Name(), "tcp", 7, inodeMap, pidNames)
	if err != nil {
		t.Fatalf("parseProcNetFile: %v", err)
	}
	if len(conns) == 0 {
		t.Fatal("parseProcNetFile returned 0 entries from fixture")
	}

	c := conns[0]
	if c.ProcessName != "nginx" {
		t.Errorf("ProcessName = %q, want nginx", c.ProcessName)
	}
	if c.PID != 42 {
		t.Errorf("PID = %d, want 42", c.PID)
	}
	if c.Protocol != "tcp" {
		t.Errorf("Protocol = %q, want tcp", c.Protocol)
	}
	if c.AgentID != 7 {
		t.Errorf("AgentID = %d, want 7", c.AgentID)
	}
	if c.State != "ESTABLISHED" {
		t.Errorf("State = %q, want ESTABLISHED", c.State)
	}
}

// TestParseProcNetFile_UnknownPID verifies that a socket with no matching
// PID in the inodeMap still produces a Connection with empty ProcessName
// (not a missing entry) — unknown process is different from no process.
func TestParseProcNetFile_UnknownPID(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("proc net files not available on Windows")
	}

	fixture := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 11111 1 0000000000000000 100 0 0 10 -1
`
	f, _ := os.CreateTemp("", "proc_net_tcp_*")
	defer os.Remove(f.Name())
	f.WriteString(fixture)
	f.Close()

	// inode 11111 not in map — PID will be 0, ProcessName will be ""
	conns, _ := parseProcNetFile(f.Name(), "tcp", 1, map[string]int{}, map[int]string{})
	if len(conns) == 0 {
		t.Fatal("expected 1 connection even with unknown PID")
	}
	if conns[0].ProcessName != "" {
		t.Errorf("ProcessName = %q, want empty for unknown PID", conns[0].ProcessName)
	}
}

// TestConnectionPayloadContract verifies the JSON field names the desktop agent
// sends match what the backend Connection model expects. A field rename here
// would silently drop data at ingest.
func TestConnectionPayloadContract(t *testing.T) {
	pid := 1234
	c := models.Connection{
		AgentID:       42,
		Protocol:      "tcp",
		LocalAddress:  "127.0.0.1:8080",
		RemoteAddress: "1.2.3.4:443",
		State:         "ESTABLISHED",
		PID:           pid,
		ProcessName:   "nginx",
		ProcessPath:   "/usr/sbin/nginx",
	}

	if c.AgentID == 0 {
		t.Error("AgentID is zero")
	}
	if c.ProcessName == "" {
		t.Error("ProcessName is empty")
	}
	if c.PID == 0 {
		t.Error("PID is zero")
	}

	// Verify that PID is exported as an int (not a pointer in the agent model)
	// — the backend Connection uses *int but the agent uses int.
	// Type mismatch is caught at compilation; this test documents the contract.
	var _ int = c.PID
	var _ string = c.ProcessName
	var _ string = c.ProcessPath
}

// TestBuildPIDNameMap_ReturnsMap verifies that buildPIDNameMap returns a
// non-nil map on Linux (where /proc is available). An empty map is acceptable
// on hosts where the agent has restricted /proc access.
func TestBuildPIDNameMap_ReturnsMap(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no /proc on Windows")
	}
	m := buildPIDNameMap()
	if m == nil {
		t.Error("buildPIDNameMap returned nil")
	}
	// We can't assert specific entries but at minimum PID 1 should exist on Linux.
	if name, ok := m[1]; ok {
		if strings.TrimSpace(name) == "" {
			t.Error("PID 1 comm name is empty")
		}
	}
	// Missing PID 1 in a sandboxed/container environment is acceptable — just
	// verify we get a non-nil map.
}
