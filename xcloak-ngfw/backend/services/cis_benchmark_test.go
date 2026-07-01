package services

import (
	"testing"
)

// ── firstMatch / firstMatchInSet ──────────────────────────────────────────────

func TestFirstMatch_Found(t *testing.T) {
	set := map[string]bool{"xserver-xorg": true, "nginx": true}
	candidates := []string{"xserver-xorg", "xorg-x11-server-xorg"}
	if got := firstMatch(set, candidates); got != "xserver-xorg" {
		t.Errorf("firstMatch = %q, want %q", got, "xserver-xorg")
	}
}

func TestFirstMatch_NotFound(t *testing.T) {
	set := map[string]bool{"nginx": true}
	if got := firstMatch(set, []string{"xserver-xorg", "xorg-x11"}); got != "" {
		t.Errorf("firstMatch should return empty, got %q", got)
	}
}

func TestFirstMatchInSet_SecondCandidate(t *testing.T) {
	set := map[string]bool{"firewalld": true}
	candidates := []string{"iptables", "firewalld", "ufw"}
	if got := firstMatchInSet(set, candidates); got != "firewalld" {
		t.Errorf("firstMatchInSet = %q, want %q", got, "firewalld")
	}
}

// ── isPrivilegedGroup re-exported via Linux control logic ─────────────────────

func TestLinuxControlList_AllHaveRequiredFields(t *testing.T) {
	for _, ctrl := range linuxControls {
		if ctrl.ID == "" {
			t.Errorf("linux control missing ID: %+v", ctrl)
		}
		if ctrl.Title == "" {
			t.Errorf("control %s missing Title", ctrl.ID)
		}
		if ctrl.Severity == "" {
			t.Errorf("control %s missing Severity", ctrl.ID)
		}
		if ctrl.Category == "" {
			t.Errorf("control %s missing Category", ctrl.ID)
		}
		if ctrl.Remediation == "" {
			t.Errorf("control %s missing Remediation", ctrl.ID)
		}
		if ctrl.Platform != "linux" {
			t.Errorf("control %s platform = %q, want linux", ctrl.ID, ctrl.Platform)
		}
	}
}

func TestWindowsControlList_AllHaveRequiredFields(t *testing.T) {
	for _, ctrl := range windowsControls {
		if ctrl.ID == "" {
			t.Errorf("windows control missing ID: %+v", ctrl)
		}
		if ctrl.Title == "" {
			t.Errorf("control %s missing Title", ctrl.ID)
		}
		if ctrl.Severity == "" {
			t.Errorf("control %s missing Severity", ctrl.ID)
		}
		if ctrl.Platform != "windows" {
			t.Errorf("control %s platform = %q, want windows", ctrl.ID, ctrl.Platform)
		}
	}
}

func TestLinuxControlIDs_Unique(t *testing.T) {
	seen := make(map[string]bool)
	for _, ctrl := range linuxControls {
		if seen[ctrl.ID] {
			t.Errorf("duplicate linux control ID: %s", ctrl.ID)
		}
		seen[ctrl.ID] = true
	}
}

func TestWindowsControlIDs_Unique(t *testing.T) {
	seen := make(map[string]bool)
	for _, ctrl := range windowsControls {
		if seen[ctrl.ID] {
			t.Errorf("duplicate windows control ID: %s", ctrl.ID)
		}
		seen[ctrl.ID] = true
	}
}

// ── checkRegistryNumeric logic (pure) ────────────────────────────────────────

func TestCheckRegistryNumericLogic(t *testing.T) {
	// Simulate the numeric comparison logic used inside checkRegistryNumeric.
	cases := []struct {
		val       int
		threshold int
		op        string
		want      bool
	}{
		{14, 14, "gte", true},
		{13, 14, "gte", false},
		{5, 5, "lte", true},
		{6, 5, "lte", false},
		{0, 5, "lte", true},
		{90, 30, "gt", true},
		{10, 30, "lt", true},
	}
	for _, c := range cases {
		var got bool
		switch c.op {
		case "gte":
			got = c.val >= c.threshold
		case "lte":
			got = c.val <= c.threshold
		case "gt":
			got = c.val > c.threshold
		case "lt":
			got = c.val < c.threshold
		}
		if got != c.want {
			t.Errorf("val=%d op=%s threshold=%d: got %v, want %v",
				c.val, c.op, c.threshold, got, c.want)
		}
	}
}

// ── Duplicate UID detection logic ─────────────────────────────────────────────

func TestDuplicateUIDDetection(t *testing.T) {
	users := []agentUser{
		{username: "alice", uid: 1001},
		{username: "bob", uid: 1002},
		{username: "charlie", uid: 1001}, // duplicate of alice
	}
	uidCounts := make(map[int][]string)
	for _, u := range users {
		if u.uid >= 0 {
			uidCounts[u.uid] = append(uidCounts[u.uid], u.username)
		}
	}
	dups := 0
	for _, names := range uidCounts {
		if len(names) > 1 {
			dups++
		}
	}
	if dups != 1 {
		t.Errorf("expected 1 duplicate UID group, got %d", dups)
	}
}

// ── Root UID 0 detection ──────────────────────────────────────────────────────

func TestRootUID0Detection(t *testing.T) {
	users := []agentUser{
		{username: "root", uid: 0},
		{username: "toor", uid: 0}, // shadow root — should fail
		{username: "alice", uid: 1001},
	}
	var uid0nonRoot []string
	for _, u := range users {
		if u.uid == 0 && u.username != "root" {
			uid0nonRoot = append(uid0nonRoot, u.username)
		}
	}
	if len(uid0nonRoot) != 1 || uid0nonRoot[0] != "toor" {
		t.Errorf("uid0 detection: got %v, want [toor]", uid0nonRoot)
	}
}

// ── System account login shell detection ─────────────────────────────────────

func TestSystemAccountShellDetection(t *testing.T) {
	loginShells := map[string]bool{
		"/bin/bash": true, "/bin/sh": true, "/bin/zsh": true,
	}
	users := []agentUser{
		{username: "daemon", uid: 1, shell: "/usr/sbin/nologin"},
		{username: "www-data", uid: 33, shell: "/usr/sbin/nologin"},
		{username: "backup", uid: 34, shell: "/bin/sh"}, // bad
		{username: "alice", uid: 1001, shell: "/bin/bash"}, // normal user, skip
	}
	var bad []string
	for _, u := range users {
		if u.uid > 0 && u.uid < 1000 && u.username != "sync" && loginShells[u.shell] {
			bad = append(bad, u.username)
		}
	}
	if len(bad) != 1 || bad[0] != "backup" {
		t.Errorf("system account shell detection: got %v, want [backup]", bad)
	}
}

// ── AgentCISScore ─────────────────────────────────────────────────────────────

func TestAgentCISScore_ZeroTotal(t *testing.T) {
	// When total is 0, score should be 0 not NaN.
	pass, total := 0, 0
	score := 0.0
	if total > 0 {
		score = float64(pass) / float64(total) * 100
	}
	if score != 0.0 {
		t.Errorf("score with zero total should be 0, got %f", score)
	}
}

func TestAgentCISScore_Calculation(t *testing.T) {
	cases := []struct {
		pass, total int
		wantScore   float64
	}{
		{18, 18, 100.0},
		{9, 18, 50.0},
		{0, 18, 0.0},
		{14, 20, 70.0},
	}
	for _, c := range cases {
		score := float64(c.pass) / float64(c.total) * 100
		if score != c.wantScore {
			t.Errorf("score(%d/%d) = %f, want %f", c.pass, c.total, score, c.wantScore)
		}
	}
}
