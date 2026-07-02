package services

import (
	"testing"
	"time"
)

// ── isOffHours ────────────────────────────────────────────────────────────────

func TestIsOffHours(t *testing.T) {
	// Monday 2024-01-15, times in UTC
	loc := time.UTC
	tests := []struct {
		name string
		t    time.Time
		want bool
	}{
		{"monday 10am — business hours", time.Date(2024, 1, 15, 10, 0, 0, 0, loc), false},
		{"monday 8am — boundary start", time.Date(2024, 1, 15, 8, 0, 0, 0, loc), false},
		{"monday 7:59am — before start", time.Date(2024, 1, 15, 7, 59, 0, 0, loc), true},
		{"monday 19:59pm — last business hour", time.Date(2024, 1, 15, 19, 59, 0, 0, loc), false},
		{"monday 20:00pm — boundary end", time.Date(2024, 1, 15, 20, 0, 0, 0, loc), true},
		{"monday 23pm — late night", time.Date(2024, 1, 15, 23, 0, 0, 0, loc), true},
		{"saturday — weekend", time.Date(2024, 1, 13, 10, 0, 0, 0, loc), true},
		{"sunday — weekend", time.Date(2024, 1, 14, 10, 0, 0, 0, loc), true},
		{"friday 10am — still business", time.Date(2024, 1, 19, 10, 0, 0, 0, loc), false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := isOffHours(tc.t)
			if got != tc.want {
				t.Errorf("isOffHours(%v) = %v, want %v", tc.t, got, tc.want)
			}
		})
	}
}

func TestOffHoursSuffix(t *testing.T) {
	loc := time.UTC
	biz := time.Date(2024, 1, 15, 10, 0, 0, 0, loc)
	off := time.Date(2024, 1, 13, 10, 0, 0, 0, loc)

	if s := offHoursSuffix(biz); s != "" {
		t.Errorf("offHoursSuffix(business hour) = %q, want empty", s)
	}
	if s := offHoursSuffix(off); s != " (off-hours)" {
		t.Errorf("offHoursSuffix(off-hours) = %q, want \" (off-hours)\"", s)
	}
}

// ── uebaSnip ─────────────────────────────────────────────────────────────────

func TestUEBASnip(t *testing.T) {
	tests := []struct {
		input string
		n     int
		want  string
	}{
		{"hello world", 20, "hello world"},
		{"hello world", 5, "hello…"},
		{"", 10, ""},
		{"abc", 3, "abc"},
		{"abcd", 3, "abc…"},
	}
	for _, tc := range tests {
		got := uebaSnip(tc.input, tc.n)
		if got != tc.want {
			t.Errorf("uebaSnip(%q, %d) = %q, want %q", tc.input, tc.n, got, tc.want)
		}
	}
}

// ── Log parsing regexes ───────────────────────────────────────────────────────

func TestReFailedPassword(t *testing.T) {
	cases := []struct {
		line     string
		username string
		ip       string
	}{
		{
			"Failed password for alice from 1.2.3.4 port 22 ssh2",
			"alice", "1.2.3.4",
		},
		{
			"Failed password for invalid user bob from 10.0.0.1 port 55123 ssh2",
			"bob", "10.0.0.1",
		},
		{
			"Failed password for root from 2001:db8::1 port 22 ssh2",
			"root", "2001:db8::1",
		},
	}
	for _, tc := range cases {
		m := reFailedPassword.FindStringSubmatch(tc.line)
		if len(m) < 3 {
			t.Errorf("reFailedPassword did not match %q", tc.line)
			continue
		}
		if m[1] != tc.username {
			t.Errorf("username: got %q, want %q (line=%q)", m[1], tc.username, tc.line)
		}
		if m[2] != tc.ip {
			t.Errorf("ip: got %q, want %q (line=%q)", m[2], tc.ip, tc.line)
		}
	}
}

func TestReAcceptedPassword(t *testing.T) {
	cases := []struct {
		line     string
		username string
		ip       string
	}{
		{
			"Accepted password for alice from 1.2.3.4 port 22 ssh2",
			"alice", "1.2.3.4",
		},
		{
			"Accepted publickey for deploy from 10.20.30.40 port 44444 ssh2",
			"deploy", "10.20.30.40",
		},
	}
	for _, tc := range cases {
		m := reAcceptedPassword.FindStringSubmatch(tc.line)
		if len(m) < 3 {
			t.Errorf("reAcceptedPassword did not match %q", tc.line)
			continue
		}
		if m[1] != tc.username {
			t.Errorf("username: got %q, want %q", m[1], tc.username)
		}
		if m[2] != tc.ip {
			t.Errorf("ip: got %q, want %q", m[2], tc.ip)
		}
	}
}

func TestReSudo(t *testing.T) {
	line := "sudo:  alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash"
	m := reSudo.FindStringSubmatch(line)
	if len(m) < 3 {
		t.Fatalf("reSudo did not match %q", line)
	}
	if m[1] != "alice" {
		t.Errorf("username: got %q, want %q", m[1], "alice")
	}
	if m[2] != "/bin/bash" {
		t.Errorf("command: got %q, want %q", m[2], "/bin/bash")
	}
}

func TestRePrivEsc(t *testing.T) {
	positive := []string{
		"su[12345]: pam_unix(su:session): session opened for user root",
		"newgrp[99]: invoked by user alice to root",
		"usermod -aG wheel alice for root",
	}
	negative := []string{
		"Failed password for alice from 1.2.3.4",
		"Accepted publickey for deploy from 10.0.0.1",
	}
	for _, s := range positive {
		if !rePrivEsc.MatchString(s) {
			t.Errorf("rePrivEsc should match %q", s)
		}
	}
	for _, s := range negative {
		if rePrivEsc.MatchString(s) {
			t.Errorf("rePrivEsc should NOT match %q", s)
		}
	}
}

func TestReSessionOpened(t *testing.T) {
	line := "pam_unix(sshd:session): session opened for user alice by (uid=0)"
	m := reSessionOpened.FindStringSubmatch(line)
	if len(m) < 2 {
		t.Fatalf("reSessionOpened did not match %q", line)
	}
	if m[1] != "alice" {
		t.Errorf("username: got %q, want alice", m[1])
	}
}
