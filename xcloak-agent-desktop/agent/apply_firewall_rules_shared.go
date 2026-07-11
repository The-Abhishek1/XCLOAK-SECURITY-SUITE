package agent

import (
	"fmt"
	"strings"
)

// SyncRule mirrors the wire format from the backend (enterprise fields included).
type SyncRule struct {
	ID            int      `json:"id"`
	Name          string   `json:"name"`
	SourceIP      string   `json:"source_ip"`
	DestinationIP string   `json:"destination_ip"`
	Protocol      string   `json:"protocol"`
	Port          int      `json:"port"`
	PortRange     string   `json:"port_range"`  // "80", "8000-9000", "80,443"
	Direction     string   `json:"direction"`   // "in" | "out" | "both"
	LogEnabled    bool     `json:"log_enabled"`
	LogPrefix     string   `json:"log_prefix"`
	Action        string   `json:"action"`
	Priority      int      `json:"priority"`
	Tags          []string `json:"tags"`
}

// FirewallSyncPayload is the task payload dispatched from the backend.
type FirewallSyncPayload struct {
	Rules         []SyncRule `json:"rules"`
	Mode          string     `json:"mode"`          // "replace" | "append"
	AllowManage   string     `json:"allow_manage"`  // always-whitelist this IP
	DefaultAction string     `json:"default_action"` // "allow" | "deny"
	SyncID        int64      `json:"sync_id"`
}

// effectivePortSpec returns the iptables/netsh port specification for a rule.
// Prefers PortRange if set, falls back to Port.
func effectivePortSpec(r SyncRule) string {
	if r.PortRange != "" {
		return r.PortRange
	}
	if r.Port > 0 {
		return fmt.Sprintf("%d", r.Port)
	}
	return ""
}

func describeRule(r SyncRule) string {
	src := r.SourceIP
	if src == "" {
		src = "any"
	}
	dst := r.DestinationIP
	if dst == "" {
		dst = "any"
	}
	portSpec := effectivePortSpec(r)
	portStr := ""
	if portSpec != "" {
		portStr = ":" + portSpec
	}
	dir := r.Direction
	if dir == "" {
		dir = "both"
	}
	return fmt.Sprintf("[%s] %s→%s%s %s %s", dir, src, dst, portStr, r.Protocol, r.Action)
}

func sanitizeComment(s string) string {
	s = strings.Map(func(r rune) rune {
		if r >= 32 && r < 127 && r != '"' && r != '\'' {
			return r
		}
		return '_'
	}, s)
	if len(s) > 60 {
		s = s[:60]
	}
	return s
}
