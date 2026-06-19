package agent

import (
	"fmt"
	"strings"
)

// SyncRule mirrors the wire format from the backend.
type SyncRule struct {
	ID            int    `json:"id"`
	Name          string `json:"name"`
	SourceIP      string `json:"source_ip"`
	DestinationIP string `json:"destination_ip"`
	Protocol      string `json:"protocol"`
	Port          int    `json:"port"`
	Action        string `json:"action"`
	Priority      int    `json:"priority"`
}

// FirewallSyncPayload is the task payload dispatched from the backend.
type FirewallSyncPayload struct {
	Rules       []SyncRule `json:"rules"`
	Mode        string     `json:"mode"`         // "replace" | "append"
	AllowManage string     `json:"allow_manage"` // always-whitelist this IP
	SyncID      int64      `json:"sync_id"`
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
	port := ""
	if r.Port > 0 {
		port = fmt.Sprintf(":%d", r.Port)
	}
	return fmt.Sprintf("%s→%s%s %s %s", src, dst, port, r.Protocol, r.Action)
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
