package agent

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"runtime"
	"strconv"
	"strings"

	"xcloak-agent/models"
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

type FirewallSyncPayload struct {
	Rules       []SyncRule `json:"rules"`
	Mode        string     `json:"mode"`         // "replace" | "append"
	AllowManage string     `json:"allow_manage"` // always-whitelist this IP
	SyncID      int64      `json:"sync_id"`
}

// ApplyFirewallRules translates XCloak rules into iptables commands.
// On Windows it prints a warning but returns without error.
func ApplyFirewallRules(task models.AgentTask) (string, error) {
	if runtime.GOOS == "windows" {
		return "Windows iptables sync not supported — use Windows Defender Firewall API", nil
	}

	if _, err := exec.LookPath("iptables"); err != nil {
		return "", fmt.Errorf("iptables not found on this host")
	}

	var payload FirewallSyncPayload
	if err := json.Unmarshal(task.Payload, &payload); err != nil {
		return "", fmt.Errorf("invalid payload: %w", err)
	}

	if len(payload.Rules) == 0 {
		return "no rules in payload — nothing applied", nil
	}

	var applied, skipped int
	var log []string

	if payload.Mode == "replace" {
		// Flush XCloak chain, recreate it.
		// We manage rules in a dedicated chain (XCLOAK) to avoid
		// trashing any existing host rules.
		exec.Command("iptables", "-N", "XCLOAK").Run() // create if not exists
		exec.Command("iptables", "-F", "XCLOAK").Run() // flush existing
		// Hook XCLOAK into INPUT and FORWARD if not already.
		hookChain("INPUT")
		hookChain("FORWARD")
		log = append(log, fmt.Sprintf("[replace] flushed XCLOAK chain (sync_id=%d)", payload.SyncID))
	}

	// Always allow management IP first.
	if payload.AllowManage != "" {
		runIPT("-A", "XCLOAK", "-s", payload.AllowManage, "-j", "ACCEPT")
		runIPT("-A", "XCLOAK", "-d", payload.AllowManage, "-j", "ACCEPT")
		log = append(log, fmt.Sprintf("whitelist manage IP %s", payload.AllowManage))
	}

	// Apply rules in priority order (payload already sorted by backend).
	for _, rule := range payload.Rules {
		cmd, err := ruleToIPTables(rule)
		if err != nil {
			log = append(log, fmt.Sprintf("SKIP rule %d (%s): %v", rule.ID, rule.Name, err))
			skipped++
			continue
		}

		out, execErr := exec.Command(cmd[0], cmd[1:]...).CombinedOutput()
		if execErr != nil {
			log = append(log, fmt.Sprintf("ERR rule %d (%s): %s %s", rule.ID, rule.Name, execErr, string(out)))
			skipped++
			continue
		}

		log = append(log, fmt.Sprintf("OK  rule %d (%s) → %s", rule.ID, rule.Name, describeRule(rule)))
		applied++
	}

	summary := fmt.Sprintf("applied=%d skipped=%d sync_id=%d\n%s",
		applied, skipped, payload.SyncID, strings.Join(log, "\n"))

	return summary, nil
}

// ruleToIPTables converts a SyncRule to an iptables -A XCLOAK command.
func ruleToIPTables(r SyncRule) ([]string, error) {
	action := "ACCEPT"
	if r.Action == "deny" || r.Action == "drop" {
		action = "DROP"
	} else if r.Action == "reject" {
		action = "REJECT"
	}

	args := []string{"iptables", "-A", "XCLOAK"}

	// Source IP / CIDR
	if r.SourceIP != "" && r.SourceIP != "any" && r.SourceIP != "0.0.0.0/0" {
		args = append(args, "-s", r.SourceIP)
	}

	// Destination IP / CIDR
	if r.DestinationIP != "" && r.DestinationIP != "any" && r.DestinationIP != "0.0.0.0/0" {
		args = append(args, "-d", r.DestinationIP)
	}

	// Protocol
	proto := strings.ToLower(r.Protocol)
	if proto != "" && proto != "any" {
		args = append(args, "-p", proto)

		// Port (only valid for tcp/udp)
		if r.Port > 0 && (proto == "tcp" || proto == "udp") {
			args = append(args, "--dport", strconv.Itoa(r.Port))
		}
	}

	args = append(args, "-j", action)

	// Add comment so rules are traceable.
	if r.Name != "" {
		args = append(args, "-m", "comment", "--comment",
			fmt.Sprintf("xcloak:%d:%s", r.ID, sanitizeComment(r.Name)))
	}

	return args, nil
}

func hookChain(parent string) {
	// Check if XCLOAK is already in parent chain.
	out, _ := exec.Command("iptables", "-L", parent, "-n").Output()
	if strings.Contains(string(out), "XCLOAK") {
		return
	}
	exec.Command("iptables", "-I", parent, "1", "-j", "XCLOAK").Run()
}

func runIPT(args ...string) {
	exec.Command("iptables", args...).Run()
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
	// iptables comment must be ≤ 256 chars, no special chars
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
