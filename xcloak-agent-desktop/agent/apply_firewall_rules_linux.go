//go:build !windows

package agent

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"xcloak-agent-desktop/models"
)

// ApplyFirewallRules on Linux translates XCloak rules into iptables commands
// inside a dedicated XCLOAK chain, leaving any pre-existing host rules intact.
func ApplyFirewallRules(task models.AgentTask) (string, error) {

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

	// The XCLOAK chain and its hook into INPUT/FORWARD must exist before any
	// "-A XCLOAK ..." below can succeed — both calls are idempotent (a
	// second "-N" on an existing chain just errors harmlessly, and
	// hookChain checks before inserting). Previously this only ran inside
	// the "replace" branch, so "append" silently no-op'd every rule
	// (including the management-IP whitelist) on a host that had never
	// had a replace-mode sync.
	exec.Command("iptables", "-N", "XCLOAK").Run()
	hookChain("INPUT")
	hookChain("FORWARD")

	if payload.Mode == "replace" {
		exec.Command("iptables", "-F", "XCLOAK").Run()
		log = append(log, fmt.Sprintf("[replace] flushed XCLOAK chain (sync_id=%d)", payload.SyncID))
	} else {
		log = append(log, fmt.Sprintf("[append] adding to existing XCLOAK chain (sync_id=%d)", payload.SyncID))
	}

	if payload.AllowManage != "" {
		runIPT("-A", "XCLOAK", "-s", payload.AllowManage, "-j", "ACCEPT")
		runIPT("-A", "XCLOAK", "-d", payload.AllowManage, "-j", "ACCEPT")
		log = append(log, fmt.Sprintf("whitelist manage IP %s", payload.AllowManage))
	}

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

	return fmt.Sprintf("applied=%d skipped=%d sync_id=%d\n%s",
		applied, skipped, payload.SyncID, strings.Join(log, "\n")), nil
}

func ruleToIPTables(r SyncRule) ([]string, error) {
	action := "ACCEPT"
	if r.Action == "deny" || r.Action == "drop" {
		action = "DROP"
	} else if r.Action == "reject" {
		action = "REJECT"
	}

	args := []string{"iptables", "-A", "XCLOAK"}

	if r.SourceIP != "" && r.SourceIP != "any" && r.SourceIP != "0.0.0.0/0" {
		args = append(args, "-s", r.SourceIP)
	}
	if r.DestinationIP != "" && r.DestinationIP != "any" && r.DestinationIP != "0.0.0.0/0" {
		args = append(args, "-d", r.DestinationIP)
	}

	proto := strings.ToLower(r.Protocol)
	if proto != "" && proto != "any" {
		args = append(args, "-p", proto)
		if r.Port > 0 && (proto == "tcp" || proto == "udp") {
			args = append(args, "--dport", strconv.Itoa(r.Port))
		}
	}

	args = append(args, "-j", action)

	if r.Name != "" {
		args = append(args, "-m", "comment", "--comment",
			fmt.Sprintf("xcloak:%d:%s", r.ID, sanitizeComment(r.Name)))
	}

	return args, nil
}

func hookChain(parent string) {
	out, _ := exec.Command("iptables", "-L", parent, "-n").Output()
	if strings.Contains(string(out), "XCLOAK") {
		return
	}
	exec.Command("iptables", "-I", parent, "1", "-j", "XCLOAK").Run()
}

func runIPT(args ...string) {
	exec.Command("iptables", args...).Run()
}
