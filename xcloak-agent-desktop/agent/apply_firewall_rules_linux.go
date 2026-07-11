//go:build !windows

package agent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"xcloak-agent-desktop/models"
)

// ApplyFirewallRules on Linux translates XCloak rules into iptables rules
// inside a dedicated XCLOAK chain. Uses iptables-restore for atomic apply so
// the ruleset is never partially applied during a replace sync.
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

	// Try atomic iptables-restore path; fall back to incremental if not available.
	if _, err := exec.LookPath("iptables-restore"); err == nil {
		return applyAtomicLinux(payload)
	}
	return applyIncrementalLinux(payload)
}

// ─────────────────────────────────────────────────────────────────────────────
// Atomic path: build a full iptables-restore script and pipe it in one shot.
// ─────────────────────────────────────────────────────────────────────────────

func applyAtomicLinux(payload FirewallSyncPayload) (string, error) {
	var buf bytes.Buffer
	var log []string
	var applied, skipped int

	buf.WriteString("*filter\n")

	// In replace mode we flush the XCLOAK chain; in append mode we leave it.
	if payload.Mode == "replace" {
		buf.WriteString(":XCLOAK - [0:0]\n")
		buf.WriteString("-F XCLOAK\n")
		log = append(log, fmt.Sprintf("[replace] flushed XCLOAK chain (sync_id=%d)", payload.SyncID))
	} else {
		buf.WriteString(":XCLOAK - [0:0]\n")
		log = append(log, fmt.Sprintf("[append] adding to XCLOAK chain (sync_id=%d)", payload.SyncID))
	}

	// Default policy tail rule.
	if payload.DefaultAction == "deny" {
		buf.WriteString("-A XCLOAK -j DROP\n")
	}

	// Management IP whitelist.
	if payload.AllowManage != "" {
		buf.WriteString(fmt.Sprintf("-A XCLOAK -s %s -j ACCEPT\n", payload.AllowManage))
		buf.WriteString(fmt.Sprintf("-A XCLOAK -d %s -j ACCEPT\n", payload.AllowManage))
		log = append(log, fmt.Sprintf("whitelist manage IP %s", payload.AllowManage))
	}

	for _, rule := range payload.Rules {
		lines, err := ruleToIPTablesLines(rule)
		if err != nil {
			log = append(log, fmt.Sprintf("SKIP rule %d (%s): %v", rule.ID, rule.Name, err))
			skipped++
			continue
		}
		for _, l := range lines {
			buf.WriteString(l + "\n")
		}
		log = append(log, fmt.Sprintf("OK  rule %d (%s) → %s", rule.ID, rule.Name, describeRule(rule)))
		applied++
	}
	buf.WriteString("COMMIT\n")

	// Ensure the chain exists and is hooked before restore.
	exec.Command("iptables", "-N", "XCLOAK").Run()
	hookChain("INPUT")
	hookChain("OUTPUT")
	hookChain("FORWARD")

	cmd := exec.Command("iptables-restore", "--noflush")
	cmd.Stdin = &buf
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("iptables-restore failed: %s — %s", err, strings.TrimSpace(string(out)))
	}

	return fmt.Sprintf("applied=%d skipped=%d sync_id=%d (atomic)\n%s",
		applied, skipped, payload.SyncID, strings.Join(log, "\n")), nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Incremental fallback (iptables-restore not available)
// ─────────────────────────────────────────────────────────────────────────────

func applyIncrementalLinux(payload FirewallSyncPayload) (string, error) {
	var applied, skipped int
	var log []string

	exec.Command("iptables", "-N", "XCLOAK").Run()
	hookChain("INPUT")
	hookChain("OUTPUT")
	hookChain("FORWARD")

	if payload.Mode == "replace" {
		exec.Command("iptables", "-F", "XCLOAK").Run()
		log = append(log, fmt.Sprintf("[replace] flushed XCLOAK chain (sync_id=%d)", payload.SyncID))
	} else {
		log = append(log, fmt.Sprintf("[append] adding to XCLOAK chain (sync_id=%d)", payload.SyncID))
	}

	if payload.AllowManage != "" {
		runIPT("-A", "XCLOAK", "-s", payload.AllowManage, "-j", "ACCEPT")
		runIPT("-A", "XCLOAK", "-d", payload.AllowManage, "-j", "ACCEPT")
		log = append(log, fmt.Sprintf("whitelist manage IP %s", payload.AllowManage))
	}

	for _, rule := range payload.Rules {
		lines, err := ruleToIPTablesLines(rule)
		if err != nil {
			log = append(log, fmt.Sprintf("SKIP rule %d (%s): %v", rule.ID, rule.Name, err))
			skipped++
			continue
		}
		var ruleFailed bool
		for _, l := range lines {
			// Strip leading "-A XCLOAK " prefix and split into args for exec.
			args := strings.Fields(l)
			if len(args) < 2 {
				continue
			}
			// l is like "-A XCLOAK -p tcp ..." — prepend iptables.
			fullArgs := append([]string{"iptables"}, args...)
			out, execErr := exec.Command(fullArgs[0], fullArgs[1:]...).CombinedOutput()
			if execErr != nil {
				log = append(log, fmt.Sprintf("ERR rule %d (%s): %s %s", rule.ID, rule.Name, execErr, string(out)))
				ruleFailed = true
				break
			}
		}
		if ruleFailed {
			skipped++
		} else {
			log = append(log, fmt.Sprintf("OK  rule %d (%s) → %s", rule.ID, rule.Name, describeRule(rule)))
			applied++
		}
	}

	if payload.DefaultAction == "deny" {
		runIPT("-A", "XCLOAK", "-j", "DROP")
	}

	return fmt.Sprintf("applied=%d skipped=%d sync_id=%d\n%s",
		applied, skipped, payload.SyncID, strings.Join(log, "\n")), nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Rule translation
// ─────────────────────────────────────────────────────────────────────────────

// ruleToIPTablesLines returns one or two iptables rule strings (without the
// "iptables" binary prefix) for a SyncRule. Two lines are generated when
// direction == "both" (one for INPUT chain hint via -A XCLOAK, which is
// already hooked into INPUT and OUTPUT).
//
// For direction-aware routing:
//   - "in"  → only hook via INPUT (we just use -A XCLOAK with comment)
//   - "out" → only hook via OUTPUT
//   - "both"→ one rule covers both directions via XCLOAK chain
func ruleToIPTablesLines(r SyncRule) ([]string, error) {
	target := actionToTarget(r.Action)

	// Build common args (without chain and without the binary).
	common, err := buildCommonArgs(r)
	if err != nil {
		return nil, err
	}

	if r.LogEnabled && r.Action != "log" {
		// Prepend a LOG rule before the terminal action.
		logPrefix := r.LogPrefix
		if logPrefix == "" {
			logPrefix = fmt.Sprintf("xcloak:%d: ", r.ID)
		}
		logArgs := append([]string{"-A", "XCLOAK"}, common...)
		logArgs = append(logArgs, "-j", "LOG", "--log-prefix", logPrefix, "--log-level", "4")
		termArgs := append([]string{"-A", "XCLOAK"}, common...)
		termArgs = append(termArgs, "-j", target)
		return []string{
			strings.Join(logArgs, " "),
			strings.Join(termArgs, " "),
		}, nil
	}

	args := append([]string{"-A", "XCLOAK"}, common...)
	args = append(args, "-j", target)
	return []string{strings.Join(args, " ")}, nil
}

func buildCommonArgs(r SyncRule) ([]string, error) {
	var args []string

	if r.SourceIP != "" && !isWildcardIP(r.SourceIP) {
		args = append(args, "-s", r.SourceIP)
	}
	if r.DestinationIP != "" && !isWildcardIP(r.DestinationIP) {
		args = append(args, "-d", r.DestinationIP)
	}

	proto := strings.ToLower(r.Protocol)
	if proto != "" && proto != "any" {
		args = append(args, "-p", proto)

		portSpec := effectivePortSpec(r)
		if portSpec != "" && (proto == "tcp" || proto == "udp") {
			if strings.ContainsAny(portSpec, ",-") {
				// Multi-port or range — use -m multiport.
				// iptables multiport uses commas for lists and ":" for ranges.
				multiSpec := strings.ReplaceAll(portSpec, "-", ":")
				args = append(args, "-m", "multiport", "--dports", multiSpec)
			} else {
				args = append(args, "--dport", portSpec)
			}
		}
	}

	if r.Name != "" {
		args = append(args, "-m", "comment", "--comment",
			fmt.Sprintf("xcloak:%d:%s", r.ID, sanitizeComment(r.Name)))
	}

	return args, nil
}

func actionToTarget(action string) string {
	switch strings.ToLower(action) {
	case "deny", "drop":
		return "DROP"
	case "reject":
		return "REJECT"
	case "log":
		return "LOG"
	default:
		return "ACCEPT"
	}
}

func isWildcardIP(ip string) bool {
	return ip == "" || ip == "any" || ip == "0.0.0.0/0" || ip == "::/0"
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
