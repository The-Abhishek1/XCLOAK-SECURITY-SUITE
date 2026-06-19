//go:build windows

package agent

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"xcloak-agent/models"
)

// ApplyFirewallRules on Windows translates XCloak rules into Windows Defender
// Firewall rules using the `netsh advfirewall firewall` CLI.
//
// Rules are namespaced with "XCloak-<id>-<name>" so they can be cleanly
// flushed on a "replace" sync without touching any pre-existing host rules.
//
// Requires elevated privileges (the agent must run as Administrator or
// LocalSystem). Returns an error if netsh is not available.
func ApplyFirewallRules(task models.AgentTask) (string, error) {

	if _, err := exec.LookPath("netsh"); err != nil {
		return "", fmt.Errorf("netsh not found — is this running as Administrator?")
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

	// ── Replace mode: delete all existing XCloak rules ───────────
	if payload.Mode == "replace" {
		deleteXCloakRules()
		log = append(log, fmt.Sprintf("[replace] flushed XCloak rules (sync_id=%d)", payload.SyncID))
	}

	// ── Always allow management IP ────────────────────────────────
	if payload.AllowManage != "" {
		addAllowRule(
			fmt.Sprintf("XCloak-manage-in-%s", sanitizeRuleName(payload.AllowManage)),
			"in", payload.AllowManage, "", "", 0,
		)
		addAllowRule(
			fmt.Sprintf("XCloak-manage-out-%s", sanitizeRuleName(payload.AllowManage)),
			"out", "", payload.AllowManage, "", 0,
		)
		log = append(log, fmt.Sprintf("allowed manage IP %s (in+out)", payload.AllowManage))
	}

	// ── Apply rules ───────────────────────────────────────────────
	for _, rule := range payload.Rules {
		errs := applyWDFRule(rule)
		if errs != nil {
			log = append(log, fmt.Sprintf("ERR rule %d (%s): %v", rule.ID, rule.Name, errs))
			skipped++
			continue
		}
		log = append(log, fmt.Sprintf("OK  rule %d (%s) → %s", rule.ID, rule.Name, describeRule(rule)))
		applied++
	}

	return fmt.Sprintf("applied=%d skipped=%d sync_id=%d\n%s",
		applied, skipped, payload.SyncID, strings.Join(log, "\n")), nil
}

// applyWDFRule creates one or two netsh rules for a SyncRule.
// Windows Defender Firewall requires separate rules for inbound and outbound,
// so we create both for rules without a direction specified.
func applyWDFRule(r SyncRule) error {
	action := "allow"
	if r.Action == "deny" || r.Action == "drop" || r.Action == "reject" {
		action = "block"
	}

	ruleName := fmt.Sprintf("XCloak-%d-%s", r.ID, sanitizeRuleName(r.Name))

	proto := strings.ToLower(r.Protocol)
	if proto == "" || proto == "any" {
		proto = "any"
	}

	portStr := ""
	if r.Port > 0 && (proto == "tcp" || proto == "udp") {
		portStr = strconv.Itoa(r.Port)
	}

	// Build the base netsh args shared by inbound and outbound rules.
	base := []string{
		"advfirewall", "firewall", "add", "rule",
		"name=" + ruleName,
		"protocol=" + proto,
		"action=" + action,
		"enable=yes",
		"profile=any",
	}

	if proto != "any" && portStr != "" {
		base = append(base, "localport="+portStr)
	}

	// Inbound rule (remoteip = source, localip = destination)
	inArgs := append([]string{"netsh"}, base...)
	inArgs = append(inArgs, "dir=in")
	if r.SourceIP != "" && r.SourceIP != "any" && r.SourceIP != "0.0.0.0/0" {
		inArgs = append(inArgs, "remoteip="+r.SourceIP)
	}
	if r.DestinationIP != "" && r.DestinationIP != "any" && r.DestinationIP != "0.0.0.0/0" {
		inArgs = append(inArgs, "localip="+r.DestinationIP)
	}

	if out, err := exec.Command(inArgs[0], inArgs[1:]...).CombinedOutput(); err != nil {
		return fmt.Errorf("netsh in: %s — %s", err, strings.TrimSpace(string(out)))
	}

	// Outbound rule (remoteip = destination, localip = source)
	outArgs := append([]string{"netsh"}, base...)
	outArgs = append(outArgs, "dir=out")
	if r.DestinationIP != "" && r.DestinationIP != "any" && r.DestinationIP != "0.0.0.0/0" {
		outArgs = append(outArgs, "remoteip="+r.DestinationIP)
	}
	if r.SourceIP != "" && r.SourceIP != "any" && r.SourceIP != "0.0.0.0/0" {
		outArgs = append(outArgs, "localip="+r.SourceIP)
	}

	if out, err := exec.Command(outArgs[0], outArgs[1:]...).CombinedOutput(); err != nil {
		return fmt.Errorf("netsh out: %s — %s", err, strings.TrimSpace(string(out)))
	}

	return nil
}

// addAllowRule creates a single named allow rule for the management IP.
func addAllowRule(name, dir, remoteIP, localIP, proto string, port int) {
	args := []string{
		"netsh", "advfirewall", "firewall", "add", "rule",
		"name=" + name,
		"dir=" + dir,
		"action=allow",
		"enable=yes",
		"profile=any",
	}
	if proto == "" {
		proto = "any"
	}
	args = append(args, "protocol="+proto)
	if remoteIP != "" {
		args = append(args, "remoteip="+remoteIP)
	}
	if localIP != "" {
		args = append(args, "localip="+localIP)
	}
	if port > 0 {
		args = append(args, "localport="+strconv.Itoa(port))
	}
	exec.Command(args[0], args[1:]...).Run()
}

// deleteXCloakRules removes all rules whose name starts with "XCloak-".
// Uses netsh with a name filter; runs twice to catch both in and out rules.
func deleteXCloakRules() {
	exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name=XCloak-").Run()
}

// sanitizeRuleName removes characters invalid in netsh rule names.
func sanitizeRuleName(s string) string {
	s = strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			return r
		}
		return '_'
	}, s)
	if len(s) > 50 {
		s = s[:50]
	}
	return s
}
