//go:build windows

package agent

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"xcloak-agent-desktop/models"
)

// ApplyFirewallRules on Windows translates XCloak rules into Windows Defender
// Firewall rules using `netsh advfirewall firewall`.
// Rules are namespaced with "XCloak-<id>-<name>" for clean replace-mode flush.
// Requires elevated privileges (Administrator or LocalSystem).
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

	if payload.Mode == "replace" {
		deleteXCloakRules()
		log = append(log, fmt.Sprintf("[replace] flushed XCloak rules (sync_id=%d)", payload.SyncID))
	}

	if payload.AllowManage != "" {
		addAllowRule(
			fmt.Sprintf("XCloak-manage-in-%s", sanitizeRuleName(payload.AllowManage)),
			"in", payload.AllowManage, "", "", "",
		)
		addAllowRule(
			fmt.Sprintf("XCloak-manage-out-%s", sanitizeRuleName(payload.AllowManage)),
			"out", "", payload.AllowManage, "", "",
		)
		log = append(log, fmt.Sprintf("allowed manage IP %s (in+out)", payload.AllowManage))
	}

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

// applyWDFRule creates one or two netsh rules for a SyncRule based on direction.
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

	portSpec := effectivePortSpec(r)
	// netsh uses comma-separated ports; ranges use "-" (same format)
	portStr := portSpec

	dir := strings.ToLower(r.Direction)
	if dir == "" {
		dir = "both"
	}

	base := []string{
		"advfirewall", "firewall", "add", "rule",
		"protocol=" + proto,
		"action=" + action,
		"enable=yes",
		"profile=any",
	}

	if proto != "any" && portStr != "" {
		base = append(base, "localport="+portStr)
	}

	if dir == "in" || dir == "both" {
		inName := ruleName
		if dir == "both" {
			inName = ruleName + "-in"
		}
		inArgs := append([]string{"netsh"}, base...)
		inArgs = append(inArgs, "name="+inName, "dir=in")
		if r.SourceIP != "" && !isWildcardWin(r.SourceIP) {
			inArgs = append(inArgs, "remoteip="+r.SourceIP)
		}
		if r.DestinationIP != "" && !isWildcardWin(r.DestinationIP) {
			inArgs = append(inArgs, "localip="+r.DestinationIP)
		}
		if out, err := exec.Command(inArgs[0], inArgs[1:]...).CombinedOutput(); err != nil {
			return fmt.Errorf("netsh in: %s — %s", err, strings.TrimSpace(string(out)))
		}
	}

	if dir == "out" || dir == "both" {
		outName := ruleName
		if dir == "both" {
			outName = ruleName + "-out"
		}
		outArgs := append([]string{"netsh"}, base...)
		outArgs = append(outArgs, "name="+outName, "dir=out")
		if r.DestinationIP != "" && !isWildcardWin(r.DestinationIP) {
			outArgs = append(outArgs, "remoteip="+r.DestinationIP)
		}
		if r.SourceIP != "" && !isWildcardWin(r.SourceIP) {
			outArgs = append(outArgs, "localip="+r.SourceIP)
		}
		if out, err := exec.Command(outArgs[0], outArgs[1:]...).CombinedOutput(); err != nil {
			return fmt.Errorf("netsh out: %s — %s", err, strings.TrimSpace(string(out)))
		}
	}

	return nil
}

func isWildcardWin(ip string) bool {
	return ip == "" || ip == "any" || ip == "0.0.0.0/0" || ip == "::/0"
}

// addAllowRule creates a single named allow rule for the management IP.
func addAllowRule(name, dir, remoteIP, localIP, proto, port string) {
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
	if port != "" {
		args = append(args, "localport="+port)
	}
	exec.Command(args[0], args[1:]...).Run()
}

// deleteXCloakRules removes all rules whose name starts with "XCloak-".
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
