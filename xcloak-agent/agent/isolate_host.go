//go:build !windows

package agent

import (
	"encoding/json"
	"fmt"
	"os/exec"

	"xcloak-agent/models"
)

type IsolatePayload struct {
	AllowIPs []string `json:"allow_ips"` // IPs to keep reachable (e.g. XCloak server)
	Duration int      `json:"duration"`  // seconds; 0 = permanent until manual rollback
}

// IsolateHost applies iptables rules to block all traffic except to/from
// the XCloak management server (so the agent stays in contact).
//
// On Linux this uses iptables; on systems without it the function returns an
// error rather than silently succeeding. A rollback script is written to
// /tmp/xcloak-isolate-rollback.sh so an admin can un-isolate manually.
func IsolateHost(task models.AgentTask) error {

	var payload IsolatePayload
	if err := json.Unmarshal(task.Payload, &payload); err != nil {
		return fmt.Errorf("invalid isolate_host payload: %w", err)
	}

	// Verify iptables is available.
	if _, err := exec.LookPath("iptables"); err != nil {
		return fmt.Errorf("iptables not found — isolation not supported on this host")
	}

	fmt.Println("Applying network isolation...")

	// Flush existing INPUT/OUTPUT rules and set default DROP.
	cmds := [][]string{
		{"iptables", "-F", "INPUT"},
		{"iptables", "-F", "OUTPUT"},
		{"iptables", "-F", "FORWARD"},
		{"iptables", "-P", "INPUT", "DROP"},
		{"iptables", "-P", "OUTPUT", "DROP"},
		{"iptables", "-P", "FORWARD", "DROP"},

		// Allow loopback.
		{"iptables", "-A", "INPUT",  "-i", "lo", "-j", "ACCEPT"},
		{"iptables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"},

		// Allow established/related connections.
		{"iptables", "-A", "INPUT",  "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"},
		{"iptables", "-A", "OUTPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"},
	}

	// Allow traffic to/from each IP in the allow list (management IPs).
	for _, ip := range payload.AllowIPs {
		cmds = append(cmds,
			[]string{"iptables", "-A", "INPUT",  "-s", ip, "-j", "ACCEPT"},
			[]string{"iptables", "-A", "OUTPUT", "-d", ip, "-j", "ACCEPT"},
		)
	}

	for _, cmd := range cmds {
		if out, err := exec.Command(cmd[0], cmd[1:]...).CombinedOutput(); err != nil {
			// If a rule fails, abort without completing isolation.
			return fmt.Errorf("iptables error: %s — %s", err, string(out))
		}
	}

	// Write rollback script so an admin can restore connectivity.
	rollback := "#!/bin/bash\niptables -F\niptables -P INPUT ACCEPT\niptables -P OUTPUT ACCEPT\niptables -P FORWARD ACCEPT\necho 'Network isolation lifted'\n"
	exec.Command("bash", "-c", "echo '"+rollback+"' > /tmp/xcloak-isolate-rollback.sh && chmod +x /tmp/xcloak-isolate-rollback.sh").Run()

	fmt.Println("Host isolated. Rollback: bash /tmp/xcloak-isolate-rollback.sh")

	return nil
}
