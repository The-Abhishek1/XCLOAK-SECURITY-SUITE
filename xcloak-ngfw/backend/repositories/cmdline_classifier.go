package repositories

import "strings"

// ─────────────────────────────────────────────────────────────────────────────
// classifyCmdline tags a command line with a threat label if it matches
// known-bad patterns. Returns "" for benign commands.
//
// This runs synchronously on every audit event ingested so the threat_tag
// column is populated immediately — no separate pipeline step needed.
// The tags map directly to MITRE ATT&CK technique names.
// ─────────────────────────────────────────────────────────────────────────────

func classifyCmdline(cmdline, exe string) string {
	cmd := strings.ToLower(cmdline)
	ex  := strings.ToLower(exe)

	// ── Execution / scripting ─────────────────────────────────────────────────

	// T1059.004 — Unix Shell: bash/sh one-liner execution
	if matchAny(cmd, "bash -c ", "sh -c ", "/bin/sh -c") {
		if matchAny(cmd, "/dev/tcp", "/dev/udp", "nc ", "ncat ", "socat ") {
			return "reverse_shell"
		}
		if matchAny(cmd, "base64 -d", "base64 --decode", "|sh", "| sh", "|bash", "| bash") {
			return "obfuscated_exec"
		}
	}

	// T1059.001 — PowerShell (Linux via pwsh)
	if matchAny(ex, "pwsh", "powershell") {
		if matchAny(cmd, "-encodedcommand", "-enc ", "-e ", "iex(", "invoke-expression") {
			return "powershell_encoded"
		}
		if matchAny(cmd, "downloadstring", "webclient", "webrequest", "downloadfile") {
			return "powershell_download"
		}
	}

	// T1059.006 — Python one-liners
	if matchAny(ex, "python", "python3", "python2") {
		if matchAny(cmd, "-c \"import", "-c 'import", "exec(", "eval(", "__import__") {
			return "python_exec"
		}
		if matchAny(cmd, "socket", "connect(", "bind(", "reverse") {
			return "python_reverse_shell"
		}
	}

	// T1059.005 — Perl / Ruby
	if matchAny(ex, "perl", "ruby") && matchAny(cmd, "-e ", "exec(", "system(", "socket") {
		return "script_exec"
	}

	// ── Defense evasion ───────────────────────────────────────────────────────

	// T1140 — Base64 decode + pipe to shell
	if matchAny(cmd, "base64 -d", "base64 --decode", "openssl base64") {
		if matchAny(cmd, "|sh", "| sh", "|bash", "| bash", "|python", "exec") {
			return "obfuscated_exec"
		}
	}

	// T1027 — Encoded payloads
	if matchAny(cmd, "echo ", "printf ") && matchAny(cmd, "|base64 -d", "| base64 -d", "|xxd -r") {
		return "obfuscated_exec"
	}

	// T1070 — Log/history tampering
	if matchAny(cmd, "history -c", "unset histfile", "export histfile=/dev/null",
		"rm -rf /var/log", "rm /var/log/auth", "shred /var/log") {
		return "log_tampering"
	}

	// T1562 — Disable security tools
	if matchAny(cmd, "systemctl stop auditd", "service auditd stop",
		"pkill auditd", "kill.*auditd", "auditctl -e 0",
		"systemctl stop apparmor", "setenforce 0",
		"systemctl stop firewall", "ufw disable", "iptables -F") {
		return "defense_disabled"
	}

	// ── Privilege escalation ─────────────────────────────────────────────────

	// T1548.003 — Sudo abuse
	if matchAny(ex, "/usr/bin/sudo", "/bin/sudo") {
		if matchAny(cmd, "sudo su", "sudo bash", "sudo sh", "sudo -s", "sudo -i",
			"sudo /bin/bash", "sudo /bin/sh") {
			return "sudo_shell"
		}
	}

	// T1548.001 — setuid binary abuse
	if matchAny(cmd, "chmod +s", "chmod 4755", "chmod 6755", "chmod u+s") {
		return "setuid_set"
	}

	// T1611 — Escape from container (if running in container)
	if matchAny(cmd, "nsenter", "unshare --pid", "docker run --privileged") {
		return "container_escape"
	}

	// ── Persistence ───────────────────────────────────────────────────────────

	// T1053.003 — Cron persistence
	if matchAny(ex, "crontab") && matchAny(cmd, "crontab -e", "crontab -") {
		return "cron_persistence"
	}
	if matchAny(cmd, "echo.*>>/etc/crontab", "echo.*>/etc/cron") {
		return "cron_persistence"
	}

	// T1098 — SSH key injection
	if matchAny(cmd, "authorized_keys", ".ssh/authorized_keys") &&
		matchAny(cmd, "echo ", "tee ", ">>", "cp ") {
		return "ssh_key_added"
	}

	// T1543.002 — Systemd service persistence
	if matchAny(cmd, "systemctl enable", "systemctl daemon-reload") &&
		matchAny(cmd, "/tmp/", "/dev/shm/", "/var/tmp/") {
		return "service_persistence"
	}

	// ── Credential access ─────────────────────────────────────────────────────

	// T1003.008 — /etc/shadow read
	if matchAny(cmd, "cat /etc/shadow", "unshadow", "john ", "hashcat ") {
		return "credential_dump"
	}

	// T1552 — Searching for credentials in files
	if matchAny(ex, "grep", "find", "awk") && matchAny(cmd, "password", "passwd", "secret", ".env", "id_rsa") {
		return "credential_search"
	}

	// ── Discovery / recon ─────────────────────────────────────────────────────

	// T1046 — Network service scanning
	if matchAny(ex, "nmap", "masscan", "zmap", "rustscan", "arp-scan") {
		return "network_scan"
	}

	// T1018 — Remote system discovery
	if matchAny(cmd, "arp -a", "ip neigh", "nbtscan", "netdiscover") {
		return "host_discovery"
	}

	// T1049 — Network connections enumeration
	if matchAny(ex, "ss", "netstat") && matchAny(cmd, "-tulnp", "-anp", "-plant") {
		return "network_enum"
	}

	// ── Lateral movement / C2 ────────────────────────────────────────────────

	// T1021.004 — SSH lateral movement
	if matchAny(ex, "ssh") && matchAny(cmd, "-o stricthostkeychecking=no",
		"-o userknownhostsfile=/dev/null", "-i /tmp/", "proxyjump") {
		return "ssh_lateral_move"
	}

	// T1219 — Remote access tools
	if matchAny(ex, "ngrok", "frpc", "chisel", "ligolo") {
		return "tunnel_tool"
	}

	// T1071 — C2 over common protocols
	if matchAny(cmd, "curl ", "wget ") && matchAny(cmd, "-o /tmp/", "-o /dev/shm/",
		"| bash", "|bash", "| sh", "|sh", "chmod +x") {
		return "dropper"
	}

	// ── Exfiltration ─────────────────────────────────────────────────────────

	// T1048 — Exfil over alternative protocols
	if matchAny(cmd, "curl.*--upload", "curl.*-T ", "scp ", "rsync.*@") &&
		matchAny(cmd, "/etc/passwd", "/etc/shadow", ".ssh/", "id_rsa") {
		return "data_exfil"
	}

	return "" // benign
}

// matchAny returns true if s contains any of the given substrings.
func matchAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
