package agent

// ExecuteScriptPayload is the wire format for an execute_script task,
// shared by both the Linux/macOS (execute_script.go) and Windows
// (execute_script_windows.go) implementations.
type ExecuteScriptPayload struct {
	Script string `json:"script"`
	Shell  string `json:"shell"` // "bash" | "sh" | "python3" on Linux; "powershell" | "cmd" | "python3" on Windows
	Label  string `json:"label"`
}
