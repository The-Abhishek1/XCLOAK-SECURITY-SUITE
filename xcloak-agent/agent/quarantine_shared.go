package agent

// QuarantineFilePayload is the wire format for a quarantine_file task,
// shared by both the Linux (qurantine_file.go) and Windows
// (quarantine_windows.go) implementations.
type QuarantineFilePayload struct {
	Path string `json:"path"`
}
