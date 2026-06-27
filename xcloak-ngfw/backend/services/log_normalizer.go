package services

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// ─────────────────────────────────────────────────────────────────────────────
// ParsedFields is the normalised representation of any log line.
// Every field is optional — parsers fill what they can; the rest stays zero.
//
// Field names follow the Elastic Common Schema (ECS) naming conventions so
// XCloak Sigma rules can use the same field names as community Sigma rules
// written for Elastic/Splunk (src_ip, dst_ip, user, event_id, etc.).
// ─────────────────────────────────────────────────────────────────────────────

type ParsedFields struct {
	// Timestamps
	Timestamp string `json:"timestamp,omitempty"` // ISO8601

	// Identity
	User    string `json:"user,omitempty"`     // username
	UID     string `json:"uid,omitempty"`      // numeric UID
	Process string `json:"process,omitempty"`  // process/program name
	PID     string `json:"pid,omitempty"`

	// Network
	SrcIP   string `json:"src_ip,omitempty"`
	DstIP   string `json:"dst_ip,omitempty"`
	SrcPort string `json:"src_port,omitempty"`
	DstPort string `json:"dst_port,omitempty"`
	Proto   string `json:"proto,omitempty"`

	// Host
	Hostname string `json:"hostname,omitempty"`

	// Auth / session
	AuthMethod string `json:"auth_method,omitempty"` // "password" | "publickey"
	AuthResult string `json:"auth_result,omitempty"` // "success" | "failure"
	SessionID  string `json:"session_id,omitempty"`

	// Windows Event Log
	EventID    string `json:"event_id,omitempty"`
	Channel    string `json:"channel,omitempty"`    // "Security", "System", etc.
	SubjectUser string `json:"subject_user,omitempty"`
	TargetUser  string `json:"target_user,omitempty"`
	LogonType  string `json:"logon_type,omitempty"`
	WorkstationName string `json:"workstation_name,omitempty"`

	// Syslog
	Severity string `json:"severity,omitempty"` // "emerg" through "debug"
	Facility string `json:"facility,omitempty"`

	// CEF
	DeviceVendor  string `json:"device_vendor,omitempty"`
	DeviceProduct string `json:"device_product,omitempty"`
	CEFName       string `json:"cef_name,omitempty"`
	CEFSeverity   string `json:"cef_severity,omitempty"`

	// Windows process-creation fields (EventID 4688 / Sysmon EventID 1)
	// These map to the standard Sigma field names used in community rules.
	Image              string `json:"image,omitempty"`               // full executable path
	CommandLine        string `json:"command_line,omitempty"`        // process command line
	ParentImage        string `json:"parent_image,omitempty"`        // parent executable path
	ParentCommandLine  string `json:"parent_command_line,omitempty"` // parent command line
	IntegrityLevel     string `json:"integrity_level,omitempty"`     // Low/Medium/High/System
	Hashes             string `json:"hashes,omitempty"`              // MD5=...,SHA256=...
	OriginalFileName   string `json:"original_file_name,omitempty"`  // original PE filename
	CurrentDirectory   string `json:"current_directory,omitempty"`   // working directory

	// Windows service / scheduled task fields (EventID 7045, 4698)
	ServiceName string `json:"service_name,omitempty"`
	ServiceType string `json:"service_type,omitempty"`
	StartType   string `json:"start_type,omitempty"`

	// Freeform key=value extras that don't fit above
	Extra map[string]string `json:"extra,omitempty"`

	// Internal bookkeeping
	Format string `json:"format,omitempty"` // "syslog" | "winevent" | "json" | "cef" | "raw"
}

// ─────────────────────────────────────────────────────────────────────────────
// NormalizeLog parses a raw log message and returns a ParsedFields struct.
// The function tries each parser in order and returns the first successful
// result. If nothing matches, it runs the raw key=value extractor as a
// last resort so at least obvious fields like user= and src= get pulled out.
// ─────────────────────────────────────────────────────────────────────────────

func NormalizeLog(source, message string) ParsedFields {
	if message == "" {
		return ParsedFields{Format: "raw"}
	}

	// ── 1. Windows Event Log text (wevtutil /f:Text output) ──────
	if source == "Security" || source == "Security-PS" ||
		source == "System" || source == "Application" ||
		strings.Contains(message, "EventID") || strings.Contains(message, "Event ID") {
		if f := parseWindowsEvent(message); f != nil {
			return *f
		}
	}

	// ── 2. CEF (ArcSight Common Event Format) ────────────────────
	if strings.HasPrefix(message, "CEF:") {
		if f := parseCEF(message); f != nil {
			return *f
		}
	}

	// ── 3. JSON ──────────────────────────────────────────────────
	if len(message) > 0 && message[0] == '{' {
		if f := parseJSON(message); f != nil {
			return *f
		}
	}

	// ── 4. Syslog RFC3164 / RFC5424 ──────────────────────────────
	if f := parseSyslog(message); f != nil {
		return *f
	}

	// ── 5. Raw key=value fallback ─────────────────────────────────
	return parseKeyValue(message)
}

// MarshalParsedFields serialises ParsedFields to a JSON string suitable
// for storage in a Postgres JSONB column.
func MarshalParsedFields(f ParsedFields) string {
	b, err := json.Marshal(f)
	if err != nil {
		return "{}"
	}
	return string(b)
}

// ─────────────────────────────────────────────────────────────────────────────
// Parser 1 — Syslog RFC3164 / RFC5424
//
// RFC3164: <PRI>Mon DD HH:MM:SS hostname process[pid]: message
// RFC5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [STRUCTURED-DATA] MSG
//
// Examples:
//   Mar 15 10:23:45 web01 sshd[12345]: Accepted password for alice from 10.0.0.1 port 54321 ssh2
//   2025-03-15T10:23:45.000Z web01 sshd 12345 - - Accepted password for alice
// ─────────────────────────────────────────────────────────────────────────────

var (
	// RFC3164: optional <PRI>, then month day time hostname process[pid]:
	rfc3164RE = regexp.MustCompile(
		`^(?:<\d+>)?(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d+\s+\d+:\d+:\d+\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s*(.*)$`,
	)

	// RFC5424: <PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID ...
	rfc5424RE = regexp.MustCompile(
		`^<\d+>1\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+\S+\s+(?:\[.*?\]\s+)?(.*)$`,
	)

	// SSH patterns within the syslog message body.
	sshAcceptRE  = regexp.MustCompile(`Accepted\s+(\S+)\s+for\s+(\S+)\s+from\s+(\S+)\s+port\s+(\d+)`)
	sshFailRE    = regexp.MustCompile(`(?:Failed|Invalid user)\s+(?:password|publickey)?\s*(?:for\s+)?(\S+)?\s+from\s+(\S+)\s+port\s+(\d+)`)
	sshDisconRE  = regexp.MustCompile(`Disconnected from\s+(?:user\s+(\S+)\s+)?(\S+)\s+port\s+(\d+)`)
	sudoRE       = regexp.MustCompile(`(\S+)\s*:\s*TTY=\S+\s*;\s*PWD=\S+\s*;\s*USER=(\S+)\s*;\s*COMMAND=(.+)`)
	userinfoRE   = regexp.MustCompile(`for user[:\s]+(\S+)`)
)

func parseSyslog(message string) *ParsedFields {
	var f ParsedFields
	var body string

	if m := rfc5424RE.FindStringSubmatch(message); m != nil {
		f.Format    = "syslog5424"
		f.Timestamp = m[1]
		f.Hostname  = m[2]
		f.Process   = m[3]
		f.PID       = m[4]
		body        = m[5]
	} else if m := rfc3164RE.FindStringSubmatch(message); m != nil {
		f.Format   = "syslog3164"
		f.Hostname = m[1]
		f.Process  = strings.TrimSuffix(m[2], ":")
		f.PID      = m[3]
		body       = m[4]
	} else {
		return nil
	}

	// ── Enrich from known message body patterns ──────────────────
	if m := sshAcceptRE.FindStringSubmatch(body); m != nil {
		f.AuthMethod = m[1]
		f.User       = m[2]
		f.SrcIP      = m[3]
		f.SrcPort    = m[4]
		f.AuthResult = "success"
	} else if m := sshFailRE.FindStringSubmatch(body); m != nil {
		f.AuthResult = "failure"
		if m[1] != "" { f.User  = m[1] }
		f.SrcIP  = m[2]
		f.SrcPort = m[3]
	} else if m := sshDisconRE.FindStringSubmatch(body); m != nil {
		if m[1] != "" { f.User = m[1] }
		f.SrcIP   = m[2]
		f.SrcPort = m[3]
	} else if m := sudoRE.FindStringSubmatch(body); m != nil {
		f.User    = m[1]
		f.Extra   = map[string]string{"sudo_user": m[2], "command": m[3]}
	} else if m := userinfoRE.FindStringSubmatch(body); m != nil {
		f.User = m[1]
	}

	// Severity hint from message
	bodyLower := strings.ToLower(body)
	switch {
	case strings.Contains(bodyLower, "error") || strings.Contains(bodyLower, "failed"):
		f.Severity = "error"
	case strings.Contains(bodyLower, "warning") || strings.Contains(bodyLower, "warn"):
		f.Severity = "warning"
	case strings.Contains(bodyLower, "accepted") || strings.Contains(bodyLower, "success"):
		f.Severity = "info"
	}

	return &f
}

// ─────────────────────────────────────────────────────────────────────────────
// Parser 2 — Windows Event Log (wevtutil /f:Text flat-text format)
//
// wevtutil text output looks like:
//   Event[0]: Log Name: Security  Source: Microsoft-Windows-Security-Auditing
//   Date: 2025-03-15T10:23:45  Event ID: 4624  Task: Logon  Level: Information
//   ...
//   Account Name:    alice
//   Workstation Name: DESKTOP-ABC
//   Source Network Address: 10.0.0.1
// ─────────────────────────────────────────────────────────────────────────────

func parseWindowsEvent(message string) *ParsedFields {
	f := &ParsedFields{Format: "winevent"}

	lines := strings.Split(message, "\n")
	// Allow single-line flattened form (spaces between fields).
	if len(lines) == 1 {
		lines = strings.Split(message, "  ")
	}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Split on first colon.
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		if val == "" || val == "-" || val == "N/A" {
			continue
		}

		switch strings.ToLower(key) {
		case "event id", "eventid", "event_id":
			f.EventID = val
		case "date", "time created":
			f.Timestamp = val
		case "log name", "logname":
			f.Channel = val
		case "account name", "subject account name", "new account name":
			if f.SubjectUser == "" { f.SubjectUser = val }
		case "target account name", "target user name":
			f.TargetUser = val
		case "source network address", "ip address", "ipaddress":
			f.SrcIP = val
		case "source port", "ip port":
			f.SrcPort = val
		case "workstation name", "workstationname":
			f.WorkstationName = val
		case "logon type":
			f.LogonType = val
		case "account domain", "subject domain name":
			if f.SubjectUser != "" && val != "" {
				f.SubjectUser = val + `\` + f.SubjectUser
			}
		case "process name", "creator process name", "parentimage":
			if f.ParentImage == "" { f.ParentImage = val }
			if f.Process == ""    { f.Process = val }
		case "new process name", "image":
			f.Image = val
			if f.Process == "" { f.Process = val }
		case "process command line", "commandline":
			f.CommandLine = val
		case "parent command line", "parentcommandline":
			f.ParentCommandLine = val
		case "token elevation type", "mandatory label", "integrity level":
			f.IntegrityLevel = val
		case "hashes":
			f.Hashes = val
		case "original file name", "originalfilename":
			f.OriginalFileName = val
		case "current directory", "currentdirectory":
			f.CurrentDirectory = val
		case "service name", "servicename":
			f.ServiceName = val
		case "service type", "servicetype":
			f.ServiceType = val
		case "start type", "starttype":
			f.StartType = val
		case "level":
			f.Severity = strings.ToLower(val)
		}
	}

	// Map EventID → human AuthResult.
	switch f.EventID {
	case "4624":
		f.AuthResult = "success"
		if f.User == "" { f.User = f.TargetUser }
	case "4625":
		f.AuthResult = "failure"
		if f.User == "" { f.User = f.TargetUser }
	case "4648":
		f.AuthResult = "explicit"
		if f.User == "" { f.User = f.SubjectUser }
	case "4634", "4647":
		f.AuthResult = "logoff"
		if f.User == "" { f.User = f.SubjectUser }
	case "4688":
		// Process creation — user is SubjectUser; Image/CommandLine parsed above
		f.User = f.SubjectUser
	case "7045":
		// Service installation
	case "4720", "4726":
		// User account created/deleted
		f.User = f.TargetUser
	}

	// Only return if we extracted at least one useful field.
	if f.EventID == "" && f.SrcIP == "" && f.User == "" && f.SubjectUser == "" {
		return nil
	}
	return f
}

// ─────────────────────────────────────────────────────────────────────────────
// Parser 3 — CEF (Common Event Format)
//
// CEF:Version|Device Vendor|Device Product|Device Version|SignatureID|Name|Severity|Extension
//
// Example:
//   CEF:0|Palo Alto|PAN-OS|10.1|4624|User Login|5|src=10.0.0.1 spt=54321 dst=192.168.1.1 dpt=22 duser=alice
// ─────────────────────────────────────────────────────────────────────────────

var cefHeaderRE = regexp.MustCompile(
	`^CEF:\d+\|([^|]*)\|([^|]*)\|[^|]*\|[^|]*\|([^|]*)\|([^|]*)\|(.*)$`,
)

func parseCEF(message string) *ParsedFields {
	m := cefHeaderRE.FindStringSubmatch(message)
	if m == nil {
		return nil
	}

	f := &ParsedFields{
		Format:        "cef",
		DeviceVendor:  m[1],
		DeviceProduct: m[2],
		CEFName:       m[3],
		CEFSeverity:   m[4],
	}

	// Parse key=value extension.
	ext := parseKVPairs(m[5])
	if v, ok := ext["src"];    ok { f.SrcIP   = v }
	if v, ok := ext["dst"];    ok { f.DstIP   = v }
	if v, ok := ext["spt"];    ok { f.SrcPort = v }
	if v, ok := ext["dpt"];    ok { f.DstPort = v }
	if v, ok := ext["proto"];  ok { f.Proto   = v }
	if v, ok := ext["suser"];  ok { f.User    = v }
	if v, ok := ext["duser"];  ok { if f.User == "" { f.User = v } }
	if v, ok := ext["sproc"];  ok { f.Process = v }
	if v, ok := ext["rt"];     ok { f.Timestamp = v }
	if v, ok := ext["msg"];    ok {
		if f.Extra == nil { f.Extra = make(map[string]string) }
		f.Extra["msg"] = v
	}

	return f
}

// ─────────────────────────────────────────────────────────────────────────────
// Parser 4 — JSON log lines
//
// Many modern log shippers (Fluentd, Filebeat, Docker) output JSON.
// We map common field names to ParsedFields.
// ─────────────────────────────────────────────────────────────────────────────

func parseJSON(message string) *ParsedFields {
	var raw map[string]interface{}
	if err := json.Unmarshal([]byte(message), &raw); err != nil {
		return nil
	}

	f := &ParsedFields{Format: "json"}

	str := func(keys ...string) string {
		for _, k := range keys {
			if v, ok := raw[k]; ok {
				switch s := v.(type) {
				case string:
					return s
				case float64:
					return fmt.Sprintf("%.0f", s)
				}
			}
		}
		return ""
	}

	f.Timestamp        = str("timestamp", "@timestamp", "time", "ts", "datetime")
	f.Hostname         = str("hostname", "host", "computer_name", "computer", "ComputerName")
	f.User             = str("user", "username", "user_name", "account_name", "AccountName")
	f.Process          = str("process", "process_name", "program", "app")
	f.PID              = str("pid", "process_id", "ProcessId")
	f.SrcIP            = str("src_ip", "src", "source_ip", "remote_ip", "client_ip", "IpAddress", "SourceIp")
	f.DstIP            = str("dst_ip", "dst", "dest_ip", "destination_ip", "DestinationIp")
	f.SrcPort          = str("src_port", "source_port", "SourcePort")
	f.DstPort          = str("dst_port", "dest_port", "port", "DestinationPort")
	f.EventID          = str("event_id", "EventID", "eventId", "EventId")
	f.Severity         = str("level", "severity", "log_level", "loglevel")
	f.AuthResult       = str("auth_result", "result", "outcome")
	f.Image            = str("Image", "image", "exe", "process_path")
	f.CommandLine      = str("CommandLine", "command_line", "cmdline", "cmd")
	f.ParentImage      = str("ParentImage", "parent_image", "parent_exe")
	f.ParentCommandLine = str("ParentCommandLine", "parent_command_line")
	f.IntegrityLevel   = str("IntegrityLevel", "integrity_level")
	f.Hashes           = str("Hashes", "hashes", "hash")
	f.OriginalFileName = str("OriginalFileName", "original_file_name")
	f.ServiceName      = str("ServiceName", "service_name")
	f.Channel          = str("Channel", "channel", "log_name")

	if f.Timestamp == "" && f.Hostname == "" && f.User == "" &&
		f.SrcIP == "" && f.EventID == "" {
		return nil
	}
	return f
}

// ─────────────────────────────────────────────────────────────────────────────
// Parser 5 — Generic key=value fallback
//
// Handles logs like:
//   user=alice src=10.0.0.1 dst=192.168.1.1 action=login result=success
//   Failed password for invalid user bob from 10.0.0.2 port 12345
// ─────────────────────────────────────────────────────────────────────────────

var ipRE = regexp.MustCompile(`\b(\d{1,3}(?:\.\d{1,3}){3})\b`)

func parseKeyValue(message string) ParsedFields {
	f := ParsedFields{Format: "raw"}
	kv := parseKVPairs(message)

	if v, ok := kv["user"];      ok { f.User    = v }
	if v, ok := kv["username"];  ok { f.User    = v }
	if v, ok := kv["src"];       ok { f.SrcIP   = v }
	if v, ok := kv["src_ip"];    ok { f.SrcIP   = v }
	if v, ok := kv["dst"];       ok { f.DstIP   = v }
	if v, ok := kv["dst_ip"];    ok { f.DstIP   = v }
	if v, ok := kv["host"];      ok { f.Hostname = v }
	if v, ok := kv["hostname"];  ok { f.Hostname = v }
	if v, ok := kv["pid"];       ok { f.PID     = v }
	if v, ok := kv["process"];   ok { f.Process = v }
	if v, ok := kv["event_id"];  ok { f.EventID = v }

	// IP address extraction from freeform text as a last resort.
	if f.SrcIP == "" {
		ips := ipRE.FindAllString(message, 3)
		if len(ips) > 0 {
			f.SrcIP = ips[0]
		}
		if len(ips) > 1 {
			f.DstIP = ips[1]
		}
	}

	return f
}

// ─────────────────────────────────────────────────────────────────────────────
// Utilities
// ─────────────────────────────────────────────────────────────────────────────

// parseKVPairs extracts key=value pairs from a string.
// Handles quoted values: key="value with spaces" and key=value.
var kvRE = regexp.MustCompile(`(\w+)=(?:"([^"]*)"|([\S]+))`)

func parseKVPairs(s string) map[string]string {
	result := make(map[string]string)
	matches := kvRE.FindAllStringSubmatch(s, -1)
	for _, m := range matches {
		key := strings.ToLower(m[1])
		val := m[2]
		if val == "" {
			val = m[3]
		}
		result[key] = val
	}
	return result
}

// GetFieldValue looks up a named field on a ParsedFields struct.
// Used by the Sigma engine for field-level matching.
// Returns ("", false) if the field doesn't exist or is empty.
// GetFieldValue looks up a named field, accepting both our internal names and
// the standard Sigma/ECS field names used in community rule sets.
func GetFieldValue(f ParsedFields, fieldName string) (string, bool) {
	fieldName = strings.ToLower(fieldName)
	var val string
	switch fieldName {
	// ── Core ──────────────────────────────────────────────────────────────
	case "timestamp":
		val = f.Timestamp
	case "user", "username", "accountname", "account_name", "subjectaccountname":
		val = f.User
	case "uid":
		val = f.UID
	case "process", "process_name", "processname":
		val = f.Process
	case "pid", "processid", "process_id":
		val = f.PID
	// ── Network ───────────────────────────────────────────────────────────
	case "src_ip", "src", "sourceip", "source_ip", "ipaddress", "remoteaddress":
		val = f.SrcIP
	case "dst_ip", "dst", "destinationip", "destination_ip", "destip":
		val = f.DstIP
	case "src_port", "sourceport", "source_port":
		val = f.SrcPort
	case "dst_port", "destinationport", "destination_port", "destport":
		val = f.DstPort
	case "proto", "protocol":
		val = f.Proto
	// ── Host ──────────────────────────────────────────────────────────────
	case "hostname", "host", "computername", "computer_name":
		val = f.Hostname
	// ── Auth ──────────────────────────────────────────────────────────────
	case "auth_method":
		val = f.AuthMethod
	case "auth_result", "authresult":
		val = f.AuthResult
	case "session_id":
		val = f.SessionID
	// ── Windows event log ─────────────────────────────────────────────────
	case "event_id", "eventid":
		val = f.EventID
	case "channel":
		val = f.Channel
	case "subject_user", "subjectusername", "subjectaccountsid":
		val = f.SubjectUser
	case "target_user", "targetusername", "targetusernam", "target_user_name":
		val = f.TargetUser
	case "logon_type", "logontype":
		val = f.LogonType
	case "workstation", "workstationname", "workstation_name":
		val = f.WorkstationName
	// ── Process creation (Sigma: process_creation / Sysmon 1 / EID 4688) ─
	case "image", "newprocessname", "new_process_name", "commandpath":
		val = f.Image
	case "commandline", "command_line":
		val = f.CommandLine
	case "parentimage", "parent_image", "creatorprocessname", "creator_process_name":
		val = f.ParentImage
	case "parentcommandline", "parent_command_line":
		val = f.ParentCommandLine
	case "integritylevel", "integrity_level":
		val = f.IntegrityLevel
	case "hashes":
		val = f.Hashes
	case "originalfilename", "original_file_name":
		val = f.OriginalFileName
	case "currentdirectory", "current_directory":
		val = f.CurrentDirectory
	// ── Windows service / task ────────────────────────────────────────────
	case "servicename", "service_name":
		val = f.ServiceName
	case "servicetype", "service_type":
		val = f.ServiceType
	case "starttype", "start_type":
		val = f.StartType
	// ── Syslog / CEF ──────────────────────────────────────────────────────
	case "severity":
		val = f.Severity
	case "facility":
		val = f.Facility
	case "device_vendor", "devicevendor":
		val = f.DeviceVendor
	case "device_product", "deviceproduct":
		val = f.DeviceProduct
	case "cef_name", "cefname":
		val = f.CEFName
	case "cef_severity", "cefseverity":
		val = f.CEFSeverity
	case "format":
		val = f.Format
	default:
		if f.Extra != nil {
			val = f.Extra[fieldName]
		}
	}
	return val, val != ""
}


