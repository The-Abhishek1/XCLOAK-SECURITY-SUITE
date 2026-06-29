package services

// OT / ICS Security Detector
//
// Detects attacks and anomalies targeting Operational Technology (OT) and
// Industrial Control System (ICS) environments. This is a high-value
// differentiator for enterprises in energy, utilities, manufacturing, water
// treatment, and critical infrastructure.
//
// Log sources:
//   - Network logs (firewall, IDS) with dst_port field
//   - SCADA/DCS historian logs forwarded via syslog
//   - Windows Event Logs from OT workstations/servers
//   - Dragos / Claroty / Nozomi IDS alert JSON
//
// Detection categories:
//
//  IT→OT Protocol Access (T1021) — Connection from IT IP range to industrial
//      protocol ports: Modbus/TCP (502), DNP3 (20000), IEC-104 (2404),
//      EtherNet/IP (44818), S7Comm (102), OPC-UA (4840), BACnet (47808),
//      Profinet (34962), Modbus over TLS (802)
//
//  PLC Programming Mode  (T1059) — Programming session detected on PLC
//      (Step7, TIA Portal, RSLogix5000, FactoryTalk, Studio 5000 connecting
//      to PLC IP range)
//
//  SCADA Historian Anomaly (T1005) — Bulk data read from historian (OSIsoft PI,
//      AspenTech, Wonderware) from non-SCADA source
//
//  ICS Network Scan      (T1046) — Port sweep targeting known ICS ports from
//      a single source
//
//  Remote Access to OT   (T1021.001) — RDP/VNC to OT hosts from IT zone
//
//  Unauthorized Firmware Update (T1542) — Firmware write/update commands
//      detected in protocol payload keywords
//
//  Safety System Access  (T0878) — MITRE ATT&CK for ICS: access to safety
//      instrumented system (SIS) via safety protocol ports (61850 IEC, 2404)
//
//  Engineering Workstation Anomaly (T1078) — EWS (Engineering Workstation)
//      process launching unusual child processes (cmd, powershell, etc.)
//
// The detector uses a configurable OT IP range (env: OT_CIDR, default 10.100.0.0/16)
// and an IT range heuristic to flag IT→OT communications.
//
// Runs every 5 minutes. Dedup TTL: 30 minutes.

import (
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
)

var otDedup = newTTLMap(30 * time.Minute)

// ICS protocol ports and their names.
var icsPorts = map[string]string{
	"502":   "Modbus/TCP",
	"20000": "DNP3",
	"2404":  "IEC-104",
	"44818": "EtherNet/IP",
	"102":   "S7Comm (Siemens)",
	"4840":  "OPC-UA",
	"47808": "BACnet",
	"34962": "Profinet RT",
	"802":   "Modbus-TLS",
	"61850": "IEC 61850",
	"20547": "ProConOs",
	"1089":  "FF HSE",
	"1090":  "FF Annunciation",
	"2222":  "EtherNet/IP implicit",
	"9600":  "OMRON FINS",
}

// OT engineering/SCADA software signatures.
var otSoftwareSigs = []string{
	"step7", "tia portal", "rslogix", "factorytalk", "studio 5000",
	"wonderware", "intouch", "wincc", "simatic", "ignition", "osisoft pi",
	"aspentech", "osi pi", "pi system", "abb 800xa", "deltaV", "ovation",
}

// OT-specific attack keywords in log messages.
type otSig struct {
	fragments []string
	ruleName  string
	severity  string
	mitre     string
	mitreName string
}

var otSigs = []otSig{
	// Firmware / configuration modification
	{[]string{"firmware", "update"}, "OT — Firmware Update Detected", "high", "T1542", "Pre-OS Boot"},
	{[]string{"firmware", "write"}, "OT — Firmware Write Command", "critical", "T1542", "Pre-OS Boot"},
	{[]string{"programming mode", "enabled"}, "OT — PLC Programming Mode Enabled", "critical", "T1059", "Command and Scripting Interpreter"},
	{[]string{"download program", "plc"}, "OT — PLC Program Download", "critical", "T1059", "Command and Scripting Interpreter"},
	{[]string{"force coil", "modbus"}, "OT — Modbus Force Coil (actuation)", "critical", "T0855", "Unauthorized Command Message"},
	{[]string{"write multiple", "modbus"}, "OT — Modbus Write Multiple Registers", "high", "T0855", "Unauthorized Command Message"},
	{[]string{"stop cpu", "siemens"}, "OT — Siemens PLC CPU Stop Command", "critical", "T0881", "Service Stop"},
	{[]string{"sis", "bypass"}, "OT — Safety System Bypass Detected", "critical", "T0878", "Alarm Suppression"},
	{[]string{"historian", "export", "all"}, "OT — Mass Historian Data Export", "high", "T1005", "Data from Local System"},
	// Remote access to OT
	{[]string{"rdp", ":3389"}, "OT — RDP Session to OT Host", "high", "T1021.001", "Remote Desktop Protocol"},
	{[]string{"vnc", ":5900"}, "OT — VNC Session to OT Host", "high", "T1021.005", "VNC"},
	// EWS anomalies
	{[]string{"engineering workstation", "cmd.exe"}, "OT — Engineering Workstation Spawned CMD", "high", "T1078", "Valid Accounts"},
	{[]string{"engineering workstation", "powershell"}, "OT — Engineering Workstation Spawned PowerShell", "high", "T1059.001", "PowerShell"},
}

// otCIDR is the configured OT network CIDR.
func otCIDR() *net.IPNet {
	cidr := os.Getenv("OT_CIDR")
	if cidr == "" {
		cidr = "10.100.0.0/16"
	}
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil
	}
	return network
}

func StartOTICSScheduler() {
	go func() {
		time.Sleep(120 * time.Second)
		for {
			runOTICSDetection()
			time.Sleep(5 * time.Minute)
		}
	}()
}

func runOTICSDetection() {
	rows, err := database.DB.Query(`SELECT id FROM tenants WHERE is_active = true`)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var tid int
		if rows.Scan(&tid) == nil {
			detectICSProtocolAccess(tid)
			detectICSPortScan(tid)
			detectOTSoftware(tid)
			detectOTKeywords(tid)
		}
	}
}

// detectICSProtocolAccess — connections to ICS protocol ports.
func detectICSProtocolAccess(tenantID int) {
	portList := make([]string, 0, len(icsPorts))
	for p := range icsPorts {
		portList = append(portList, p)
	}

	for port, proto := range icsPorts {
		rows, err := database.DB.Query(`
			SELECT el.agent_id,
			       coalesce(el.parsed_fields->>'src_ip','') AS src_ip,
			       coalesce(el.parsed_fields->>'dst_ip','') AS dst_ip,
			       coalesce(el.parsed_fields->>'user','') AS user,
			       el.log_message
			FROM endpoint_logs el
			JOIN agents a ON a.id = el.agent_id AND a.tenant_id = $1
			WHERE (
			       el.parsed_fields->>'dst_port' = $2
			    OR el.log_message ILIKE $3
			  )
			  AND el.created_at > NOW() - INTERVAL '5 minutes'
			LIMIT 50
		`, tenantID, port, "% :"+port+" %")
		if err != nil {
			continue
		}
		for rows.Next() {
			var agentID int
			var srcIP, dstIP, user, logMsg string
			if rows.Scan(&agentID, &srcIP, &dstIP, &user, &logMsg) != nil {
				continue
			}

			// Only flag if source is NOT in the OT network (IT→OT communication)
			if srcIP != "" {
				network := otCIDR()
				if network != nil {
					if parsed := net.ParseIP(srcIP); parsed != nil && network.Contains(parsed) {
						continue // src is in OT network — expected
					}
				}
			}

			key := fmt.Sprintf("%d:ics-proto:%s:%s:%s", tenantID, port, srcIP, dstIP)
			if otDedup.touched(key) {
				break
			}
			otDedup.touch(key)

			severity := "high"
			if port == "2404" || port == "61850" || port == "20000" {
				severity = "critical"
			}

			m := fmt.Sprintf("IT→OT Protocol Access — protocol='%s' port=%s src_ip='%s' dst_ip='%s' (unauthorized industrial protocol access from IT network)",
				proto, port, srcIP, dstIP)
			log.Printf("[OT] %s", m)
			CreateAlert(models.Alert{
				AgentID:        agentID,
				TenantID:       tenantID,
				Severity:       severity,
				RuleName:       fmt.Sprintf("IT→OT: %s on port %s", proto, port),
				LogMessage:     m,
				MitreTactic:    "Lateral Movement",
				MitreTechnique: "T1021",
				MitreName:      "Remote Services",
				Fingerprint:    fmt.Sprintf("ot-proto-%s-%d-%s", port, tenantID, srcIP),
			})
		}
		rows.Close()
	}
}

// detectICSPortScan — a single IP hitting multiple ICS ports in 5 min.
func detectICSPortScan(tenantID int) {
	rows, err := database.DB.Query(`
		SELECT el.agent_id,
		       el.parsed_fields->>'src_ip' AS src_ip,
		       COUNT(DISTINCT el.parsed_fields->>'dst_port') AS port_count,
		       string_agg(DISTINCT el.parsed_fields->>'dst_port', ',') AS ports
		FROM endpoint_logs el
		JOIN agents a ON a.id = el.agent_id AND a.tenant_id = $1
		WHERE el.parsed_fields->>'dst_port' IN ('502','20000','2404','44818','102','4840','47808','34962','61850','9600')
		  AND el.parsed_fields->>'src_ip' IS NOT NULL
		  AND el.created_at > NOW() - INTERVAL '5 minutes'
		GROUP BY el.agent_id, el.parsed_fields->>'src_ip'
		HAVING COUNT(DISTINCT el.parsed_fields->>'dst_port') >= 3
	`, tenantID)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var agentID int
		var srcIP, ports string
		var portCount int
		if rows.Scan(&agentID, &srcIP, &portCount, &ports) != nil {
			continue
		}
		key := fmt.Sprintf("%d:ics-scan:%s", tenantID, srcIP)
		if otDedup.touched(key) {
			continue
		}
		otDedup.touch(key)
		m := fmt.Sprintf("ICS Network Scan — src_ip='%s' hit %d industrial protocol ports (%s) in 5 min (possible Shodan/ICS enumeration)", srcIP, portCount, ports)
		log.Printf("[OT] %s", m)
		CreateAlert(models.Alert{
			AgentID:        agentID,
			TenantID:       tenantID,
			Severity:       "critical",
			RuleName:       "ICS Port Scan — Industrial Protocol Enumeration",
			LogMessage:     m,
			MitreTactic:    "Discovery",
			MitreTechnique: "T1046",
			MitreName:      "Network Service Discovery",
			Fingerprint:    fmt.Sprintf("ot-scan-%d-%s", tenantID, srcIP),
		})
	}
}

// detectOTSoftware — SCADA/PLC engineering software running from unusual accounts or hosts.
func detectOTSoftware(tenantID int) {
	for _, sw := range otSoftwareSigs {
		rows, err := database.DB.Query(`
			SELECT el.agent_id,
			       coalesce(el.parsed_fields->>'user','') AS user,
			       coalesce(el.parsed_fields->>'src_ip','') AS src_ip,
			       el.log_message
			FROM endpoint_logs el
			JOIN agents a ON a.id = el.agent_id AND a.tenant_id = $1
			WHERE el.log_message ILIKE $2
			  AND el.created_at > NOW() - INTERVAL '5 minutes'
			LIMIT 20
		`, tenantID, "%"+sw+"%")
		if err != nil {
			continue
		}
		for rows.Next() {
			var agentID int
			var user, srcIP, logMsg string
			if rows.Scan(&agentID, &user, &srcIP, &logMsg) != nil {
				continue
			}
			key := fmt.Sprintf("%d:ot-sw:%s:%s", tenantID, sw, user)
			if otDedup.touched(key) {
				break
			}
			otDedup.touch(key)
			m := fmt.Sprintf("OT Engineering Software Detected — software='%s' user='%s' src_ip='%s'", sw, user, srcIP)
			log.Printf("[OT] %s", m)
			CreateAlert(models.Alert{
				AgentID:        agentID,
				TenantID:       tenantID,
				Severity:       "medium",
				RuleName:       "OT Engineering Software Activity",
				LogMessage:     m,
				MitreTactic:    "Execution",
				MitreTechnique: "T1059",
				MitreName:      "Command and Scripting Interpreter",
				Fingerprint:    fmt.Sprintf("ot-sw-%d-%s-%s", tenantID, sw, user),
			})
		}
		rows.Close()
	}
}

// detectOTKeywords — keyword-based OT-specific attack patterns in log messages.
func detectOTKeywords(tenantID int) {
	rows, err := database.DB.Query(`
		SELECT el.agent_id,
		       lower(el.log_message) AS msg,
		       coalesce(el.parsed_fields->>'user','') AS user,
		       coalesce(el.parsed_fields->>'src_ip','') AS src_ip,
		       el.log_message
		FROM endpoint_logs el
		JOIN agents a ON a.id = el.agent_id AND a.tenant_id = $1
		WHERE el.created_at > NOW() - INTERVAL '5 minutes'
		  AND (
		       el.log_message ILIKE '%plc%'
		    OR el.log_message ILIKE '%scada%'
		    OR el.log_message ILIKE '%dcs%'
		    OR el.log_message ILIKE '%modbus%'
		    OR el.log_message ILIKE '%historian%'
		    OR el.log_message ILIKE '%engineering workstation%'
		    OR el.log_message ILIKE '%firmware%'
		    OR el.log_message ILIKE '%hmi%'
		    OR el.log_message ILIKE '%safety%'
		  )
		LIMIT 1000
	`, tenantID)
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var agentID int
		var msg, user, srcIP, logMsg string
		if rows.Scan(&agentID, &msg, &user, &srcIP, &logMsg) != nil {
			continue
		}
		for _, sig := range otSigs {
			allMatch := true
			for _, frag := range sig.fragments {
				if !strings.Contains(msg, frag) {
					allMatch = false
					break
				}
			}
			if !allMatch {
				continue
			}
			key := fmt.Sprintf("%d:ot-kw:%s:%s", tenantID, sig.mitre, user)
			if otDedup.touched(key) {
				break
			}
			otDedup.touch(key)
			m := fmt.Sprintf("%s — user='%s' src_ip='%s' detail='%s'",
				sig.ruleName, user, srcIP, truncateLog(logMsg, 200))
			log.Printf("[OT] %s", m)
			CreateAlert(models.Alert{
				AgentID:        agentID,
				TenantID:       tenantID,
				Severity:       sig.severity,
				RuleName:       sig.ruleName,
				LogMessage:     m,
				MitreTactic:    "Execution",
				MitreTechnique: sig.mitre,
				MitreName:      sig.mitreName,
				Fingerprint:    fmt.Sprintf("ot-kw-%s-%d", sig.mitre, tenantID),
			})
			break
		}
	}
}
