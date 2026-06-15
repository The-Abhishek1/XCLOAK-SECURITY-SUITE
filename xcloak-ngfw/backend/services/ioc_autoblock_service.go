package services

import (
	"fmt"
	"strings"

	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
)

// autoBlockIOC extracts the IOC indicator from the alert log message and
// creates a firewall DENY rule to block that IP. Called as a goroutine.
func autoBlockIOC(alert models.Alert) {

	// Extract IP from log message — IOC alerts have format:
	// "IOC match: indicator=<value> type=<type>"
	indicator := extractIOCIndicator(alert.LogMessage)
	if indicator == "" || !isIPAddress(indicator) {
		return // only auto-block IP addresses
	}

	// Check if already blocked.
	var existing int
	database.DB.QueryRow(`
		SELECT COUNT(*) FROM firewall_rules
		WHERE source_ip = $1 AND action = 'deny'
	`, indicator).Scan(&existing)

	if existing > 0 {
		return // already blocked
	}

	// Create deny rule.
	rule := models.FirewallRule{
		Name:      fmt.Sprintf("IOC Block: %s", indicator),
		SourceIP:  indicator,
		Protocol:  "any",
		Action:    "deny",
		Enabled:   true,
	}

	err := CreateFirewallRule(rule)
	if err != nil {
		fmt.Printf("IOC auto-block failed for %s: %v\n", indicator, err)
		return
	}

	// Log the block.
	database.DB.Exec(`
		INSERT INTO ioc_firewall_blocks (ioc_id, indicator, agent_id)
		VALUES (0, $1, $2)
	`, indicator, alert.AgentID)

	LogEvent("IOC_AUTO_BLOCK",
		fmt.Sprintf("Auto-blocked IOC IP %s (agent #%d)", indicator, alert.AgentID),
		"system",
	)

	fmt.Printf("IOC auto-blocked: %s\n", indicator)
}

func extractIOCIndicator(logMsg string) string {
	lower := strings.ToLower(logMsg)

	// Pattern: "indicator=1.2.3.4" or "IOC match: 1.2.3.4"
	for _, prefix := range []string{"indicator=", "ioc match: ", "matched ioc: "} {
		idx := strings.Index(lower, prefix)
		if idx >= 0 {
			rest := logMsg[idx+len(prefix):]
			// Take until space or end
			end := strings.IndexAny(rest, " \t\n,;")
			if end < 0 {
				end = len(rest)
			}
			return strings.TrimSpace(rest[:end])
		}
	}
	return ""
}

func isIPAddress(s string) bool {
	// Simple check — 4 dot-separated octets
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if len(p) == 0 || len(p) > 3 {
			return false
		}
		for _, c := range p {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	// Exclude private ranges from auto-blocking
	if strings.HasPrefix(s, "10.") ||
		strings.HasPrefix(s, "192.168.") ||
		strings.HasPrefix(s, "172.") ||
		s == "127.0.0.1" {
		return false
	}
	return true
}

// GetIOCBlocks returns the IOC auto-block history.
func GetIOCBlocks() ([]map[string]interface{}, error) {
	rows, err := database.DB.Query(`
		SELECT id, indicator, agent_id, blocked_at
		FROM ioc_firewall_blocks
		ORDER BY blocked_at DESC
		LIMIT 100
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var blocks []map[string]interface{}
	for rows.Next() {
		var id, agentID int
		var indicator, blockedAt string
		if err := rows.Scan(&id, &indicator, &agentID, &blockedAt); err == nil {
			blocks = append(blocks, map[string]interface{}{
				"id": id, "indicator": indicator,
				"agent_id": agentID, "blocked_at": blockedAt,
			})
		}
	}
	return blocks, nil
}
