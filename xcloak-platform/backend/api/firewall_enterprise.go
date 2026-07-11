package api

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"xcloak-platform/models"
	"xcloak-platform/repositories"
	"xcloak-platform/services"
	"xcloak-platform/validators"
)

// GetFirewallPolicy — GET /api/firewall/policy
func GetFirewallPolicy(c *gin.Context) {
	tenantID := tenantIDFromContext(c)
	action, err := repositories.GetFirewallPolicy(tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"default_action": action})
}

// SetFirewallPolicy — PUT /api/firewall/policy
func SetFirewallPolicy(c *gin.Context) {
	tenantID := tenantIDFromContext(c)
	userVal, _ := c.Get("username")
	username, _ := userVal.(string)

	var body struct {
		DefaultAction string `json:"default_action"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.DefaultAction == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "default_action required"})
		return
	}
	if body.DefaultAction != "allow" && body.DefaultAction != "deny" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "default_action must be 'allow' or 'deny'"})
		return
	}
	if username == "" {
		username = "system"
	}
	if err := repositories.SetFirewallPolicy(tenantID, body.DefaultAction, username); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"default_action": body.DefaultAction})
}

// BulkFirewallAction — POST /api/firewall/rules/bulk
// Body: { "ids": [1,2,3], "action": "enable"|"disable"|"delete" }
func BulkFirewallAction(c *gin.Context) {
	tenantID := tenantIDFromContext(c)

	var body struct {
		IDs    []int  `json:"ids"`
		Action string `json:"action"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if len(body.IDs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ids array required"})
		return
	}
	if body.Action != "enable" && body.Action != "disable" && body.Action != "delete" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "action must be enable, disable, or delete"})
		return
	}

	n, err := repositories.BulkAction(body.IDs, body.Action, tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"affected": n})
}

// ImportFirewallRules — POST /api/firewall/rules/import
// Body: { "rules": [ <FirewallRule objects> ], "mode": "append"|"replace" }
func ImportFirewallRules(c *gin.Context) {
	tenantID := tenantIDFromContext(c)

	var body struct {
		Rules []models.FirewallRule `json:"rules"`
		Mode  string               `json:"mode"` // "append" (default) | "replace"
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if len(body.Rules) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "rules array required"})
		return
	}

	// Validate all before writing any (all-or-nothing feel).
	for i, r := range body.Rules {
		if err := validators.ValidateFirewallRule(r); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "validation failed at rule index " + fwItoa(i) + ": " + err.Error(),
			})
			return
		}
	}

	if body.Mode == "replace" {
		existing, _ := repositories.GetRulesForTenant(tenantID)
		ids := make([]int, 0, len(existing))
		for _, r := range existing {
			ids = append(ids, r.ID)
		}
		if len(ids) > 0 {
			repositories.BulkAction(ids, "delete", tenantID)
		}
	}

	var imported, failed int
	for _, r := range body.Rules {
		if err := repositories.CreateRule(r, tenantID); err != nil {
			failed++
		} else {
			imported++
		}
	}

	c.JSON(http.StatusOK, gin.H{"imported": imported, "failed": failed})
}

// GetFirewallTemplates — GET /api/firewall/templates
// Returns a curated list of common enterprise rule templates.
func GetFirewallTemplates(c *gin.Context) {
	c.JSON(http.StatusOK, firewallTemplates)
}

// GetExpiredFirewallRules — GET /api/firewall/expired
func GetExpiredFirewallRules(c *gin.Context) {
	rules, err := repositories.GetExpiredRules(tenantIDFromContext(c))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if rules == nil {
		rules = []models.FirewallRule{}
	}
	c.JSON(http.StatusOK, rules)
}

// PruneExpiredFirewallRules — DELETE /api/firewall/expired
func PruneExpiredFirewallRules(c *gin.Context) {
	n, err := repositories.PruneExpiredRules(tenantIDFromContext(c))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"pruned": n})
}

// GetFirewallConflictsV2 replaces the old handler using the upgraded service.
func GetFirewallConflictsV2(c *gin.Context) {
	conflicts, err := services.DetectFirewallConflicts(tenantIDFromContext(c))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, conflicts)
}

// ─────────────────────────────────────────────────────────────────────────────
// Built-in templates
// ─────────────────────────────────────────────────────────────────────────────

var firewallTemplates = []map[string]interface{}{
	{
		"name": "Block Telnet", "description": "Block inbound Telnet (legacy, insecure)",
		"group_name": "security-baseline", "direction": "in",
		"protocol": "tcp", "port_range": "23", "action": "deny",
		"tags": []string{"baseline", "telnet"},
	},
	{
		"name": "Allow HTTPS", "description": "Allow inbound HTTPS traffic",
		"group_name": "web", "direction": "in",
		"protocol": "tcp", "port_range": "443", "action": "allow",
		"tags": []string{"web", "https"},
	},
	{
		"name": "Allow HTTP", "description": "Allow inbound HTTP traffic",
		"group_name": "web", "direction": "in",
		"protocol": "tcp", "port_range": "80", "action": "allow",
		"tags": []string{"web", "http"},
	},
	{
		"name": "Block SMB", "description": "Block inbound SMB — prevents lateral movement",
		"group_name": "security-baseline", "direction": "in",
		"protocol": "tcp", "port_range": "445", "action": "deny",
		"tags": []string{"baseline", "smb", "lateral-movement"},
	},
	{
		"name": "Block RDP (external)", "description": "Block inbound RDP from any source",
		"group_name": "security-baseline", "direction": "in",
		"protocol": "tcp", "port_range": "3389", "action": "deny",
		"tags": []string{"baseline", "rdp"},
	},
	{
		"name": "Allow DNS (outbound)", "description": "Allow outbound DNS queries",
		"group_name": "dns", "direction": "out",
		"protocol": "udp", "port_range": "53", "action": "allow",
		"tags": []string{"dns", "outbound"},
	},
	{
		"name": "Allow NTP (outbound)", "description": "Allow outbound NTP",
		"group_name": "infra", "direction": "out",
		"protocol": "udp", "port_range": "123", "action": "allow",
		"tags": []string{"ntp", "infra"},
	},
	{
		"name": "Block NetBIOS", "description": "Block NetBIOS name service and datagram",
		"group_name": "security-baseline", "direction": "in",
		"protocol": "udp", "port_range": "137,138", "action": "deny",
		"tags": []string{"baseline", "netbios"},
	},
	{
		"name": "Block WinRM", "description": "Block Windows Remote Management",
		"group_name": "security-baseline", "direction": "in",
		"protocol": "tcp", "port_range": "5985,5986", "action": "deny",
		"tags": []string{"baseline", "winrm"},
	},
	{
		"name": "Allow SSH", "description": "Allow inbound SSH",
		"group_name": "admin", "direction": "in",
		"protocol": "tcp", "port_range": "22", "action": "allow",
		"tags": []string{"admin", "ssh"},
	},
	{
		"name": "Allow ICMP", "description": "Allow ICMP (ping/traceroute for diagnostics)",
		"group_name": "infra", "direction": "both",
		"protocol": "icmp", "port_range": "", "action": "allow",
		"tags": []string{"infra", "icmp"},
	},
	{
		"name": "Block known-bad ports", "description": "Block common C2/RAT/botnet ports",
		"group_name": "threat-prevention", "direction": "both",
		"protocol": "tcp", "port_range": "1080,4444,6666,6667,6697,8080,31337", "action": "deny",
		"tags": []string{"threat-prevention", "c2", "malware"},
	},
}

func fwItoa(n int) string {
	if n == 0 {
		return "0"
	}
	s := ""
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	return s
}
