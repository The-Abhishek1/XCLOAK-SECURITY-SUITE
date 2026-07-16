package api

import (
	"strconv"

	"github.com/gin-gonic/gin"

	"xcloak-platform/database"
	"xcloak-platform/repositories"
)

// AgentSecurityStatus is a derived security posture snapshot for one agent.
type AgentSecurityStatus struct {
	EDREnabled       bool    `json:"edr_enabled"`
	TamperProtection *bool   `json:"tamper_protection"`
	IsIsolated       bool    `json:"is_isolated"`
	VPNActive        *bool   `json:"vpn_active"`
	IsRooted         *bool   `json:"is_rooted"`
	DeveloperMode    *bool   `json:"developer_mode"`
	SecurityPatch    *string `json:"security_patch"`
	SensorHealth     string  `json:"sensor_health"`
	// Fields below require agent-side reporting and default to null until collected.
	FirewallEnabled  *bool   `json:"firewall_enabled"`
	DiskEncrypted    *bool   `json:"disk_encrypted"`
	SecureBoot       *bool   `json:"secure_boot"`
	TPMPresent       *bool   `json:"tpm_present"`
	AntivirusRunning *bool   `json:"antivirus_running"`
	DefenderStatus   string  `json:"defender_status"`
	PatchStatus      string  `json:"patch_status"`
}

// GetAgentSecurityStatus returns the security posture for a single agent.
func GetAgentSecurityStatus(c *gin.Context) {
	agentID, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid agent id"})
		return
	}

	tenantID := tenantIDFromContext(c)
	agent, err := repositories.GetAgentByID(c.Param("id"), tenantID)
	if err != nil {
		c.JSON(404, gin.H{"error": "agent not found"})
		return
	}

	// Derive sensor health from agent status.
	sensorHealth := "healthy"
	if agent.Status == "offline" {
		sensorHealth = "offline"
	}

	// Check if there is an active isolate_host task for this agent.
	var isolateCount int
	_ = database.DB.QueryRow(`
		SELECT COUNT(*) FROM tasks
		WHERE agent_id = $1 AND task_type = 'isolate_host' AND status IN ('pending','running')
	`, agentID).Scan(&isolateCount)
	isIsolated := isolateCount > 0

	// Derive patch status from security_patch field (mobile) or agent version freshness.
	patchStatus := "unknown"
	if agent.SecurityPatch != nil && *agent.SecurityPatch != "" {
		patchStatus = "reported"
	}

	status := AgentSecurityStatus{
		EDREnabled:       true,
		IsIsolated:       isIsolated,
		VPNActive:        agent.VPNActive,
		IsRooted:         agent.IsRooted,
		DeveloperMode:    agent.DeveloperMode,
		SecurityPatch:    agent.SecurityPatch,
		SensorHealth:     sensorHealth,
		DefenderStatus:   "unknown",
		PatchStatus:      patchStatus,
		// Fields below require agent-side collection; null until reported.
		FirewallEnabled:  nil,
		DiskEncrypted:    nil,
		SecureBoot:       nil,
		TPMPresent:       nil,
		AntivirusRunning: nil,
	}

	c.JSON(200, status)
}
