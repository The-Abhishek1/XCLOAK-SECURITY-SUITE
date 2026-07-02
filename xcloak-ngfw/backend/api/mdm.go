package api

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"xcloak-ngfw/services"
)

// ── Device endpoints ─────────────────────────────────────────────────────────

// POST /api/mdm/devices
// Enroll or update a device check-in.
func EnrollMDMDevice(c *gin.Context) {
	tenantID := c.GetInt("tenant_id")

	var d services.MDMDevice
	if err := c.ShouldBindJSON(&d); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	d.TenantID = tenantID

	if d.UDID == "" || d.Platform == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "udid and platform are required"})
		return
	}

	id, err := services.EnrollDevice(d)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"id": id, "message": "device enrolled"})
}

// GET /api/mdm/devices
// Query params: platform, status, owner_email
func ListMDMDevices(c *gin.Context) {
	tenantID := c.GetInt("tenant_id")
	platform   := c.Query("platform")
	status     := c.Query("status")
	ownerEmail := c.Query("owner_email")

	devices, err := services.ListDevices(tenantID, platform, status, ownerEmail)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if devices == nil {
		devices = []services.MDMDevice{}
	}
	c.JSON(http.StatusOK, gin.H{"devices": devices, "count": len(devices)})
}

// GET /api/mdm/devices/:id
func GetMDMDevice(c *gin.Context) {
	tenantID := c.GetInt("tenant_id")
	deviceID, _ := strconv.Atoi(c.Param("id"))

	device, err := services.GetDevice(deviceID, tenantID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "device not found"})
		return
	}
	c.JSON(http.StatusOK, device)
}

// DELETE /api/mdm/devices/:id
func UnenrollMDMDevice(c *gin.Context) {
	tenantID := c.GetInt("tenant_id")
	deviceID, _ := strconv.Atoi(c.Param("id"))

	if err := services.UnenrollDevice(deviceID, tenantID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "device unenrolled"})
}

// POST /api/mdm/devices/:id/block
func BlockMDMDevice(c *gin.Context) {
	tenantID := c.GetInt("tenant_id")
	deviceID, _ := strconv.Atoi(c.Param("id"))

	if err := services.BlockDevice(deviceID, tenantID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "device blocked"})
}

// ── Compliance endpoints ──────────────────────────────────────────────────────

// GET /api/mdm/devices/:id/compliance
func GetMDMDeviceCompliance(c *gin.Context) {
	tenantID := c.GetInt("tenant_id")
	deviceID, _ := strconv.Atoi(c.Param("id"))

	results, err := services.GetDeviceCompliance(deviceID, tenantID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	if results == nil {
		results = []services.MDMComplianceResult{}
	}
	c.JSON(http.StatusOK, gin.H{"results": results, "count": len(results)})
}

// GET /api/mdm/compliance/summary
func GetMDMComplianceSummary(c *gin.Context) {
	tenantID := c.GetInt("tenant_id")
	c.JSON(http.StatusOK, services.GetComplianceSummary(tenantID))
}

// POST /api/mdm/compliance/run
// Manually trigger a compliance evaluation for the tenant.
func TriggerMDMCompliance(c *gin.Context) {
	tenantID := c.GetInt("tenant_id")
	go services.RunComplianceForTenant(tenantID)
	c.JSON(http.StatusAccepted, gin.H{"message": "compliance evaluation started"})
}

// ── Policy endpoints ──────────────────────────────────────────────────────────

// GET /api/mdm/policies
func ListMDMPolicies(c *gin.Context) {
	tenantID := c.GetInt("tenant_id")
	policies, err := services.ListPolicies(tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if policies == nil {
		policies = []services.MDMPolicy{}
	}
	c.JSON(http.StatusOK, gin.H{"policies": policies, "count": len(policies)})
}

// POST /api/mdm/policies
func CreateMDMPolicy(c *gin.Context) {
	tenantID := c.GetInt("tenant_id")

	var p services.MDMPolicy
	if err := c.ShouldBindJSON(&p); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	p.TenantID = tenantID

	if p.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
		return
	}

	id, err := services.CreatePolicy(p)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": id, "message": "policy created"})
}

// ── Command endpoints ─────────────────────────────────────────────────────────

// POST /api/mdm/devices/:id/commands
// Body: { "command_type": "lock"|"wipe"|"sync"|"push_profile"|..., "payload": {} }
func QueueMDMCommand(c *gin.Context) {
	tenantID := c.GetInt("tenant_id")
	userID   := c.GetInt("user_id")
	deviceID, _ := strconv.Atoi(c.Param("id"))

	var req struct {
		CommandType string         `json:"command_type" binding:"required"`
		Payload     map[string]any `json:"payload"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Payload == nil {
		req.Payload = map[string]any{}
	}

	id, err := services.QueueCommand(tenantID, deviceID, userID, req.CommandType, req.Payload)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"command_id": id, "status": "pending"})
}

// GET /api/mdm/devices/:id/commands
func ListMDMCommands(c *gin.Context) {
	tenantID := c.GetInt("tenant_id")
	deviceID, _ := strconv.Atoi(c.Param("id"))
	limit := 50
	if l, err := strconv.Atoi(c.Query("limit")); err == nil && l > 0 && l <= 200 {
		limit = l
	}

	commands, err := services.ListCommands(deviceID, tenantID, limit)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	if commands == nil {
		commands = []services.MDMCommand{}
	}
	c.JSON(http.StatusOK, gin.H{"commands": commands, "count": len(commands)})
}

// POST /api/mdm/commands/:id/acknowledge
// Called by the device agent after executing a command.
func AcknowledgeMDMCommand(c *gin.Context) {
	commandID, _ := strconv.Atoi(c.Param("id"))

	var req struct {
		Success bool   `json:"success"`
		ErrMsg  string `json:"error_msg"`
	}
	c.ShouldBindJSON(&req)

	if err := services.AcknowledgeCommand(commandID, req.Success, req.ErrMsg); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "acknowledged"})
}

// ── Profile endpoints ─────────────────────────────────────────────────────────

// GET /api/mdm/profiles
func ListMDMProfiles(c *gin.Context) {
	tenantID := c.GetInt("tenant_id")
	profiles, err := services.ListProfiles(tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if profiles == nil {
		profiles = []services.MDMProfile{}
	}
	c.JSON(http.StatusOK, gin.H{"profiles": profiles, "count": len(profiles)})
}

// POST /api/mdm/profiles
func CreateMDMProfile(c *gin.Context) {
	tenantID := c.GetInt("tenant_id")

	var p services.MDMProfile
	if err := c.ShouldBindJSON(&p); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	p.TenantID = tenantID

	if p.Name == "" || p.Platform == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name and platform are required"})
		return
	}

	id, err := services.CreateProfile(p)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": id, "message": "profile created"})
}

// POST /api/mdm/profiles/:id/deploy
// Queues push_profile commands for all matching enrolled devices.
func DeployMDMProfile(c *gin.Context) {
	tenantID := c.GetInt("tenant_id")
	userID   := c.GetInt("user_id")
	profileID, _ := strconv.Atoi(c.Param("id"))

	count, err := services.DeployProfileToDevices(profileID, tenantID, userID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"message":         "profile queued for deployment",
		"devices_targeted": count,
	})
}
