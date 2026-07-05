package api

// MDM Mobile — API handlers for the Android/iOS self-enrollment flow.
//
// Enrollment flow:
//  1. Admin: POST /api/mdm/enrollment-tokens  → token string
//  2. Admin shares the token (QR code / email / MDM profile)
//  3. Device: POST /api/mdm/self-enroll        → agent_token + device_id
//  4. Device uses agent_token for all subsequent calls (RequireAgentAuth):
//     - PUT  /api/mdm/devices/:id/checkin        (posture + heartbeat)
//     - GET  /api/mdm/devices/:id/commands/pending
//     - POST /api/mdm/commands/:id/acknowledge  (existing endpoint)
//     - POST /api/logs/ingest                   (existing endpoint)
//     - POST /api/agents/heartbeat              (existing endpoint)

import (
	"fmt"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"xcloak-ngfw/middleware"
	"xcloak-ngfw/services"
)

// ── Enrollment token management (RequireAuth — admin/analyst) ─────────────────

// CreateEnrollmentToken — POST /api/mdm/enrollment-tokens
func CreateEnrollmentToken(c *gin.Context) {
	var req struct {
		Label     string `json:"label"`
		Platform  string `json:"platform"`   // android|ios|any
		MaxUses   *int   `json:"max_uses"`   // nil = unlimited
		ExpiresIn *int   `json:"expires_in"` // seconds from now; nil = never
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	if req.Label == "" {
		req.Label = "mobile-enroll"
	}

	var expiresAt *time.Time
	if req.ExpiresIn != nil && *req.ExpiresIn > 0 {
		t := time.Now().Add(time.Duration(*req.ExpiresIn) * time.Second)
		expiresAt = &t
	}

	userID, _ := c.Get("user_id")
	uid, _ := userID.(float64)
	token, err := services.CreateEnrollmentToken(
		tenantIDFromContext(c), req.Label, req.Platform,
		req.MaxUses, expiresAt, int(uid),
	)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	username, _ := c.Get("username")
	services.LogEvent("MDM_ENROLL_TOKEN_CREATE",
		fmt.Sprintf("label=%s platform=%s", req.Label, req.Platform),
		fmt.Sprintf("%v", username))
	c.JSON(201, token)
}

// ListEnrollmentTokens — GET /api/mdm/enrollment-tokens
func ListEnrollmentTokens(c *gin.Context) {
	tokens, err := services.ListEnrollmentTokens(tenantIDFromContext(c))
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, tokens)
}

// RevokeEnrollmentToken — DELETE /api/mdm/enrollment-tokens/:id
func RevokeEnrollmentToken(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid id"})
		return
	}
	if err := services.RevokeEnrollmentToken(id, tenantIDFromContext(c)); err != nil {
		c.JSON(404, gin.H{"error": err.Error()})
		return
	}
	username, _ := c.Get("username")
	services.LogEvent("MDM_ENROLL_TOKEN_REVOKE", fmt.Sprintf("id=%d", id), fmt.Sprintf("%v", username))
	c.JSON(200, gin.H{"message": "token revoked"})
}

// ── Self-enrollment (no user auth, only enrollment token) ─────────────────────

// SelfEnrollDevice — POST /api/mdm/self-enroll
// Called by the mobile agent during first-time setup. Returns an agent_token
// that the device stores in secure storage and uses for all future calls.
func SelfEnrollDevice(c *gin.Context) {
	var req struct {
		EnrollToken  string  `json:"enroll_token"`
		UDID         string  `json:"udid"`
		DeviceName   string  `json:"device_name"`
		Model        string  `json:"model"`
		OSVersion    string  `json:"os_version"`
		BuildVersion string  `json:"build_version"`
		OwnerEmail   string  `json:"owner_email"`
		PushToken    string  `json:"push_token"` // FCM token for push delivery
		IsEncrypted  *bool   `json:"is_encrypted"`
		HasPasscode  *bool   `json:"has_passcode"`
		IsRooted     bool    `json:"is_rooted"`
		DevModeOn    bool    `json:"developer_mode_on"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	if req.EnrollToken == "" {
		c.JSON(400, gin.H{"error": "enroll_token is required"})
		return
	}
	if req.UDID == "" {
		c.JSON(400, gin.H{"error": "udid is required"})
		return
	}

	device := services.MDMDevice{
		UDID:           req.UDID,
		DeviceName:     req.DeviceName,
		Model:          req.Model,
		Platform:       "android",
		OSVersion:      req.OSVersion,
		BuildVersion:   req.BuildVersion,
		OwnerEmail:     req.OwnerEmail,
		PushToken:      req.PushToken,
		EnrollmentType: "byod",
		IsEncrypted:    req.IsEncrypted,
		HasPasscode:    req.HasPasscode,
		IsJailbroken:   req.IsRooted,
		DeveloperModeOn: req.DevModeOn,
	}

	result, err := services.SelfEnrollDevice(req.EnrollToken, device)
	if err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, gin.H{
		"device_id":   result.DeviceID,
		"agent_id":    result.AgentID,
		"agent_token": result.AgentToken,
	})
}

// ── Agent-authenticated device operations ─────────────────────────────────────

// MobileDeviceCheckIn — PUT /api/mdm/devices/:id/checkin
// The mobile agent posts posture data on every check-in cycle (default: 5 min).
// Uses RequireAgentAuth — the device's agent_token is validated, then we confirm
// the device_id matches the calling agent before updating.
func MobileDeviceCheckIn(c *gin.Context) {
	deviceID, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid device id"})
		return
	}

	// Verify the calling agent owns this device.
	agentRaw, _ := c.Get(middleware.AgentKey)
	if agentRaw == nil {
		c.JSON(401, gin.H{"error": "agent auth required"})
		return
	}
	tenantID, _ := c.Get("tenant_id")
	tid := int(tenantID.(int))

	linkedDeviceID, err := services.LookupDeviceByAgent(
		c.GetInt("agent_id"), tid,
	)
	if err != nil || linkedDeviceID != deviceID {
		c.JSON(403, gin.H{"error": "device does not belong to this agent"})
		return
	}

	var req struct {
		OSVersion    string `json:"os_version"`
		BuildVersion string `json:"build_version"`
		IsEncrypted  *bool  `json:"is_encrypted"`
		HasPasscode  *bool  `json:"has_passcode"`
		PasscodeOK   *bool  `json:"passcode_compliant"`
		IsRooted     bool   `json:"is_rooted"`
		DevModeOn    bool   `json:"developer_mode_on"`
		PushToken    string `json:"push_token"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	d := services.MDMDevice{
		OSVersion:         req.OSVersion,
		BuildVersion:      req.BuildVersion,
		IsEncrypted:       req.IsEncrypted,
		HasPasscode:       req.HasPasscode,
		PasscodeCompliant: req.PasscodeOK,
		IsJailbroken:      req.IsRooted,
		DeveloperModeOn:   req.DevModeOn,
		PushToken:         req.PushToken,
	}
	if err := services.DeviceCheckIn(deviceID, tid, d); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"ok": true})
}

// GetPendingMobileCommands — GET /api/mdm/devices/:id/commands/pending
// Mobile agent polls this endpoint (RequireAgentAuth) to receive queued commands
// when FCM push is unavailable or not configured.
func GetPendingMobileCommands(c *gin.Context) {
	deviceID, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid device id"})
		return
	}

	tenantID, _ := c.Get("tenant_id")
	tid := int(tenantID.(int))

	linkedDeviceID, err := services.LookupDeviceByAgent(c.GetInt("agent_id"), tid)
	if err != nil || linkedDeviceID != deviceID {
		c.JSON(403, gin.H{"error": "device does not belong to this agent"})
		return
	}

	cmds, err := services.GetPendingMobileCommands(deviceID, tid)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"commands": cmds})
}

// SubmitAppInventory — POST /api/mdm/devices/:id/apps
// The mobile agent uploads the full app list for sideload / threat detection.
func SubmitAppInventory(c *gin.Context) {
	deviceID, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid device id"})
		return
	}

	tenantID, _ := c.Get("tenant_id")
	tid := int(tenantID.(int))

	linkedDeviceID, err := services.LookupDeviceByAgent(c.GetInt("agent_id"), tid)
	if err != nil || linkedDeviceID != deviceID {
		c.JSON(403, gin.H{"error": "device does not belong to this agent"})
		return
	}

	var req struct {
		Apps []services.AppInfo `json:"apps"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	if len(req.Apps) > 1000 {
		c.JSON(400, gin.H{"error": "app list exceeds 1000 entries"})
		return
	}

	if err := services.SubmitAppInventory(deviceID, tid, req.Apps); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"received": len(req.Apps)})
}
