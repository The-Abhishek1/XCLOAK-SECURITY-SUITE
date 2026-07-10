package api

import (
	"fmt"
	"strconv"

	"github.com/gin-gonic/gin"

	"xcloak-platform/services"
)

// ── Memory dump ──────────────────────────────────────────────────────────────

// DispatchMemoryDump — POST /api/agents/:id/memory-dump
// Body: { "pid": 0, "label": "pre-remediation" }
// pid=0 requests a full RAM dump; pid>0 dumps only that process's virtual memory.
func DispatchMemoryDump(c *gin.Context) {
	agentID, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid agent id"})
		return
	}
	if !agentBelongsToTenant(agentID, tenantIDFromContext(c)) {
		c.JSON(404, gin.H{"error": "agent not found"})
		return
	}

	var body struct {
		PID   int    `json:"pid"`
		Label string `json:"label"`
	}
	c.ShouldBindJSON(&body)
	if body.Label == "" {
		body.Label = "on-demand"
	}

	taskID, err := services.DispatchMemoryDump(agentID, tenantIDFromContext(c), body.PID, body.Label)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	username, _ := c.Get("username")
	services.LogEvent("MEMORY_DUMP_REQUESTED",
		fmt.Sprintf("agent #%d pid=%d label=%q task=#%d by %v", agentID, body.PID, body.Label, taskID, username),
		fmt.Sprintf("%v", username))

	c.JSON(200, gin.H{
		"task_id":  taskID,
		"agent_id": agentID,
		"message":  "memory dump task dispatched (pending approval)",
	})
}

// ── Process snapshot ─────────────────────────────────────────────────────────

// DispatchProcessSnapshot — POST /api/agents/:id/process-snapshot
// Body: { "collection_id": 0 }  (0 = standalone, not part of a collection)
func DispatchProcessSnapshot(c *gin.Context) {
	agentID, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid agent id"})
		return
	}
	if !agentBelongsToTenant(agentID, tenantIDFromContext(c)) {
		c.JSON(404, gin.H{"error": "agent not found"})
		return
	}

	var body struct {
		CollectionID int `json:"collection_id"`
	}
	c.ShouldBindJSON(&body)

	taskID, err := services.DispatchProcessSnapshot(agentID, tenantIDFromContext(c), body.CollectionID)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"task_id": taskID, "agent_id": agentID, "message": "process snapshot task dispatched"})
}

// ── Kill process tree ─────────────────────────────────────────────────────────

// DispatchKillTree — POST /api/agents/:id/kill-tree
// Body: { "process_name": "malware.exe", "reason": "confirmed IOC match" }
func DispatchKillTree(c *gin.Context) {
	agentID, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid agent id"})
		return
	}
	if !agentBelongsToTenant(agentID, tenantIDFromContext(c)) {
		c.JSON(404, gin.H{"error": "agent not found"})
		return
	}

	var body struct {
		ProcessName string `json:"process_name" binding:"required"`
		Reason      string `json:"reason"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(400, gin.H{"error": "process_name is required"})
		return
	}

	if err := services.DispatchKillProcessTree(agentID, tenantIDFromContext(c), body.ProcessName, body.Reason); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	username, _ := c.Get("username")
	services.LogEvent("KILL_TREE_REQUESTED",
		fmt.Sprintf("agent #%d process=%q reason=%q by %v", agentID, body.ProcessName, body.Reason, username),
		fmt.Sprintf("%v", username))

	c.JSON(200, gin.H{"message": "kill_process_tree task created, pending approval", "agent_id": agentID})
}

// ── Remediation plans ─────────────────────────────────────────────────────────

// CreateRemediationPlan — POST /api/incidents/:id/remediation
// Body: { "label": "...", "agent_id": N, "steps": [ {"action_type": "...", "payload": {...}}, ... ] }
func CreateRemediationPlan(c *gin.Context) {
	incidentID, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid incident id"})
		return
	}

	var body struct {
		Label   string                    `json:"label"`
		AgentID int                       `json:"agent_id" binding:"required"`
		Steps   []services.StepRequest    `json:"steps" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	if len(body.Steps) == 0 {
		c.JSON(400, gin.H{"error": "steps must not be empty"})
		return
	}
	if len(body.Steps) > 20 {
		c.JSON(400, gin.H{"error": "maximum 20 steps per plan"})
		return
	}

	if !agentBelongsToTenant(body.AgentID, tenantIDFromContext(c)) {
		c.JSON(404, gin.H{"error": "agent not found"})
		return
	}

	username, _ := c.Get("username")
	user := fmt.Sprintf("%v", username)
	if body.Label == "" {
		body.Label = fmt.Sprintf("Incident #%d remediation", incidentID)
	}

	iid := incidentID
	planID, err := services.CreateRemediationPlan(&iid, body.AgentID, tenantIDFromContext(c), body.Label, user, body.Steps)
	if err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	c.JSON(201, gin.H{"plan_id": planID, "message": "remediation plan created"})
}

// GetRemediationPlan — GET /api/incidents/:id/remediation/:plan_id
func GetRemediationPlan(c *gin.Context) {
	planID, err := strconv.Atoi(c.Param("plan_id"))
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid plan id"})
		return
	}
	plan, err := services.GetRemediationPlan(planID, tenantIDFromContext(c))
	if err != nil {
		c.JSON(404, gin.H{"error": "plan not found"})
		return
	}
	c.JSON(200, plan)
}

// ListRemediationPlans — GET /api/incidents/:id/remediation
func ListRemediationPlans(c *gin.Context) {
	incidentID, _ := strconv.Atoi(c.Param("id"))
	plans, err := services.ListRemediationPlans(incidentID, tenantIDFromContext(c))
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, plans)
}

// ExecuteRemediationPlan — POST /api/incidents/:id/remediation/:plan_id/execute
func ExecuteRemediationPlan(c *gin.Context) {
	planID, err := strconv.Atoi(c.Param("plan_id"))
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid plan id"})
		return
	}
	username, _ := c.Get("username")
	user := fmt.Sprintf("%v", username)

	if err := services.ExecuteRemediationPlan(planID, tenantIDFromContext(c), user); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"message": "remediation plan execution started", "plan_id": planID})
}

// ExecuteRemediationStep — POST /api/incidents/:id/remediation/:plan_id/steps/:step_id/execute
func ExecuteRemediationStep(c *gin.Context) {
	planID, err := strconv.Atoi(c.Param("plan_id"))
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid plan id"})
		return
	}
	stepID, err := strconv.Atoi(c.Param("step_id"))
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid step id"})
		return
	}
	username, _ := c.Get("username")
	user := fmt.Sprintf("%v", username)

	if err := services.ExecuteStep(planID, stepID, tenantIDFromContext(c), user); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"message": "step dispatched", "plan_id": planID, "step_id": stepID})
}
