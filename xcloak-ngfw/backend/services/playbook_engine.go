package services

import (
	"encoding/json"
	"fmt"
	"strings"

	"xcloak-ngfw/models"
	"xcloak-ngfw/repositories"
)

// TriggerTypes supported:
//
//	alert_critical        — fires on any alert with severity "critical"
//	alert_high            — fires on any alert with severity "high"
//	alert_medium          — fires on any alert with severity "medium"
//	alert_any             — fires on every alert regardless of severity
//	IOC Match             — fires when the triggering rule is "IOC Match"
//	YARA Match            — fires when the triggering rule is "YARA Match"
//	incident_created      — fires when a new incident is auto-created
//	<exact rule name>     — fires when alert.RuleName matches exactly
//
// This is checked in matchesTrigger below. Adding a new trigger type only
// requires adding a case here — no schema change needed.
func ExecutePlaybooks(alert models.Alert) {

	fmt.Printf("SOAR: evaluating alert rule=%q severity=%q agent=%d\n",
		alert.RuleName, alert.Severity, alert.AgentID)

	playbooks, err := repositories.GetEnabledPlaybooksForAgent(alert.AgentID)
	if err != nil {
		fmt.Println("SOAR: failed to load playbooks:", err)
		return
	}

	for _, playbook := range playbooks {

		if !matchesTrigger(playbook.TriggerType, alert) {
			continue
		}

		fmt.Printf("SOAR: playbook %q triggered (trigger=%q)\n", playbook.Name, playbook.TriggerType)

		actions, err := repositories.GetPlaybookActions(playbook.ID)
		if err != nil {
			fmt.Printf("SOAR: failed to load actions for playbook %d: %v\n", playbook.ID, err)
			continue
		}

		for _, action := range actions {

			err := dispatchAction(action, alert)

			status := "success"
			errDetail := ""
			if err != nil {
				status = "failed"
				errDetail = err.Error()
				fmt.Printf("SOAR: action %q failed: %v\n", action.ActionType, err)
			} else {
				fmt.Printf("SOAR: action %q dispatched for agent %d\n", action.ActionType, alert.AgentID)
			}

			logPlaybookExecution(playbook, action, alert, status, errDetail)
		}
	}
}

// matchesTrigger returns true if a playbook's TriggerType should fire for
// the given alert.
func matchesTrigger(triggerType string, alert models.Alert) bool {

	switch strings.ToLower(triggerType) {

	case "alert_critical":
		return strings.ToLower(alert.Severity) == "critical"

	case "alert_high":
		return strings.ToLower(alert.Severity) == "high"

	case "alert_medium":
		return strings.ToLower(alert.Severity) == "medium"

	case "alert_low":
		return strings.ToLower(alert.Severity) == "low"

	case "alert_any":
		return true

	case "ioc match":
		return strings.EqualFold(alert.RuleName, "IOC Match")

	case "yara match":
		return strings.EqualFold(alert.RuleName, "YARA Match")

	default:
		// Exact rule-name match (legacy behaviour + custom trigger names).
		return strings.EqualFold(triggerType, alert.RuleName)
	}
}

// dispatchAction creates an agent task for the action type, merging the
// action's stored payload with the alert context (so actions like
// quarantine_file can pick up the matched file path automatically).
//
// Destructive action types (see IsDestructiveTask) are held as
// pending_approval instead of being dispatched immediately — ExecutePlaybooks
// runs with zero human review, so a misconfigured or overly broad trigger
// could otherwise isolate/kill/quarantine across the whole fleet before
// anyone notices. Manual dispatch (DispatchAlertResponse) goes through the
// same gate, since a compromised/malicious session hitting the API directly
// is no less dangerous than a bad playbook trigger.
func dispatchAction(action models.PlaybookAction, alert models.Alert) error {

	// Merge alert context into action payload so the agent has full info.
	payload := mergePayload(action.Payload, alert)

	task := models.AgentTask{
		AgentID:  alert.AgentID,
		TaskType: action.ActionType,
		Payload:  payload,
	}

	if IsDestructiveTask(action.ActionType) {
		if err := repositories.CreateTaskPendingApproval(task); err != nil {
			return err
		}
		LogEvent(
			"SOAR_ACTION_PENDING_APPROVAL",
			fmt.Sprintf("Playbook → %s on agent #%d from alert %q, awaiting approval", action.ActionType, alert.AgentID, alert.RuleName),
			"system",
		)
		return nil
	}
	return CreateTask(task)
}

// mergePayload takes an action's stored JSON payload and enriches it with
// alert context fields (agent_id, rule_name, severity). The action payload
// wins on key conflicts.
func mergePayload(actionPayload json.RawMessage, alert models.Alert) json.RawMessage {

	base := map[string]interface{}{
		"agent_id":   alert.AgentID,
		"rule_name":  alert.RuleName,
		"severity":   alert.Severity,
		"log_sample": truncate(alert.LogMessage, 200),
	}

	// Overlay any fields from the stored action payload.
	if len(actionPayload) > 0 && string(actionPayload) != "null" {
		var extra map[string]interface{}
		if err := json.Unmarshal(actionPayload, &extra); err == nil {
			for k, v := range extra {
				base[k] = v
			}
		}
	}

	merged, _ := json.Marshal(base)
	return merged
}

func logPlaybookExecution(
	playbook models.Playbook,
	action models.PlaybookAction,
	alert models.Alert,
	status, errDetail string,
) {
	LogPlaybookExecution(models.PlaybookExecution{
		PlaybookID: playbook.ID,
		AgentID:    alert.AgentID,
		AlertRule:  alert.RuleName,
		ActionType: action.ActionType,
		Status:     status,
	})
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
