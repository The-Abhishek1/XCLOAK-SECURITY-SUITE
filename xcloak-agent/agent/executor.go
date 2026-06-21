package agent

import (
	"encoding/json"
	"fmt"
	"time"

	"xcloak-agent/models"
)

const taskTimeout = 5 * time.Minute

func ExecuteTask(task models.AgentTask) {

	done := make(chan string, 1)

	go func() {
		done <- runTask(task)
	}()

	var output string

	select {
	case output = <-done:
	case <-time.After(taskTimeout):
		output = fmt.Sprintf("task timed out after %s", taskTimeout)
		fmt.Printf("Task %d (%s) timed out\n", task.ID, task.TaskType)
	}

	submitResult(task.ID, output)
}

func runTask(task models.AgentTask) string {

	switch task.TaskType {

	case "collect_processes":
		CollectProcesses(task.AgentID)
		return "process inventory collected"

	case "collect_connections":
		CollectConnections(task.AgentID)
		return "connection inventory collected"

	case "collect_services":
		CollectServices(task.AgentID)
		return "service inventory collected"

	case "collect_packages":
		CollectPackages(task.AgentID)
		return "package inventory collected"

	case "collect_users":
		CollectUsers(task.AgentID)
		return "user inventory collected"

	case "collect_auth_logs":
		CollectAuthLogs(task.AgentID)
		return "auth logs collected"

	case "kill_process":
		if err := KillProcess(task); err != nil {
			return "kill_process failed: " + err.Error()
		}
		return "process terminated"

	case "collect_file":
		CollectFile(task)
		return "file collected"

	case "isolate_host":
		if err := IsolateHost(task); err != nil {
			return "isolate failed: " + err.Error()
		}
		return "host isolated"

	case "quarantine_file":
		if err := QuarantineFile(task); err != nil {
			return "quarantine failed: " + err.Error()
		}
		return "file quarantined"

	case "execute_script":
		result, err := ExecuteScript(task)
		if err != nil {
			return err.Error() + "\n" + result
		}
		return result

	case "collect_file_hashes":
		hashes := CollectFileHashes(task.AgentID)
		SendFileHashes(hashes)
		return "file hashes collected"

	case "scan_yara":
		var payload models.TaskPayload
		if err := json.Unmarshal(task.Payload, &payload); err != nil {
			return "invalid scan_yara payload: " + err.Error()
		}
		if payload.Path == "" {
			return "missing path in payload"
		}
		matches := ScanWithYara(task.AgentID, payload.Path)
		SendYaraMatches(matches)
		return fmt.Sprintf("YARA matches found: %d", len(matches))

	case "fim_scan":
		RunFIMScan(task.AgentID, task.Payload)
		return "FIM scan completed"

	// vulnerability_scan: collect packages so the backend can scan them.
	// The actual CVE matching runs server-side via ScanAgentPackages().
	// This task type is dispatched from POST /api/agents/:id/vulnerability-scan.
	case "vulnerability_scan":
		CollectPackages(task.AgentID)
		return "packages collected for vulnerability scan"

	// apply_firewall_rules: translate XCloak rules into iptables commands.
	case "apply_firewall_rules":
		result, err := ApplyFirewallRules(task)
		if err != nil {
			return "firewall sync failed: " + err.Error()
		}
		return result

	// restore_file: move a quarantined file back to its original path.
	case "restore_file":
		return RestoreQuarantinedFile(task)

	default:
		return "unknown task type: " + task.TaskType
	}
}

func submitResult(taskID int, output string) {

	result := models.TaskResult{
		TaskID: taskID,
		Result: output,
	}

	body, _ := json.Marshal(result)

	resp, err := authPost("/api/tasks/result", body)
	if err != nil {
		fmt.Println("Failed sending task result:", err)
		return
	}
	defer resp.Body.Close()

	fmt.Printf("Task %d result submitted: %s\n", taskID, output)
}
