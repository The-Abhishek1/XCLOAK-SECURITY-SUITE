package agent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	"xcloak-agent/config"
	"xcloak-agent/models"
)

func ExecuteTask(task models.AgentTask) {

	var output string

	switch task.TaskType {

	case "collect_processes":

		CollectProcesses(task.AgentID)

		output = "process inventory collected"

	case "collect_connections":

		CollectConnections(task.AgentID)

		output = "connection inventory collected"

	case "collect_services":

		CollectServices(task.AgentID)

		output = "service inventory collected"

	case "collect_packages":

		CollectPackages(task.AgentID)

		output = "package inventory collected"

	case "collect_users":

		CollectUsers(
			task.AgentID,
		)

		output = "user inventory collected"

	case "collect_auth_logs":

		CollectAuthLogs(
			task.AgentID,
		)

		output = "auth logs collected"

	case "kill_process":

		KillProcess(
			task,
		)

		output = "process terminated"

	case "collect_file":

		CollectFile(task)

		output = "file collected"

	case "isolate_host":

		err := IsolateHost(task)

		if err != nil {
			output = err.Error()
		} else {
			output = "host isolated"
		}

	case "quarantine_file":

		err := QuarantineFile(task)

		if err != nil {
			output = err.Error()
		} else {
			output = "file quarantined"
		}

	case "execute_script":

		result, err := ExecuteScript(task)

		if err != nil {
			output = err.Error() + "\n" + result
		} else {
			output = result
		}

	case "collect_file_hashes":

		hashes := CollectFileHashes(
			task.AgentID,
		)

		SendFileHashes(
			hashes,
		)

		output = "file hashes collected"

	case "scan_yara":

		var payload models.TaskPayload

		json.Unmarshal(
			task.Payload,
			&payload,
		)

		if payload.Path == "" {

			output = "missing path"

			break
		}

		matches := ScanWithYara(
			task.AgentID,
			payload.Path,
		)

		SendYaraMatches(
			matches,
		)

		output = fmt.Sprintf(
			"YARA matches found: %d",
			len(matches),
		)

	default:

		output = "unknown task"
	}

	taskResult := models.TaskResult{
		TaskID: task.ID,
		Result: output,
	}

	body, _ := json.Marshal(
		taskResult,
	)

	_, err := http.Post(
		config.ServerURL+"/api/tasks/result",
		"application/json",
		bytes.NewBuffer(body),
	)

	if err != nil {
		println(
			"Failed sending task result",
		)
		return
	}

	println(
		"Executed:",
		task.TaskType,
	)
}
