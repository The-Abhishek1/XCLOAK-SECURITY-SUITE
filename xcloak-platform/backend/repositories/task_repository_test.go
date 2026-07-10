package repositories

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"

	"xcloak-platform/database"
	"xcloak-platform/models"
)

// These are integration tests against a real Postgres instance — gated
// behind RUN_INTEGRATION_TESTS so `go test ./...` never touches a real
// database by accident. CI sets this against a throwaway DB; set it
// locally only if DB_* in your .env points at a database you're fine
// inserting/deleting test rows in.
func skipUnlessIntegration(t *testing.T) {
	t.Helper()
	if os.Getenv("RUN_INTEGRATION_TESTS") == "" {
		t.Skip("set RUN_INTEGRATION_TESTS=1 to run repository tests against a real Postgres instance")
	}
	if database.DB == nil {
		if err := database.Connect(); err != nil {
			t.Fatalf("database.Connect: %v", err)
		}
		if err := database.Migrate(); err != nil {
			t.Fatalf("database.Migrate: %v", err)
		}
	}
}

// createTestAgent inserts a throwaway agent row and returns its ID, with a
// cleanup registered to delete it (and, via ON DELETE CASCADE, its tasks).
func createTestAgent(t *testing.T) int {
	t.Helper()

	unique := fmt.Sprintf("test-%d", time.Now().UnixNano())

	var agentID int
	err := database.DB.QueryRow(`
		INSERT INTO agents (hostname, os, status, machine_id, token)
		VALUES ('test-agent-task-dispatch', 'linux', 'online', $1, $2)
		RETURNING id
	`, unique, unique).Scan(&agentID)
	if err != nil {
		t.Fatalf("inserting test agent: %v", err)
	}

	t.Cleanup(func() {
		// agent_tasks.agent_id has no ON DELETE CASCADE — delete tasks first
		// or the agent delete fails on the FK constraint.
		if _, err := database.DB.Exec(`DELETE FROM agent_tasks WHERE agent_id = $1`, agentID); err != nil {
			t.Errorf("cleanup: deleting test agent's tasks: %v", err)
		}
		if _, err := database.DB.Exec(`DELETE FROM agents WHERE id = $1`, agentID); err != nil {
			t.Errorf("cleanup: deleting test agent: %v", err)
		}
	})

	return agentID
}

func TestCreateTask_AndGetPendingTasks(t *testing.T) {
	skipUnlessIntegration(t)

	agentID := createTestAgent(t)

	payload, _ := json.Marshal(map[string]string{"shell": "bash", "script": "echo hi"})
	err := CreateTask(models.AgentTask{
		AgentID:  agentID,
		TaskType: "execute_script",
		Payload:  payload,
	})
	if err != nil {
		t.Fatalf("CreateTask: %v", err)
	}

	tasks, err := GetPendingTasks(strconv.Itoa(agentID))
	if err != nil {
		t.Fatalf("GetPendingTasks: %v", err)
	}

	if len(tasks) != 1 {
		t.Fatalf("got %d pending tasks, want 1", len(tasks))
	}
	if tasks[0].TaskType != "execute_script" {
		t.Errorf("task_type = %q, want execute_script", tasks[0].TaskType)
	}
	if tasks[0].Status != "pending" {
		t.Errorf("status = %q, want pending", tasks[0].Status)
	}
}

func TestCreateTask_DefaultsEmptyPayload(t *testing.T) {
	skipUnlessIntegration(t)

	agentID := createTestAgent(t)

	err := CreateTask(models.AgentTask{
		AgentID:  agentID,
		TaskType: "kill_process",
	})
	if err != nil {
		t.Fatalf("CreateTask with empty payload: %v", err)
	}

	tasks, err := GetPendingTasks(strconv.Itoa(agentID))
	if err != nil {
		t.Fatalf("GetPendingTasks: %v", err)
	}
	if len(tasks) != 1 {
		t.Fatalf("got %d pending tasks, want 1", len(tasks))
	}
}
