package main

import (
	"fmt"
	"time"

	"xcloak-agent/agent"
)

const (
	heartbeatInterval = 30 * time.Second
	pollInterval      = 15 * time.Second
	registerMaxRetry  = 10
	registerRetryWait = 5 * time.Second
)

func main() {

	// ── Register with retry ───────────────────────────────────
	// On first startup (or after a server restart) the backend may not be
	// immediately reachable. Retry up to registerMaxRetry times so the agent
	// doesn't need manual intervention after a server bounce.
	var agentID int

	for attempt := 1; attempt <= registerMaxRetry; attempt++ {

		id, err := agent.Register()

		if err == nil {
			agentID = id
			break
		}

		fmt.Printf("Register attempt %d/%d failed: %v\n", attempt, registerMaxRetry, err)

		if attempt == registerMaxRetry {
			panic("Failed to register agent: " + err.Error())
		}

		time.Sleep(registerRetryWait)
	}

	fmt.Println("Registered as agent", agentID)

	// ── Heartbeat loop ────────────────────────────────────────
	go func() {
		for {
			agent.SendHeartbeat(agentID)
			time.Sleep(heartbeatInterval)
		}
	}()

	// ── Task poll loop ────────────────────────────────────────
	// Tasks are executed concurrently (each in its own goroutine) so a slow
	// task (e.g. YARA scan of /usr) doesn't block the poll for new tasks.
	// Each task has an internal 5-minute timeout (see executor.go).
	consecutiveErrors := 0

	for {

		tasks, err := agent.FetchTasks(agentID)

		if err != nil {
			consecutiveErrors++
			backoff := time.Duration(consecutiveErrors) * 5 * time.Second
			if backoff > 2*time.Minute {
				backoff = 2 * time.Minute
			}
			fmt.Printf("Poll error (%d consecutive): %v — waiting %s\n",
				consecutiveErrors, err, backoff)
			time.Sleep(backoff)
			continue
		}

		consecutiveErrors = 0

		for _, task := range tasks {
			go agent.ExecuteTask(task)
		}

		time.Sleep(pollInterval)
	}
}
