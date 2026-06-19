package main

import (
	"fmt"
	"math/rand"
	"os"
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

	// Seed the global RNG used for collection jitter.
	rand.Seed(time.Now().UnixNano()) //nolint:staticcheck

	var agentID int

	// ── Check if already registered ───────────────────────────
	// If a token is saved on disk, we're already registered.
	// Try to resume using the saved token before attempting re-registration.
	if existingToken := agent.LoadToken(); existingToken != "" {
		id, err := agent.ResumeSession()
		if err == nil {
			agentID = id
			fmt.Printf("✓ Resumed as agent #%d (token found on disk)\n", agentID)
			goto startLoops
		}
		fmt.Printf("[WARN] Saved token invalid (%v) — re-registering...\n", err)
		// Clear bad token so we re-register fresh
		agent.ClearToken()
	}

	// ── First-time registration with retry ────────────────────
	for attempt := 1; attempt <= registerMaxRetry; attempt++ {

		id, err := agent.Register()

		if err == nil {
			agentID = id
			break
		}

		fmt.Printf("Register attempt %d/%d failed: %v\n", attempt, registerMaxRetry, err)

		if attempt == registerMaxRetry {
			fmt.Println("\nAll registration attempts failed. Exiting.")
			fmt.Println("Fix: Generate a new install token at XCloak UI → Agents → Add Agent")
			os.Exit(1)
		}

		time.Sleep(registerRetryWait)
	}

startLoops:
	fmt.Printf("✓ Agent #%d running\n", agentID)

	// ── Heartbeat loop ─────────────────────────────────────────
	go func() {
		for {
			agent.SendHeartbeat(agentID)
			time.Sleep(heartbeatInterval)
		}
	}()

	// ── Autonomous collection loops ────────────────────────────
	// Starts 7 independent goroutines that collect and ship telemetry on
	// fixed intervals without requiring server-dispatched tasks.
	// Each collector runs on its own schedule with random jitter on startup
	// so they don't all hit the server simultaneously.
	agent.StartCollectors(agentID)

	// ── Task poll loop ─────────────────────────────────────────
	// Server-dispatched tasks (isolate host, kill process, FIM scan, etc.)
	// still run from this loop. Autonomous collection above covers the
	// recurring telemetry that was previously task-dispatched.
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
