package main

import (
	"errors"
	"log/slog"
	"math/rand"
	"os"
	"time"

	"xcloak-agent-desktop/agent"
)

const (
	heartbeatInterval = 30 * time.Second
	pollInterval      = 15 * time.Second
	registerMaxRetry  = 10
	registerRetryWait = 5 * time.Second
)

// Version is set at build time via -ldflags "-X main.Version=1.2.3"
var Version = "dev"

func main() {
	agent.InitLogger()

	agent.CurrentVersion = Version

	rand.Seed(time.Now().UnixNano()) //nolint:staticcheck

	var agentID int

	if existingToken := agent.LoadToken(); existingToken != "" {
		id, err := agent.ResumeSession()
		if err == nil {
			agentID = id
			slog.Info("resumed session", "agent_id", agentID)
			goto startLoops
		}
		slog.Warn("saved token invalid — re-registering", "err", err)
		agent.ClearToken()
	}

	for attempt := 1; attempt <= registerMaxRetry; attempt++ {
		id, err := agent.Register()
		if err == nil {
			agentID = id
			break
		}
		if errors.Is(err, agent.ErrInvalidToken) {
			// Token missing or rejected — prompt user interactively (3 attempts)
			id, err = agent.RegisterInteractive(3)
			if err == nil {
				agentID = id
				break
			}
			slog.Error("registration failed", "err", err)
			os.Exit(1)
		}
		// Network / server error — retry with delay
		slog.Warn("registration attempt failed", "attempt", attempt, "max", registerMaxRetry, "err", err)
		if attempt == registerMaxRetry {
			slog.Error("all registration attempts failed — exiting")
			slog.Info("fix: check SERVER_URL and ensure the XCloak backend is reachable")
			os.Exit(1)
		}
		time.Sleep(registerRetryWait)
	}

startLoops:
	slog.Info("agent running", "agent_id", agentID, "version", Version)

	go func() {
		for {
			agent.SendHeartbeat(agentID)
			time.Sleep(heartbeatInterval)
		}
	}()

	agent.StartCollectors(agentID)
	agent.StartSelfUpdateChecker()
	agent.StartFirewallStatsCollector()

	consecutiveErrors := 0

	for {
		tasks, err := agent.FetchTasks(agentID)
		if err != nil {
			consecutiveErrors++
			backoff := time.Duration(consecutiveErrors) * 5 * time.Second
			if backoff > 2*time.Minute {
				backoff = 2 * time.Minute
			}
			slog.Warn("task poll error", "consecutive", consecutiveErrors, "err", err, "backoff", backoff)
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
