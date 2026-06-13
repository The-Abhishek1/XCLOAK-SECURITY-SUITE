package main

import (
	"fmt"
	"time"

	"xcloak-agent/agent"
	"xcloak-agent/config"
)

func main() {

	// Register (or re-register) with the server.
	// On restart, the server returns the same agent_id + token via machine_id lookup.
	result, err := agent.Register()
	if err != nil {
		panic(fmt.Sprintf("Failed to register agent: %v", err))
	}

	fmt.Printf("Agent ID: %d\n", result.AgentID)

	// Authenticated HTTP client used by all subsequent calls.
	client := &agent.AuthClient{
		Token:     result.Token,
		ServerURL: config.ServerURL,
	}

	// Heartbeat loop
	go func() {
		for {
			agent.SendHeartbeat(client)
			time.Sleep(30 * time.Second)
		}
	}()

	// Task polling loop
	for {
		tasks, err := agent.FetchTasks(client, result.AgentID)

		if err == nil {
			for _, task := range tasks {
				agent.ExecuteTask(client, task)
			}
		}

		time.Sleep(15 * time.Second)
	}
}
