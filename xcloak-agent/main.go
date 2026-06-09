package main

import (
	"fmt"
	"time"

	"xcloak-agent/agent"
)

func main() {

	agentID, err := agent.Register()

	if err != nil {
		panic(err)
	}

	fmt.Println("Registered Agent:", agentID)

	go func() {

		for {

			agent.SendHeartbeat(agentID)

			time.Sleep(
				30 * time.Second,
			)
		}

	}()

	for {

		tasks, err := agent.FetchTasks(agentID)

		if err == nil {

			for _, task := range tasks {

				agent.ExecuteTask(task)
			}
		}

		time.Sleep(
			15 * time.Second,
		)
	}
}
