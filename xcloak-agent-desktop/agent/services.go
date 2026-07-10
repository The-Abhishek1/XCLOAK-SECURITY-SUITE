//go:build !windows

package agent

import (
	"bufio"
	"encoding/json"
	"log/slog"
	"os/exec"
	"strings"

	"xcloak-agent-desktop/models"
)

func CollectServices(agentID int) {
	cmd := exec.Command("systemctl", "list-units", "--type=service", "--no-pager", "--no-legend")
	output, err := cmd.Output()
	if err != nil {
		slog.Error("service collection failed", "err", err)
		return
	}

	var services []models.Service
	sc := bufio.NewScanner(strings.NewReader(string(output)))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 4 {
			continue
		}
		services = append(services, models.Service{
			AgentID:      agentID,
			ServiceName:  fields[0],
			ServiceState: fields[2],
		})
	}

	body, _ := json.Marshal(services)
	resp, err := authPost("/api/agents/services", body)
	if err != nil {
		slog.Error("failed sending services", "err", err)
		return
	}
	defer resp.Body.Close()
	slog.Info("services sent", "count", len(services))
}
