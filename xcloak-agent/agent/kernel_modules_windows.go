//go:build windows

package agent

import (
	"encoding/json"
	"log/slog"
	"os/exec"
	"strings"
)

type KernelModule struct {
	AgentID int    `json:"agent_id"`
	Name    string `json:"name"`
	Size    string `json:"size"`
	UsedBy  string `json:"used_by"`
}

// CollectKernelModules enumerates loaded Windows kernel drivers via driverquery.
func CollectKernelModules(agentID int) {
	out, err := exec.Command("driverquery", "/fo", "csv", "/v").Output()
	if err != nil {
		slog.Error("driverquery failed", "err", err)
		return
	}

	var modules []KernelModule
	lines := strings.Split(string(out), "\n")
	for i, line := range lines {
		if i == 0 {
			continue // header
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// CSV: Module Name,Display Name,Driver Type,Start Mode,...
		fields := strings.SplitN(line, ",", 5)
		if len(fields) < 2 {
			continue
		}
		name := strings.Trim(strings.TrimSpace(fields[0]), "\"")
		modules = append(modules, KernelModule{
			AgentID: agentID,
			Name:    name,
		})
	}

	if len(modules) == 0 {
		slog.Debug("no kernel drivers found")
		return
	}

	body, _ := json.Marshal(modules)
	resp, err := authPost("/api/agents/kernel_modules", body)
	if err != nil {
		slog.Error("failed sending kernel drivers", "err", err)
		return
	}
	defer resp.Body.Close()
	slog.Info("kernel drivers sent", "count", len(modules))
}
