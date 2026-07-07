//go:build !windows

package agent

import (
	"bufio"
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

// CollectKernelModules enumerates loaded kernel modules via lsmod.
// Unexpected modules (e.g. rootkit drivers) are a key persistence indicator.
func CollectKernelModules(agentID int) {
	out, err := exec.Command("lsmod").Output()
	if err != nil {
		slog.Error("lsmod failed", "err", err)
		return
	}

	var modules []KernelModule
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	first := true
	for sc.Scan() {
		if first {
			first = false
			continue
		}
		fields := strings.Fields(sc.Text())
		if len(fields) < 3 {
			continue
		}
		usedBy := ""
		if len(fields) >= 4 {
			usedBy = strings.Join(fields[3:], " ")
		}
		modules = append(modules, KernelModule{
			AgentID: agentID,
			Name:    fields[0],
			Size:    fields[1],
			UsedBy:  usedBy,
		})
	}

	if len(modules) == 0 {
		slog.Debug("no kernel modules found")
		return
	}

	body, _ := json.Marshal(modules)
	resp, err := authPost("/api/agents/kernel_modules", body)
	if err != nil {
		slog.Error("failed sending kernel modules", "err", err)
		return
	}
	defer resp.Body.Close()
	slog.Info("kernel modules sent", "count", len(modules))
}
