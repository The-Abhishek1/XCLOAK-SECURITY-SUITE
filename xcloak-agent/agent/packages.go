package agent

import (
	"bufio"
	"encoding/json"
	"os/exec"
	"strings"

	"xcloak-agent/models"
)

func CollectPackages(agentID int) {

	cmd := exec.Command(
		"dpkg-query",
		"-W",
		"-f=${Package}\t${Version}\n",
	)

	output, err := cmd.Output()

	if err != nil {
		println("Package collection failed")
		return
	}

	var packages []models.Package

	scanner := bufio.NewScanner(
		strings.NewReader(
			string(output),
		),
	)

	for scanner.Scan() {

		line := scanner.Text()

		fields := strings.Split(
			line,
			"\t",
		)

		if len(fields) < 2 {
			continue
		}

		pkg := models.Package{
			AgentID:     agentID,
			PackageName: fields[0],
			Version:     fields[1],
		}

		packages = append(
			packages,
			pkg,
		)
	}

	body, _ := json.Marshal(
		packages,
	)

	resp, err := authPost("/api/agents/packages", body)

	if err != nil {
		println("Failed sending packages")
		return
	}

	defer resp.Body.Close()

	println(
		"Packages sent:",
		len(packages),
	)
}
