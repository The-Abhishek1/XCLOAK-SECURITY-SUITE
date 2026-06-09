package agent

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"xcloak-agent/models"
)

func ScanWithYara(
	agentID int,
	target string,
) []models.YaraMatch {

	var matches []models.YaraMatch

	cwd, _ := os.Getwd()
	fmt.Println("Current Dir:", cwd)

	cmd := exec.Command(
		"yara",
		"agent/yara/suspicious_shell.yar",
		target,
	)

	output, err := cmd.CombinedOutput()

	fmt.Println("YARA OUTPUT:")
	fmt.Println(string(output))

	if err != nil {

		// IMPORTANT:
		// yara returns exit code 1 when no match
		// but output may still exist

		fmt.Println("YARA ERROR:", err)
	}

	lines := strings.Split(
		strings.TrimSpace(string(output)),
		"\n",
	)

	for _, line := range lines {

		line = strings.TrimSpace(line)

		if line == "" {
			continue
		}

		parts := strings.Fields(line)

		if len(parts) < 2 {
			continue
		}

		matches = append(
			matches,
			models.YaraMatch{
				AgentID:     agentID,
				RuleName:    parts[0],
				FilePath:    parts[1],
				Severity:    "high",
				Description: "YARA Match",
			},
		)
	}

	return matches
}
