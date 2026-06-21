package agent

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"xcloak-agent/config"
	"xcloak-agent/models"
)

// remoteYaraRule mirrors the backend's YaraRule JSON shape — only the
// fields the agent needs to write a .yar file.
type remoteYaraRule struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	RuleContent string `json:"rule_content"`
	Enabled     bool   `json:"enabled"`
}

// fetchYaraRules pulls all enabled YARA rules from the server. On any error
// (offline, route missing, etc.) it falls back to the bundled local rule
// file (agent/yara/suspicious_shell.yar) so scanning still works.
func fetchYaraRules() []remoteYaraRule {

	req, err := http.NewRequest(
		"GET",
		config.ServerURL()+"/api/yara/rules/enabled",
		nil,
	)
	if err != nil {
		return nil
	}

	req.Header.Set("Authorization", "Bearer "+LoadToken())

	resp, err := Client().Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	var rules []remoteYaraRule
	if err := json.Unmarshal(body, &rules); err != nil {
		return nil
	}

	return rules
}

// writeTempRuleFiles writes each remote rule to its own .yar file under a
// temp directory and returns the directory path plus the list of written
// file paths. Caller is responsible for cleanup (os.RemoveAll).
func writeTempRuleFiles(rules []remoteYaraRule) (string, []string) {

	dir, err := os.MkdirTemp("", "xcloak-yara-")
	if err != nil {
		return "", nil
	}

	var paths []string

	for i, rule := range rules {

		if strings.TrimSpace(rule.RuleContent) == "" {
			continue
		}

		// Sanitize name for filesystem safety.
		safeName := strings.Map(func(r rune) rune {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
				return r
			}
			return '_'
		}, rule.Name)

		if safeName == "" {
			safeName = fmt.Sprintf("rule_%d", i)
		}

		path := filepath.Join(dir, fmt.Sprintf("%d_%s.yar", rule.ID, safeName))

		if err := os.WriteFile(path, []byte(rule.RuleContent), 0644); err != nil {
			continue
		}

		paths = append(paths, path)
	}

	return dir, paths
}

// ScanWithYara scans `target` against every enabled YARA rule fetched from
// the server. If the server is unreachable or has no rules configured, it
// falls back to the bundled rule at agent/yara/suspicious_shell.yar so the
// agent remains useful offline / before any rules are added via the UI.
func ScanWithYara(agentID int, target string) []models.YaraMatch {

	remoteRules := fetchYaraRules()

	var ruleFiles []string
	var cleanupDir string

	if len(remoteRules) > 0 {
		dir, paths := writeTempRuleFiles(remoteRules)
		cleanupDir = dir
		ruleFiles = paths
		if cleanupDir != "" {
			defer os.RemoveAll(cleanupDir)
		}
	}

	if len(ruleFiles) == 0 {
		// Fallback: bundled local rule.
		if _, err := os.Stat("agent/yara/suspicious_shell.yar"); err == nil {
			ruleFiles = append(ruleFiles, "agent/yara/suspicious_shell.yar")
		}
	}

	if len(ruleFiles) == 0 {
		fmt.Println("YARA: no rules available (server unreachable and no local fallback)")
		return nil
	}

	var allMatches []models.YaraMatch

	for _, rulePath := range ruleFiles {
		allMatches = append(allMatches, runYaraRule(agentID, rulePath, target)...)
	}

	return allMatches
}

// runYaraRule invokes the `yara` CLI for a single compiled rule file against
// the target path and parses its output into YaraMatch records.
func runYaraRule(agentID int, rulePath, target string) []models.YaraMatch {

	var matches []models.YaraMatch

	cmd := exec.Command("yara", rulePath, target)

	output, err := cmd.CombinedOutput()

	if err != nil {
		// yara exits 1 on "no match" — output may still be empty, that's fine.
		_ = err
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")

	for _, line := range lines {

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		matches = append(matches, models.YaraMatch{
			AgentID:     agentID,
			RuleName:    parts[0],
			FilePath:    parts[1],
			Severity:    "high",
			Description: "YARA Match",
		})
	}

	return matches
}
