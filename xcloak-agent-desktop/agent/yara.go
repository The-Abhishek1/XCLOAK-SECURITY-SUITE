package agent

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"xcloak-agent-desktop/config"
	"xcloak-agent-desktop/models"
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

// defaultScanTargets are the directories scanned when no explicit path is
// given (scheduled/automatic scans) — same convention CollectFileHashes
// already uses for "where malware tends to drop on Linux" (file_hashes.go).
var defaultScanTargets = ScanTargets

// ScanWithYara scans `target` against every enabled YARA rule fetched from
// the server. If target is empty (a scheduled scan, not a one-off task
// against a specific file), it recursively scans defaultScanTargets
// instead. If the server is unreachable or has no rules configured, it
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

	if target != "" {
		return runYara(agentID, ruleFiles, target, false)
	}

	// No path given — scheduled/automatic scan against the same
	// drop-location directories collect_file_hashes already covers.
	var allMatches []models.YaraMatch
	for _, dir := range defaultScanTargets {
		if _, err := os.Stat(dir); err != nil {
			continue
		}
		allMatches = append(allMatches, runYara(agentID, ruleFiles, dir, true)...)
	}
	return allMatches
}

// runYara invokes the yara CLI once across every rule file at once (the CLI
// accepts multiple RULES_FILE arguments) rather than once per rule file —
// fewer process spawns and matches the agent's own bundled-rule fallback
// path, which already only ever had one rule file anyway. recursive scans
// a directory (-r) instead of a single file.
func runYara(agentID int, ruleFiles []string, target string, recursive bool) []models.YaraMatch {

	args := []string{"-s", "-m", "-w", "-z", strconv.Itoa(MaxFileSize)}
	if recursive {
		args = append(args, "-r")
	}
	args = append(args, ruleFiles...)
	args = append(args, target)

	cmd := exec.Command("yara", args...)

	// Separate stdout/stderr — CombinedOutput would interleave yara's
	// warnings (e.g. deprecated syntax notices) into the match output,
	// corrupting the line-oriented parser below. -w already suppresses
	// most warnings, but errors (bad rule file, missing target) still need
	// to not contaminate stdout.
	stdout, err := cmd.Output()
	if err != nil {
		// yara exits 1 on "no match" — that's not a real error, but a
		// nonzero exit with empty stdout and something on stderr (rule
		// compile error, bad path) is worth a log line for diagnosis.
		if len(stdout) == 0 {
			if exitErr, ok := err.(*exec.ExitError); ok && len(exitErr.Stderr) > 0 {
				fmt.Printf("YARA: scan of %q produced no output, stderr: %s\n", target, strings.TrimSpace(string(exitErr.Stderr)))
			}
		}
	}

	return parseYaraOutput(agentID, string(stdout))
}

type yaraParsedMatch struct {
	ruleName string
	meta     map[string]string
	filePath string
	strings  []models.YaraMatchedString
}

// parseYaraOutput parses `yara -s -m` output into structured matches.
// Format (verified empirically against a real yara 4.5.0 binary):
//
//	RuleName [key="val",key2=val2,...] /path/to/file
//	0xOFFSET:$identifier: matched data
//	0xOFFSET:$identifier: matched data
//	NextRule [] /path/to/file
//	...
//
// A line is a new match header unless it starts with "0x" (a matched
// string belonging to the most recent header). The meta bracket can
// contain commas inside quoted string values, so it can't be split
// naively — parseMetaBlock below scans char-by-char tracking quote state.
func parseYaraOutput(agentID int, output string) []models.YaraMatch {

	var matches []models.YaraMatch
	var current *yaraParsedMatch

	flush := func() {
		if current == nil {
			return
		}
		matches = append(matches, buildYaraMatch(agentID, *current))
	}

	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}

		if strings.HasPrefix(line, "0x") {
			if current == nil {
				continue // a string line with no header seen yet — malformed/unexpected, skip
			}
			if ms, ok := parseMatchedStringLine(line); ok {
				current.strings = append(current.strings, ms)
			}
			continue
		}

		// New header line — flush whatever match we were building.
		flush()
		parsed, ok := parseHeaderLine(line)
		if !ok {
			current = nil
			continue
		}
		current = &parsed
	}
	flush()

	return matches
}

// parseHeaderLine parses "RuleName [meta] filepath" into its three parts.
func parseHeaderLine(line string) (yaraParsedMatch, bool) {
	spaceIdx := strings.Index(line, " ")
	if spaceIdx < 0 {
		return yaraParsedMatch{}, false
	}
	ruleName := line[:spaceIdx]
	rest := strings.TrimSpace(line[spaceIdx+1:])

	if !strings.HasPrefix(rest, "[") {
		return yaraParsedMatch{}, false
	}

	closeIdx := findMetaBlockEnd(rest)
	if closeIdx < 0 {
		return yaraParsedMatch{}, false
	}

	metaContent := rest[1:closeIdx]
	filePath := strings.TrimSpace(rest[closeIdx+1:])

	return yaraParsedMatch{
		ruleName: ruleName,
		meta:     parseMetaBlock(metaContent),
		filePath: filePath,
	}, true
}

// findMetaBlockEnd finds the index of the "]" that closes the leading "["
// in s, ignoring any "]" that appears inside a quoted meta string value.
func findMetaBlockEnd(s string) int {
	inQuotes := false
	for i := 1; i < len(s); i++ {
		switch s[i] {
		case '"':
			inQuotes = !inQuotes
		case ']':
			if !inQuotes {
				return i
			}
		}
	}
	return -1
}

// parseMetaBlock splits "key=\"val\",key2=val2,key3 =5" into a map, only
// splitting on commas outside quoted values (a string meta value could
// itself contain a comma). Non-string values (bools/ints) keep whatever
// literal text yara printed — only "severity"/"description" are read by
// callers and both are always declared as YARA string meta in practice.
func parseMetaBlock(s string) map[string]string {
	out := map[string]string{}
	if strings.TrimSpace(s) == "" {
		return out
	}

	var fields []string
	var buf strings.Builder
	inQuotes := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '"' {
			inQuotes = !inQuotes
		}
		if c == ',' && !inQuotes {
			fields = append(fields, buf.String())
			buf.Reset()
			continue
		}
		buf.WriteByte(c)
	}
	fields = append(fields, buf.String())

	for _, field := range fields {
		eqIdx := strings.Index(field, "=")
		if eqIdx < 0 {
			continue
		}
		key := strings.TrimSpace(field[:eqIdx])
		val := strings.TrimSpace(field[eqIdx+1:])
		val = strings.Trim(val, `"`)
		if key != "" {
			out[key] = val
		}
	}
	return out
}

// parseMatchedStringLine parses "0xOFFSET:$identifier: data" — data may
// itself contain colons, so only the first two are treated as delimiters.
func parseMatchedStringLine(line string) (models.YaraMatchedString, bool) {
	firstColon := strings.Index(line, ":")
	if firstColon < 0 {
		return models.YaraMatchedString{}, false
	}
	offset := line[:firstColon]
	rest := line[firstColon+1:]

	secondColon := strings.Index(rest, ":")
	if secondColon < 0 {
		return models.YaraMatchedString{}, false
	}
	identifier := rest[:secondColon]
	data := strings.TrimSpace(rest[secondColon+1:])

	return models.YaraMatchedString{
		Offset:     offset,
		Identifier: identifier,
		Data:       data,
	}, true
}

func buildYaraMatch(agentID int, p yaraParsedMatch) models.YaraMatch {

	severity := p.meta["severity"]
	if severity == "" {
		severity = "high" // preserves pre-meta-parsing behavior for rules without one
	}

	description := p.meta["description"]
	if description == "" {
		description = "YARA rule matched: " + p.ruleName
	}

	matchedStringsJSON := "[]"
	if len(p.strings) > 0 {
		if b, err := json.Marshal(p.strings); err == nil {
			matchedStringsJSON = string(b)
		}
	}

	fileHash := ""
	if result, err := hashFile(p.filePath); err == nil {
		fileHash = result.SHA256Hash
	}

	return models.YaraMatch{
		AgentID:        agentID,
		RuleName:       p.ruleName,
		FilePath:       p.filePath,
		Severity:       severity,
		Description:    description,
		MatchedStrings: matchedStringsJSON,
		FileHash:       fileHash,
	}
}
