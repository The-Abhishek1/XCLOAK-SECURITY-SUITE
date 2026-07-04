package api

import (
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"

	"xcloak-ngfw/models"
	"xcloak-ngfw/repositories"
	"xcloak-ngfw/services"
)

const (
	maxYARAFileBytes = 1 << 20 // 1 MiB — a YARA file this large is almost certainly malicious
	maxYARAFiles     = 20      // prevent tarpit-style uploads with thousands of tiny files
)

// ImportYARAFiles — POST /api/yara/import
// Accepts multipart upload of one or more .yar / .yara files.
// Each file may contain multiple YARA rules.
func ImportYARAFiles(c *gin.Context) {
	form, err := c.MultipartForm()
	if err != nil {
		c.JSON(400, gin.H{"error": "expected multipart form"})
		return
	}

	files := form.File["rules"]
	if len(files) == 0 {
		c.JSON(400, gin.H{"error": "no files uploaded (field name: rules)"})
		return
	}
	if len(files) > maxYARAFiles {
		c.JSON(400, gin.H{"error": fmt.Sprintf("too many files — maximum %d per request", maxYARAFiles)})
		return
	}

	imported := 0
	skipped  := 0
	errors   := []string{}

	for _, fh := range files {
		f, err := fh.Open()
		if err != nil {
			errors = append(errors, fh.Filename+": open error")
			continue
		}
		// Read at most maxYARAFileBytes+1 bytes. If we get more than the limit
		// the read was truncated and we reject the file — do not store partial rules.
		lr := io.LimitReader(f, maxYARAFileBytes+1)
		data, err := io.ReadAll(lr)
		f.Close()
		if err != nil {
			errors = append(errors, fh.Filename+": read error")
			continue
		}
		if len(data) > maxYARAFileBytes {
			errors = append(errors, fmt.Sprintf("%s: file exceeds %d-byte limit", fh.Filename, maxYARAFileBytes))
			skipped++
			continue
		}

		// Split multi-rule files — each rule starts with `rule `
		rules := splitYARARules(string(data))
		if len(rules) == 0 {
			errors = append(errors, fh.Filename+": no valid YARA rules found")
			skipped++
			continue
		}

		for _, ruleContent := range rules {
			name := extractYARARuleName(ruleContent)
			if name == "" {
				name = strings.TrimSuffix(fh.Filename, ".yar")
				name = strings.TrimSuffix(name, ".yara")
			}

			desc := extractYARAMeta(ruleContent, "description")
			if desc == "" {
				desc = "Imported from " + fh.Filename
			}

			rule := models.YaraRule{
				Name:        name,
				Description: desc,
				RuleContent: ruleContent,
				Enabled:     true,
			}

			if err := repositories.CreateYaraRule(rule, tenantIDFromContext(c)); err != nil {
				errors = append(errors, name+": "+err.Error())
				skipped++
				continue
			}

			username, _ := c.Get("username")
			user := "admin"
			if username != nil {
				user = username.(string)
			}
			services.LogEvent("IMPORT_YARA_RULE", name+" (from "+fh.Filename+")", user)
			imported++
		}
	}

	c.JSON(200, gin.H{
		"imported": imported,
		"skipped":  skipped,
		"errors":   errors,
		"message":  fmt.Sprintf("Imported %d rule(s) from %d file(s)", imported, len(files)),
	})
}

// splitYARARules splits a YARA file containing multiple rules into individual rule strings.
func splitYARARules(content string) []string {
	// YARA rules start with `rule <name>` optionally followed by `: tag1 tag2`
	re := regexp.MustCompile(`(?m)^(private\s+|global\s+)?(rule\s+\w+[^\n]*)`)
	indices := re.FindAllStringIndex(content, -1)

	if len(indices) == 0 {
		return nil
	}

	var rules []string
	for i, idx := range indices {
		start := idx[0]
		var end int
		if i+1 < len(indices) {
			end = indices[i+1][0]
		} else {
			end = len(content)
		}
		rule := strings.TrimSpace(content[start:end])
		if rule != "" {
			rules = append(rules, rule)
		}
	}
	return rules
}

// extractYARARuleName pulls the rule name from `rule <name> {`
func extractYARARuleName(content string) string {
	re := regexp.MustCompile(`(?m)^(?:private\s+|global\s+)?rule\s+(\w+)`)
	m := re.FindStringSubmatch(content)
	if len(m) >= 2 {
		return m[1]
	}
	return ""
}

// extractYARAMeta pulls a value from the meta section.
func extractYARAMeta(content, key string) string {
	re := regexp.MustCompile(`(?m)` + key + `\s*=\s*"([^"]*)"`)
	m := re.FindStringSubmatch(content)
	if len(m) >= 2 {
		return m[1]
	}
	return ""
}
