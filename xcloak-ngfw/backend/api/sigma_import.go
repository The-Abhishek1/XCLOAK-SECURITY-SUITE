package api

import (
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"

	"xcloak-ngfw/models"
	"xcloak-ngfw/repositories"
	"xcloak-ngfw/services"
)

// sigmaYAML mirrors the standard Sigma rule YAML structure.
type sigmaYAML struct {
	Title       string                 `yaml:"title"`
	Description string                 `yaml:"description"`
	Status      string                 `yaml:"status"`
	Level       string                 `yaml:"level"`   // informational, low, medium, high, critical
	Tags        []string               `yaml:"tags"`    // attack.t1078 etc.
	Detection   map[string]interface{} `yaml:"detection"`
}

// ImportSigmaYAML — POST /api/sigma/import
// Accepts a multipart file upload of one or more Sigma YAML rule files.
func ImportSigmaYAML(c *gin.Context) {

	form, err := c.MultipartForm()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "expected multipart form"})
		return
	}

	files := form.File["rules"]
	if len(files) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no files uploaded (field name: rules)"})
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
		data, err := io.ReadAll(f)
		f.Close()
		if err != nil {
			errors = append(errors, fh.Filename+": read error")
			continue
		}

		rule, err := parseSigmaYAML(data)
		if err != nil {
			errors = append(errors, fh.Filename+": "+err.Error())
			skipped++
			continue
		}

		if err := repositories.CreateSigmaRule(*rule, tenantIDFromContext(c)); err != nil {
			// Likely duplicate title — skip gracefully.
			errors = append(errors, fh.Filename+": "+err.Error())
			skipped++
			continue
		}

		imported++
	}

	c.JSON(http.StatusOK, gin.H{
		"imported": imported,
		"skipped":  skipped,
		"errors":   errors,
		"message":  fmt.Sprintf("Imported %d / %d rules", imported, len(files)),
	})
}

// parseSigmaYAML converts a standard Sigma YAML document into our SigmaRule model.
func parseSigmaYAML(data []byte) (*models.SigmaRule, error) {

	var sy sigmaYAML
	if err := yaml.Unmarshal(data, &sy); err != nil {
		return nil, fmt.Errorf("YAML parse error: %w", err)
	}

	if sy.Title == "" {
		return nil, fmt.Errorf("rule has no title")
	}

	// Normalise level → our severity.
	severity := normaliseSeverity(sy.Level)

	// Extract MITRE tags.
	tactic, technique := extractMITRETags(sy.Tags)

	// Build selections from detection block.
	selections := make(map[string][]string)
	condition  := ""

	for key, val := range sy.Detection {
		if key == "condition" {
			switch v := val.(type) {
			case string:
				condition = v
			}
			continue
		}

		// Each non-condition key is a selection group.
		keywords := extractKeywords(val)
		if len(keywords) > 0 {
			selections[key] = keywords
		}
	}

	if condition == "" && len(selections) > 0 {
		// Default: any selection matches.
		keys := make([]string, 0, len(selections))
		for k := range selections {
			keys = append(keys, k)
		}
		condition = strings.Join(keys, " or ")
	}

	rule := &models.SigmaRule{
		Title:          sy.Title,
		Severity:       severity,
		MitreTactic:    tactic,
		MitreTechnique: technique,
		Selections:     selections,
		Condition:      condition,
		Enabled:        true,
	}

	// Ensure Sigma engine index is up to date.
	services.ReloadSigmaRules()

	return rule, nil
}

func normaliseSeverity(level string) string {
	switch strings.ToLower(level) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low", "informational":
		return "low"
	default:
		return "medium"
	}
}

func extractMITRETags(tags []string) (tactic, technique string) {
	for _, tag := range tags {
		tag = strings.ToLower(tag)
		if strings.HasPrefix(tag, "attack.t") {
			// e.g. "attack.t1078" → technique T1078
			parts := strings.Split(tag, ".")
			if len(parts) >= 2 {
				technique = strings.ToUpper(parts[1])
			}
		} else if strings.HasPrefix(tag, "attack.") {
			// e.g. "attack.initial_access" → tactic
			t := strings.TrimPrefix(tag, "attack.")
			t = strings.ReplaceAll(t, "_", " ")
			tactic = strings.Title(t)
		}
	}
	return
}

// extractKeywords flattens the Sigma detection value into a []string.
// Sigma detection values can be: string, []string, or map[string]interface{}.
func extractKeywords(val interface{}) []string {

	var keywords []string

	switch v := val.(type) {
	case string:
		keywords = append(keywords, v)

	case []interface{}:
		for _, item := range v {
			if s, ok := item.(string); ok {
				keywords = append(keywords, s)
			}
		}

	case map[string]interface{}:
		// e.g. {CommandLine: ['nmap', 'masscan']}
		for _, fieldVal := range v {
			keywords = append(keywords, extractKeywords(fieldVal)...)
		}
	}

	return keywords
}
