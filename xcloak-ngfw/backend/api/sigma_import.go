package api

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"

	"xcloak-ngfw/models"
	"xcloak-ngfw/services"
)

// ─────────────────────────────────────────────────────────────────────────────
// YAML document structure
// ─────────────────────────────────────────────────────────────────────────────

type sigmaYAML struct {
	Title          string                 `yaml:"title"`
	Description    string                 `yaml:"description"`
	Status         string                 `yaml:"status"`
	Level          string                 `yaml:"level"`
	Tags           []string               `yaml:"tags"`
	FalsePositives []string               `yaml:"falsepositives"`
	References     []string               `yaml:"references"`
	Logsource      sigmaLogsource         `yaml:"logsource"`
	Detection      map[string]interface{} `yaml:"detection"`
}

type sigmaLogsource struct {
	Category string `yaml:"category"`
	Product  string `yaml:"product"`
	Service  string `yaml:"service"`
}

// ─────────────────────────────────────────────────────────────────────────────
// ImportSigmaYAML — POST /api/sigma/import
// Accepts multipart files; each file may contain multiple documents (--- sep).
// ─────────────────────────────────────────────────────────────────────────────

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
	skipped := 0
	var errs []string

	tid := tenantIDFromContext(c)

	for _, fh := range files {
		f, err := fh.Open()
		if err != nil {
			errs = append(errs, fh.Filename+": open error")
			continue
		}
		data, err := io.ReadAll(f)
		f.Close()
		if err != nil {
			errs = append(errs, fh.Filename+": read error")
			continue
		}

		// Split on YAML document separator so one file can carry many rules.
		docs := splitYAMLDocs(data)

		for i, doc := range docs {
			if len(bytes.TrimSpace(doc)) == 0 {
				continue
			}
			rule, err := parseSigmaYAML(doc)
			if err != nil {
				errs = append(errs, fmt.Sprintf("%s[%d]: %v", fh.Filename, i, err))
				skipped++
				continue
			}
			if err := services.CreateSigmaRule(*rule, tid); err != nil {
				errs = append(errs, fmt.Sprintf("%s[%d]: %v", fh.Filename, i, err))
				skipped++
				continue
			}
			imported++
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"imported": imported,
		"skipped":  skipped,
		"errors":   errs,
		"message":  fmt.Sprintf("Imported %d rule(s)", imported),
	})
}

// splitYAMLDocs splits a byte slice on YAML document-start markers ("---").
func splitYAMLDocs(data []byte) [][]byte {
	sep := []byte("\n---")
	parts := bytes.Split(data, sep)
	var docs [][]byte
	for _, p := range parts {
		p = bytes.TrimPrefix(p, []byte("---"))
		docs = append(docs, p)
	}
	return docs
}

// ─────────────────────────────────────────────────────────────────────────────
// parseSigmaYAML converts a single Sigma YAML document to our SigmaRule model.
// ─────────────────────────────────────────────────────────────────────────────

func parseSigmaYAML(data []byte) (*models.SigmaRule, error) {
	var sy sigmaYAML
	if err := yaml.Unmarshal(data, &sy); err != nil {
		return nil, fmt.Errorf("YAML parse error: %w", err)
	}
	if sy.Title == "" {
		return nil, fmt.Errorf("rule has no title")
	}

	severity := normaliseSeverity(sy.Level)
	tactic, technique := extractMITRETags(sy.Tags)

	selections, condition := buildSelections(sy.Detection)

	rule := &models.SigmaRule{
		Title:             sy.Title,
		Description:       sy.Description,
		Status:            sy.Status,
		Severity:          severity,
		MitreTactic:       tactic,
		MitreTechnique:    technique,
		Tags:              sy.Tags,
		FalsePositives:    sy.FalsePositives,
		References:        sy.References,
		LogsourceCategory: sy.Logsource.Category,
		LogsourceProduct:  sy.Logsource.Product,
		LogsourceService:  sy.Logsource.Service,
		Selections:        selections,
		Condition:         condition,
		Enabled:           true,
	}

	if rule.Status == "" {
		rule.Status = "experimental"
	}

	return rule, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Detection block processing
// ─────────────────────────────────────────────────────────────────────────────

// buildSelections converts the Sigma detection map into our selections + condition.
// Key insight: each non-condition key becomes a selection group; map-type values
// carry field names and modifiers in the YAML key (e.g. "CommandLine|contains|all").
// The |all modifier produces AND semantics (all values must match); we implement
// this by splitting them into synthetic sub-selections with __ALL__-prefixed keywords.
func buildSelections(detection map[string]interface{}) (map[string][]string, string) {
	selections := make(map[string][]string)
	var rawCondition string
	// Extra AND terms for each selection name (from |all splits).
	extraAnd := make(map[string][]string)

	for key, val := range detection {
		if key == "condition" {
			if s, ok := val.(string); ok {
				rawCondition = s
			}
			continue
		}

		switch v := val.(type) {
		case map[string]interface{}:
			main, extra := processFieldMap(key, v)
			if len(main) > 0 {
				selections[key] = main
			}
			for subName, subKws := range extra {
				selections[subName] = subKws
				extraAnd[key] = append(extraAnd[key], subName)
			}
		default:
			// Keyword list (string or []interface{})
			kws := flattenToStrings(val)
			if len(kws) > 0 {
				selections[key] = kws
			}
		}
	}

	// Build or rewrite condition.
	condition := rawCondition
	if condition == "" {
		keys := selectionNames(selections)
		// Remove the synthetic sub-selections from the top-level condition;
		// they are already ANDed in below.
		var topLevel []string
		for _, k := range keys {
			if !isSubSelection(k, extraAnd) {
				topLevel = append(topLevel, k)
			}
		}
		condition = strings.Join(topLevel, " or ")
	}

	// Inject extra AND terms into the condition by replacing selection name
	// references with "(name and sub1 and sub2)".
	for selName, subs := range extraAnd {
		repl := selName
		for _, s := range subs {
			repl += " and " + s
		}
		// Only wrap if there are actual sub-selections to join.
		if repl != selName {
			condition = replaceWordInCondition(condition, selName, "("+repl+")")
		}
	}

	// If still empty (detection had no selections at all) make it unconditional-false.
	if condition == "" || len(selections) == 0 {
		condition = ""
	}

	return selections, condition
}

// processFieldMap converts a map-type Sigma detection value.
// Each key in the map is "FieldName|mod1|mod2" and the value is a string or list.
// Returns:
//   - mainKeywords: OR-logic keywords (plain or with __ALL__ for all-or-nothing single fields)
//   - extraSelections: synthetic sub-selections for multi-value |all fields
func processFieldMap(selName string, m map[string]interface{}) (mainKeywords []string, extraSelections map[string][]string) {
	extraSelections = make(map[string][]string)

	for fieldKey, fieldVal := range m {
		parts := strings.Split(fieldKey, "|")
		fieldName := parts[0]
		modifiers := parts[1:]

		hasAll := false
		var otherMods []string
		for _, mod := range modifiers {
			if strings.EqualFold(mod, "all") {
				hasAll = true
			} else {
				otherMods = append(otherMods, mod)
			}
		}

		// Rebuild the field expression without the |all modifier.
		fieldExpr := fieldName
		if len(otherMods) > 0 {
			fieldExpr = fieldName + "|" + strings.Join(otherMods, "|")
		}

		values := flattenToStrings(fieldVal)
		if len(values) == 0 {
			continue
		}

		if hasAll && len(values) > 1 {
			// Multiple values with |all → separate sub-selection, all must match.
			subName := selName + "_all_" + sanitizeFieldName(fieldName)
			var subKws []string
			for _, v := range values {
				subKws = append(subKws, "__ALL__"+fieldExpr+":"+v)
			}
			extraSelections[subName] = subKws
		} else {
			// Single value or no |all: OR logic in main selection.
			for _, v := range values {
				mainKeywords = append(mainKeywords, fieldExpr+":"+v)
			}
		}
	}
	return
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

func flattenToStrings(val interface{}) []string {
	switch v := val.(type) {
	case string:
		return []string{v}
	case int:
		return []string{fmt.Sprintf("%d", v)}
	case float64:
		return []string{fmt.Sprintf("%g", v)}
	case []interface{}:
		var out []string
		for _, item := range v {
			out = append(out, flattenToStrings(item)...)
		}
		return out
	case nil:
		return nil
	}
	return nil
}

func sanitizeFieldName(s string) string {
	s = strings.ToLower(s)
	s = strings.NewReplacer(".", "_", " ", "_", "-", "_").Replace(s)
	return s
}

func selectionNames(m map[string][]string) []string {
	names := make([]string, 0, len(m))
	for k := range m {
		names = append(names, k)
	}
	return names
}

// isSubSelection returns true if name appears in any of the extraAnd sub-lists.
func isSubSelection(name string, extraAnd map[string][]string) bool {
	for _, subs := range extraAnd {
		for _, s := range subs {
			if s == name {
				return true
			}
		}
	}
	return false
}

// replaceWordInCondition replaces whole-word occurrences of old with new in the
// condition string, without touching partial matches.
func replaceWordInCondition(condition, old, replacement string) string {
	var out strings.Builder
	remaining := condition
	for {
		idx := strings.Index(remaining, old)
		if idx < 0 {
			out.WriteString(remaining)
			break
		}
		// Check word boundaries.
		before := idx > 0 && isWordChar(remaining[idx-1])
		after := idx+len(old) < len(remaining) && isWordChar(remaining[idx+len(old)])
		if before || after {
			out.WriteString(remaining[:idx+1])
			remaining = remaining[idx+1:]
			continue
		}
		out.WriteString(remaining[:idx])
		out.WriteString(replacement)
		remaining = remaining[idx+len(old):]
	}
	return out.String()
}

func isWordChar(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') ||
		(b >= '0' && b <= '9') || b == '_'
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
			parts := strings.Split(tag, ".")
			if len(parts) >= 2 {
				technique = strings.ToUpper(parts[1])
			}
		} else if strings.HasPrefix(tag, "attack.") {
			t := strings.TrimPrefix(tag, "attack.")
			t = strings.ReplaceAll(t, "_", " ")
			tactic = strings.Title(t) //nolint:staticcheck
		}
	}
	return
}
