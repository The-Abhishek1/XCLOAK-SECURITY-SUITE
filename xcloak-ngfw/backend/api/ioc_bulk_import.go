package api

import (
	"fmt"
	"net"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"

	"xcloak-ngfw/models"
	"xcloak-ngfw/services"
)

// BulkImportIOCs — POST /api/iocs/bulk
// Body: {
//   "indicators": "1.2.3.4\nevil.com\nabc123...",
//   "severity": "high",
//   "description": "Threat campaign X",
//   "source": "manual"
// }
func BulkImportIOCs(c *gin.Context) {
	var body struct {
		Indicators  string `json:"indicators"`  // newline or comma separated
		Severity    string `json:"severity"`
		Description string `json:"description"`
		Source      string `json:"source"`
	}

	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	if body.Severity == "" {
		body.Severity = "medium"
	}

	// Split on newline, comma, or semicolon
	raw := regexp.MustCompile(`[\n,;]+`).Split(body.Indicators, -1)

	imported := 0
	skipped  := 0
	dupes    := 0
	errList  := []string{}

	for _, line := range raw {
		indicator := strings.TrimSpace(line)
		// Strip common defang patterns: hxxp, [.], (.)
		indicator = strings.ReplaceAll(indicator, "hxxp", "http")
		indicator = strings.ReplaceAll(indicator, "[.]", ".")
		indicator = strings.ReplaceAll(indicator, "(.)", ".")
		indicator = strings.TrimSpace(indicator)

		if indicator == "" || len(indicator) < 3 {
			skipped++
			continue
		}

		iocType := classifyIndicator(indicator)
		if iocType == "" {
			errList = append(errList, fmt.Sprintf("unrecognized: %s", truncate17(indicator)))
			skipped++
			continue
		}

		desc := body.Description
		if desc == "" {
			desc = "Bulk import"
		}
		if body.Source != "" {
			desc = fmt.Sprintf("[%s] %s", body.Source, desc)
		}

		err := services.CreateIOC(models.IOC{
			Indicator:   indicator,
			Type:        iocType,
			Severity:    body.Severity,
			Description: desc,
			Enabled:     true,
		})

		if err != nil {
			if strings.Contains(err.Error(), "duplicate") || strings.Contains(err.Error(), "unique") {
				dupes++
			} else {
				errList = append(errList, indicator+": "+err.Error())
				skipped++
			}
			continue
		}
		imported++
	}

	username, _ := c.Get("username")
	services.LogEvent(
		"BULK_IMPORT_IOC",
		fmt.Sprintf("%d imported, %d dupes, %d skipped by %v", imported, dupes, skipped, username),
		fmt.Sprintf("%v", username),
	)

	c.JSON(200, gin.H{
		"imported": imported,
		"dupes":    dupes,
		"skipped":  skipped,
		"errors":   errList,
		"message":  fmt.Sprintf("Imported %d IOCs (%d already existed)", imported, dupes),
	})
}

// classifyIndicator auto-detects IOC type from its format.
func classifyIndicator(s string) string {
	// SHA256: 64 hex chars
	if matched, _ := regexp.MatchString(`^[0-9a-fA-F]{64}$`, s); matched {
		return "sha256"
	}
	// MD5: 32 hex chars
	if matched, _ := regexp.MatchString(`^[0-9a-fA-F]{32}$`, s); matched {
		return "md5"
	}
	// SHA1: 40 hex chars
	if matched, _ := regexp.MatchString(`^[0-9a-fA-F]{40}$`, s); matched {
		return "sha1"
	}
	// IPv4
	if ip := net.ParseIP(s); ip != nil {
		if ip.To4() != nil {
			return "ip"
		}
		return "ipv6"
	}
	// CIDR
	if _, _, err := net.ParseCIDR(s); err == nil {
		return "cidr"
	}
	// URL: has scheme
	if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") || strings.HasPrefix(s, "ftp://") {
		return "url"
	}
	// Email
	if matched, _ := regexp.MatchString(`^[^@]+@[^@]+\.[^@]+$`, s); matched {
		return "email"
	}
	// Domain: has at least one dot, no spaces, not a path
	if !strings.Contains(s, " ") && !strings.Contains(s, "/") {
		if matched, _ := regexp.MatchString(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$`, s); matched {
			return "domain"
		}
	}
	return ""
}

func truncate17(s string) string {
	if len(s) > 40 {
		return s[:40] + "…"
	}
	return s
}
