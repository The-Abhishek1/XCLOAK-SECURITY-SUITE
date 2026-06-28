package services

import (
	"bufio"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"xcloak-ngfw/models"
	"xcloak-ngfw/repositories"
)

// syncURLhausFeed pulls recent malicious URLs from abuse.ch URLhaus.
func syncURLhausFeed(feed models.ThreatFeed) (int, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get("https://urlhaus.abuse.ch/downloads/csv_recent/")
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return 0, &feedHTTPError{status: resp.StatusCode}
	}

	imported := 0
	scanner := bufio.NewScanner(resp.Body)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 4*1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		parts := csvSplitLine(line)
		if len(parts) < 3 {
			continue
		}
		url := strings.Trim(parts[2], `"`)
		if url == "" || !strings.HasPrefix(url, "http") {
			continue
		}
		if importIndicator(url, "url", "high", feed.Name, feed.TenantID) {
			imported++
		}
	}
	repositories.UpdateThreatFeedLastSync(feed.ID, time.Now())
	return imported, nil
}

// syncFeodoFeed pulls C2 botnet IPs from abuse.ch Feodo Tracker.
func syncFeodoFeed(feed models.ThreatFeed) (int, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get("https://feodotracker.abuse.ch/downloads/ipblocklist.txt")
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return 0, &feedHTTPError{status: resp.StatusCode}
	}

	imported := 0
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		if importIndicator(line, "ip", "critical", feed.Name, feed.TenantID) {
			imported++
		}
	}
	repositories.UpdateThreatFeedLastSync(feed.ID, time.Now())
	return imported, nil
}

// syncMalwareBazaarFeed pulls recent malware sample hashes from MalwareBazaar.
func syncMalwareBazaarFeed(feed models.ThreatFeed) (int, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.PostForm("https://mb-api.abuse.ch/api/v1/",
		map[string][]string{"query": {"get_recent"}, "selector": {"100"}})
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	var result struct {
		Data []struct {
			SHA256 string `json:"sha256_hash"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return 0, err
	}

	imported := 0
	for _, sample := range result.Data {
		if sample.SHA256 != "" && importIndicator(sample.SHA256, "sha256", "high", feed.Name, feed.TenantID) {
			imported++
		}
	}
	repositories.UpdateThreatFeedLastSync(feed.ID, time.Now())
	return imported, nil
}

// csvSplitLine splits a CSV line respecting double-quoted fields.
func csvSplitLine(line string) []string {
	var result []string
	var cur strings.Builder
	inQuote := false
	for _, ch := range line {
		if ch == '"' {
			inQuote = !inQuote
		} else if ch == ',' && !inQuote {
			result = append(result, cur.String())
			cur.Reset()
		} else {
			cur.WriteRune(ch)
		}
	}
	result = append(result, cur.String())
	return result
}
