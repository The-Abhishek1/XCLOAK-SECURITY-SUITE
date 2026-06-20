package services

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"xcloak-ngfw/models"
	"xcloak-ngfw/repositories"
)

// taxiiObjectsResponse is a STIX 2.1 bundle as returned by a TAXII 2.1
// collection's objects endpoint. We only care about "indicator" objects.
type taxiiObjectsResponse struct {
	Objects []struct {
		Type    string `json:"type"`
		Pattern string `json:"pattern"`
	} `json:"objects"`
	More bool   `json:"more"`
	Next string `json:"next"`
}

// stixComparisonPattern matches the common single-comparison STIX pattern
// shape: [object-type:property = 'value']. STIX's full pattern grammar
// supports boolean combinators (AND/OR) and comparison operators (!=, IN,
// LIKE, MATCHES...) — this client only extracts the first simple equality
// comparison, which covers the vast majority of indicator feeds in
// practice. Patterns that don't match this shape are skipped, not guessed at.
var stixComparisonPattern = regexp.MustCompile(`\[([a-z0-9\-]+):([a-zA-Z0-9_.'\-]+)\s*=\s*'([^']+)'\]`)

// syncTAXIIFeed pulls STIX indicator objects from a TAXII 2.1 collection's
// objects endpoint and imports each pattern's indicator as an IOC.
//
// feed.Source must be the full collection objects URL (e.g.
// "https://taxii.example.org/api1/collections/<id>/objects/") — this client
// does not perform TAXII discovery, you point it directly at the collection
// you want. Auth is optional: feed.Config.api_key sends an Authorization:
// Bearer header, or feed.Config.username/password sends HTTP Basic Auth.
func syncTAXIIFeed(feed models.ThreatFeed) (int, error) {

	if feed.Source == "" {
		return 0, fmt.Errorf("taxii feed requires source to be set to the collection's objects URL")
	}

	var cfg models.ThreatFeedConfig
	json.Unmarshal(feed.Config, &cfg) // best-effort; auth is optional for some TAXII servers

	const taxiiMaxPages = 50
	url := feed.Source
	client := &http.Client{Timeout: 60 * time.Second}
	imported := 0

	// Record progress even if a later page errors out — see syncOTXFeed for
	// the same rationale.
	defer repositories.UpdateThreatFeedLastSync(feed.ID, time.Now())

	for page := 0; page < taxiiMaxPages && url != ""; page++ {

		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return imported, err
		}
		req.Header.Set("Accept", "application/taxii+json;version=2.1")
		req.Header.Set("User-Agent", "XCloak-Security-Suite/1.0")
		if cfg.APIKey != "" {
			req.Header.Set("Authorization", "Bearer "+cfg.APIKey)
		} else if cfg.Username != "" {
			req.SetBasicAuth(cfg.Username, cfg.Password)
		}

		resp, err := client.Do(req)
		if err != nil {
			return imported, err
		}

		if resp.StatusCode == 401 || resp.StatusCode == 403 {
			resp.Body.Close()
			return imported, fmt.Errorf("taxii server rejected credentials (%d)", resp.StatusCode)
		}
		if resp.StatusCode != 200 {
			status := resp.StatusCode
			resp.Body.Close()
			return imported, &feedHTTPError{status: status}
		}

		var parsed taxiiObjectsResponse
		err = json.NewDecoder(resp.Body).Decode(&parsed)
		resp.Body.Close()
		if err != nil {
			return imported, fmt.Errorf("decoding taxii response: %w", err)
		}

		for _, obj := range parsed.Objects {
			if obj.Type != "indicator" {
				continue
			}
			indicator, iocType := parseSTIXPattern(obj.Pattern)
			if indicator == "" {
				continue
			}
			if importIndicator(indicator, iocType, "high", feed.Name, feed.TenantID) {
				imported++
			}
		}

		if parsed.More && parsed.Next != "" {
			url = parsed.Next
		} else {
			url = ""
		}
	}

	return imported, nil
}

// parseSTIXPattern extracts (indicator, iocType) from a simple single-
// comparison STIX pattern. Returns ("", "") if the pattern doesn't match
// the supported shape or refers to an object/property this client doesn't
// map to an internal IOC type.
func parseSTIXPattern(pattern string) (string, string) {

	m := stixComparisonPattern.FindStringSubmatch(pattern)
	if len(m) != 4 {
		return "", ""
	}
	objectType, property, value := m[1], m[2], m[3]

	switch objectType {
	case "ipv4-addr", "ipv6-addr":
		return value, "ip"
	case "domain-name":
		return value, "domain"
	case "url":
		return value, "url"
	case "email-addr":
		return value, "email"
	case "file":
		switch {
		case strings.Contains(property, "MD5"):
			return value, "md5"
		case strings.Contains(property, "SHA-256"), strings.Contains(property, "SHA256"):
			return value, "sha256"
		}
	}

	return "", ""
}
