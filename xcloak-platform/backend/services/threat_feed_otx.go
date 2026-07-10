package services

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"xcloak-platform/models"
	"xcloak-platform/repositories"
)

// otxPulsesResponse mirrors the subset of AlienVault OTX's "subscribed
// pulses" response we care about. Full schema:
// https://otx.alienvault.com/api
type otxPulsesResponse struct {
	Results []struct {
		Name       string `json:"name"`
		Indicators []struct {
			Indicator string `json:"indicator"`
			Type      string `json:"type"`
		} `json:"indicators"`
	} `json:"results"`
	Next string `json:"next"`
}

// syncOTXFeed pulls indicators from every pulse the configured API key is
// subscribed to. feed.Source is unused for OTX (the API endpoint is fixed);
// the API key comes from feed.Config.api_key.
//
// OTX paginates via a "next" URL; we follow it up to otxMaxPages times so a
// single sync can't run forever against an account subscribed to thousands
// of pulses.
func syncOTXFeed(feed models.ThreatFeed) (int, error) {

	var cfg models.ThreatFeedConfig
	if err := json.Unmarshal(feed.Config, &cfg); err != nil || cfg.APIKey == "" {
		return 0, fmt.Errorf("otx feed requires config.api_key")
	}

	const otxMaxPages = 50
	url := "https://otx.alienvault.com/api/v1/pulses/subscribed?limit=50"
	client := &http.Client{Timeout: 45 * time.Second}
	imported := 0

	// Record progress even if a later page errors out (timeout, rate limit,
	// etc) — a large OTX subscription can take several requests to walk,
	// and indicators already imported from earlier pages are real, not
	// rolled back just because a later page failed.
	defer repositories.UpdateThreatFeedLastSync(feed.ID, time.Now())

	for page := 0; page < otxMaxPages && url != ""; page++ {

		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return imported, err
		}
		req.Header.Set("X-OTX-API-KEY", cfg.APIKey)
		req.Header.Set("User-Agent", "XCloak-Security-Suite/1.0")

		resp, err := client.Do(req)
		if err != nil {
			return imported, err
		}

		if resp.StatusCode == 401 || resp.StatusCode == 403 {
			status := resp.StatusCode
			resp.Body.Close()
			return imported, fmt.Errorf("otx rejected the API key (%d)", status)
		}
		if resp.StatusCode != 200 {
			status := resp.StatusCode
			resp.Body.Close()
			return imported, &feedHTTPError{status: status}
		}

		var parsed otxPulsesResponse
		err = json.NewDecoder(resp.Body).Decode(&parsed)
		resp.Body.Close()
		if err != nil {
			return imported, fmt.Errorf("decoding otx response: %w", err)
		}

		for _, pulse := range parsed.Results {
			for _, ind := range pulse.Indicators {
				iocType := mapOTXType(ind.Type)
				if iocType == "" {
					continue // unsupported OTX type (e.g. CVE, YARA, Mutex)
				}
				if importIndicator(ind.Indicator, iocType, "high", feed.Name, feed.TenantID) {
					imported++
				}
			}
		}

		url = parsed.Next
	}

	return imported, nil
}

// mapOTXType converts an OTX indicator type to xcloak's internal IOC type.
// Returns "" for OTX types the detection engine doesn't match against yet
// (CVE, YARA, Mutex, etc.) — those are silently skipped rather than stored
// as a type nothing will ever check.
func mapOTXType(otxType string) string {
	switch strings.ToLower(otxType) {
	case "ipv4", "ipv6", "cidr":
		return "ip"
	case "domain", "hostname":
		return "domain"
	case "url", "uri":
		return "url"
	case "filehash-md5":
		return "md5"
	case "filehash-sha256":
		return "sha256"
	case "email":
		return "email"
	default:
		return ""
	}
}
