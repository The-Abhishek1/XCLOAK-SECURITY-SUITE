package services

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"xcloak-ngfw/models"
	"xcloak-ngfw/repositories"
)

// mispSearchRequest is the body for MISP's attributes/restSearch endpoint.
// https://www.misp-project.org/openapi/#tag/Attributes/operation/restSearchAttributes
type mispSearchRequest struct {
	ReturnFormat string   `json:"returnFormat"`
	Type         []string `json:"type"`
	ToIDs        bool     `json:"to_ids"` // only attributes flagged for IDS/detection use
}

type mispSearchResponse struct {
	Response struct {
		Attribute []struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"Attribute"`
	} `json:"response"`
}

// mispAttributeTypes are the MISP attribute types we know how to map to an
// internal IOC type. Asking MISP to filter server-side (rather than
// fetching everything and filtering client-side) keeps the response small.
var mispAttributeTypes = []string{
	"ip-dst", "ip-src", "domain", "hostname", "url", "md5", "sha256",
}

// syncMISPFeed pulls IDS-flagged attributes from a MISP instance's
// restSearch API. feed.Source is the MISP base URL (e.g.
// "https://misp.example.org", no trailing slash); the API key comes from
// feed.Config.api_key.
func syncMISPFeed(feed models.ThreatFeed) (int, error) {

	var cfg models.ThreatFeedConfig
	if err := json.Unmarshal(feed.Config, &cfg); err != nil || cfg.APIKey == "" {
		return 0, fmt.Errorf("misp feed requires config.api_key")
	}
	if feed.Source == "" {
		return 0, fmt.Errorf("misp feed requires source to be set to the MISP base URL")
	}

	reqBody, err := json.Marshal(mispSearchRequest{
		ReturnFormat: "json",
		Type:         mispAttributeTypes,
		ToIDs:        true,
	})
	if err != nil {
		return 0, err
	}

	url := strings.TrimRight(feed.Source, "/") + "/attributes/restSearch"
	httpReq, err := http.NewRequest("POST", url, bytes.NewReader(reqBody))
	if err != nil {
		return 0, err
	}
	httpReq.Header.Set("Authorization", cfg.APIKey)
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("User-Agent", "XCloak-Security-Suite/1.0")

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return 0, fmt.Errorf("misp rejected the API key (%d)", resp.StatusCode)
	}
	if resp.StatusCode != 200 {
		return 0, &feedHTTPError{status: resp.StatusCode}
	}

	var parsed mispSearchResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return 0, fmt.Errorf("decoding misp response: %w", err)
	}

	imported := 0
	for _, attr := range parsed.Response.Attribute {
		iocType := mapMISPType(attr.Type)
		if iocType == "" {
			continue
		}
		if importIndicator(attr.Value, iocType, "high", feed.Name) {
			imported++
		}
	}

	repositories.UpdateThreatFeedLastSync(feed.ID, time.Now())
	return imported, nil
}

// mapMISPType converts a MISP attribute type to xcloak's internal IOC type.
func mapMISPType(mispType string) string {
	switch strings.ToLower(mispType) {
	case "ip-dst", "ip-src":
		return "ip"
	case "domain", "hostname":
		return "domain"
	case "url", "uri":
		return "url"
	case "md5":
		return "md5"
	case "sha256":
		return "sha256"
	default:
		return ""
	}
}
