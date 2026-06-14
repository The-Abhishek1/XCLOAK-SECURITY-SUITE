package services

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
)

const (
	nvdBaseURL    = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	cacheValidFor = 7 * 24 * time.Hour // re-fetch after 7 days
	nvdTimeout    = 10 * time.Second
)

// nvdResponse mirrors the NVD 2.0 API response shape for a single CVE lookup.
type nvdResponse struct {
	Vulnerabilities []struct {
		CVE struct {
			ID          string `json:"id"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Published string `json:"published"`
			Metrics   struct {
				CVSSMetricV31 []struct {
					CVSSData struct {
						BaseScore    float64 `json:"baseScore"`
						BaseSeverity string  `json:"baseSeverity"`
					} `json:"cvssData"`
				} `json:"cvssMetricV31"`
				CVSSMetricV2 []struct {
					CVSSData struct {
						BaseScore float64 `json:"baseScore"`
					} `json:"cvssData"`
					BaseSeverity string `json:"baseSeverity"`
				} `json:"cvssMetricV2"`
			} `json:"metrics"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

// GetCVEDetails returns enrichment data for a CVE ID, using the local DB
// cache to avoid hammering the NVD API on every scan.
func GetCVEDetails(cveID string) (*models.CVECache, error) {

	// 1. Try cache first.
	cached := getCVEFromCache(cveID)
	if cached != nil && time.Since(cached.FetchedAt) < cacheValidFor {
		return cached, nil
	}

	// 2. Fetch from NVD.
	entry, err := fetchFromNVD(cveID)
	if err != nil {
		// Return cached data even if stale rather than failing completely.
		if cached != nil {
			return cached, nil
		}
		return nil, err
	}

	// 3. Persist to cache.
	saveCVEToCache(entry)

	return entry, nil
}

func fetchFromNVD(cveID string) (*models.CVECache, error) {

	url := fmt.Sprintf("%s?cveId=%s", nvdBaseURL, cveID)

	client := &http.Client{Timeout: nvdTimeout}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("NVD API unreachable: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		// CVE not found in NVD — return a stub so we don't retry immediately.
		return &models.CVECache{
			CVEID:       cveID,
			CVSSScore:   0,
			Severity:    "unknown",
			Description: "CVE not found in NVD database",
		}, nil
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("NVD API returned HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var nvd nvdResponse
	if err := json.Unmarshal(body, &nvd); err != nil {
		return nil, err
	}

	if len(nvd.Vulnerabilities) == 0 {
		return &models.CVECache{
			CVEID:       cveID,
			Severity:    "unknown",
			Description: "No data in NVD",
		}, nil
	}

	cve := nvd.Vulnerabilities[0].CVE

	entry := &models.CVECache{
		CVEID:    cve.ID,
		Severity: "unknown",
	}

	// Description (prefer English).
	for _, d := range cve.Descriptions {
		if d.Lang == "en" {
			entry.Description = d.Value
			break
		}
	}

	// CVSS score — prefer v3.1, fall back to v2.
	if len(cve.Metrics.CVSSMetricV31) > 0 {
		m := cve.Metrics.CVSSMetricV31[0]
		entry.CVSSScore = m.CVSSData.BaseScore
		entry.Severity  = strings.ToLower(m.CVSSData.BaseSeverity)
	} else if len(cve.Metrics.CVSSMetricV2) > 0 {
		m := cve.Metrics.CVSSMetricV2[0]
		entry.CVSSScore = m.CVSSData.BaseScore
		entry.Severity  = strings.ToLower(m.BaseSeverity)
	}

	// Published date.
	if cve.Published != "" {
		t, err := time.Parse("2006-01-02T15:04:05.000", cve.Published)
		if err == nil {
			entry.PublishedAt = &t
		}
	}

	return entry, nil
}

func getCVEFromCache(cveID string) *models.CVECache {

	var c models.CVECache

	err := database.DB.QueryRow(`
		SELECT cve_id, cvss_score, severity, description, published_at, fetched_at
		FROM cve_cache WHERE cve_id = $1
	`, cveID).Scan(&c.CVEID, &c.CVSSScore, &c.Severity, &c.Description, &c.PublishedAt, &c.FetchedAt)

	if err != nil {
		return nil
	}

	return &c
}

func saveCVEToCache(c *models.CVECache) {

	database.DB.Exec(`
		INSERT INTO cve_cache (cve_id, cvss_score, severity, description, published_at, fetched_at)
		VALUES ($1,$2,$3,$4,$5,now())
		ON CONFLICT (cve_id) DO UPDATE SET
			cvss_score  = EXCLUDED.cvss_score,
			severity    = EXCLUDED.severity,
			description = EXCLUDED.description,
			fetched_at  = now()
	`, c.CVEID, c.CVSSScore, c.Severity, c.Description, c.PublishedAt)
}
