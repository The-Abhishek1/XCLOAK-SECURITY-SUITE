package services

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"xcloak-ngfw/database"
)

const (
	epssBaseURL = "https://api.first.org/data/v1/epss"
	kevURL      = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	epssTimeout = 10 * time.Second
	kevTimeout  = 20 * time.Second

	// EPSS is recomputed daily; KEV is updated as CISA adds entries, so a
	// few hours of staleness is fine — refreshed on its own scheduler
	// (StartKEVRefreshScheduler) rather than gated per-lookup like EPSS.
	epssCacheValidFor = 24 * time.Hour
)

type epssResponse struct {
	Data []struct {
		CVE        string `json:"cve"`
		EPSS       string `json:"epss"`
		Percentile string `json:"percentile"`
	} `json:"data"`
}

// GetEPSSScore returns the EPSS exploit-prediction score and percentile for
// a CVE, using the local DB cache (refreshed daily) to avoid hammering
// FIRST.org on every scan — same pattern as GetCVEDetails/NVD.
func GetEPSSScore(cveID string) (score, percentile float64, err error) {

	if s, p, fetchedAt, ok := getEPSSFromCache(cveID); ok {
		if time.Since(fetchedAt) < epssCacheValidFor {
			return s, p, nil
		}
		score, percentile = s, p // fall back to stale cache if refetch fails
	}

	s, p, ferr := fetchEPSSFromAPI(cveID)
	if ferr != nil {
		if score != 0 || percentile != 0 {
			return score, percentile, nil
		}
		return 0, 0, ferr
	}

	saveEPSSToCache(cveID, s, p)
	return s, p, nil
}

func fetchEPSSFromAPI(cveID string) (float64, float64, error) {

	client := &http.Client{Timeout: epssTimeout}
	resp, err := client.Get(epssBaseURL + "?cve=" + cveID)
	if err != nil {
		return 0, 0, fmt.Errorf("EPSS API unreachable: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, 0, fmt.Errorf("EPSS API returned HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, 0, err
	}

	var parsed epssResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return 0, 0, fmt.Errorf("failed to parse EPSS response: %w", err)
	}
	if len(parsed.Data) == 0 {
		return 0, 0, nil
	}

	score, _ := strconv.ParseFloat(parsed.Data[0].EPSS, 64)
	percentile, _ := strconv.ParseFloat(parsed.Data[0].Percentile, 64)
	return score, percentile, nil
}

func getEPSSFromCache(cveID string) (score, percentile float64, fetchedAt time.Time, ok bool) {

	err := database.DB.QueryRow(`
		SELECT epss_score, percentile, fetched_at FROM epss_cache WHERE cve_id = $1
	`, cveID).Scan(&score, &percentile, &fetchedAt)

	return score, percentile, fetchedAt, err == nil
}

func saveEPSSToCache(cveID string, score, percentile float64) {
	database.DB.Exec(`
		INSERT INTO epss_cache (cve_id, epss_score, percentile, fetched_at)
		VALUES ($1,$2,$3,now())
		ON CONFLICT (cve_id) DO UPDATE SET
			epss_score = EXCLUDED.epss_score,
			percentile = EXCLUDED.percentile,
			fetched_at = now()
	`, cveID, score, percentile)
}

// kevCatalogResponse mirrors the subset of CISA's KEV catalog JSON schema
// this service uses.
type kevCatalogResponse struct {
	Vulnerabilities []struct {
		CveID                      string `json:"cveID"`
		VendorProject              string `json:"vendorProject"`
		Product                    string `json:"product"`
		VulnerabilityName          string `json:"vulnerabilityName"`
		DateAdded                  string `json:"dateAdded"`
		DueDate                    string `json:"dueDate"`
		RequiredAction             string `json:"requiredAction"`
		KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
	} `json:"vulnerabilities"`
}

// RefreshKEVCatalog fetches CISA's full Known Exploited Vulnerabilities
// catalog and mirrors it wholesale into kev_cache. The catalog is small
// (~1600 entries) so a full refresh is cheap; per-CVE lookups against it
// afterwards are pure local DB reads with no API call on the request path.
func RefreshKEVCatalog() error {

	client := &http.Client{Timeout: kevTimeout}
	resp, err := client.Get(kevURL)
	if err != nil {
		return fmt.Errorf("CISA KEV feed unreachable: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("CISA KEV feed returned HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var catalog kevCatalogResponse
	if err := json.Unmarshal(body, &catalog); err != nil {
		return fmt.Errorf("failed to parse CISA KEV feed: %w", err)
	}

	tx, err := database.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for _, e := range catalog.Vulnerabilities {
		dateAdded := parseKEVDate(e.DateAdded)
		dueDate := parseKEVDate(e.DueDate)

		_, err := tx.Exec(`
			INSERT INTO kev_cache
			(cve_id, vendor_project, product, vulnerability_name,
			 date_added, due_date, known_ransomware, required_action, fetched_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,now())
			ON CONFLICT (cve_id) DO UPDATE SET
				vendor_project     = EXCLUDED.vendor_project,
				product            = EXCLUDED.product,
				vulnerability_name = EXCLUDED.vulnerability_name,
				date_added         = EXCLUDED.date_added,
				due_date           = EXCLUDED.due_date,
				known_ransomware   = EXCLUDED.known_ransomware,
				required_action    = EXCLUDED.required_action,
				fetched_at         = now()
		`,
			e.CveID, e.VendorProject, e.Product, e.VulnerabilityName,
			dateAdded, dueDate, strings.EqualFold(e.KnownRansomwareCampaignUse, "Known"), e.RequiredAction,
		)
		if err != nil {
			return fmt.Errorf("upserting KEV entry %s: %w", e.CveID, err)
		}
	}

	slog.Info("kev: catalog refreshed", "entries", len(catalog.Vulnerabilities))

	return tx.Commit()
}

func parseKEVDate(s string) *time.Time {
	if s == "" {
		return nil
	}
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		return nil
	}
	return &t
}

// IsKEVCVE looks up a CVE against the locally-mirrored CISA KEV catalog —
// a plain DB read, no external call, safe to use inline during a scan.
func IsKEVCVE(cveID string) (isKEV bool, dateAdded *time.Time, ransomware bool) {

	var added sql.NullTime
	err := database.DB.QueryRow(`
		SELECT date_added, known_ransomware FROM kev_cache WHERE cve_id = $1
	`, cveID).Scan(&added, &ransomware)

	if err != nil {
		return false, nil, false
	}
	if added.Valid {
		dateAdded = &added.Time
	}
	return true, dateAdded, ransomware
}

// StartKEVRefreshScheduler refreshes the CISA KEV catalog immediately and
// then every 6 hours. Call as `go services.StartKEVRefreshScheduler()`.
func StartKEVRefreshScheduler() {
	refresh := func() {
		if err := RefreshKEVCatalog(); err != nil {
			slog.Error("kev: catalog refresh failed", "err", err)
		}
	}

	WithSingletonLock("kev_refresh", refresh)

	ticker := time.NewTicker(6 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		WithSingletonLock("kev_refresh", refresh)
	}
}
