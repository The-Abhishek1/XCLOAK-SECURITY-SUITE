package services

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"xcloak-platform/database"
)

type GeoIPResult struct {
	IP          string `json:"ip"`
	Country     string `json:"country"`
	CountryCode string `json:"country_code"`
	City        string `json:"city"`
	ISP         string `json:"isp"`
	IsProxy     bool   `json:"is_proxy"`
}

// LookupGeoIP returns geolocation for an IP address.
// Uses ip-api.com free tier (no API key, 1000 req/day limit).
// Results cached in DB for 7 days.
func LookupGeoIP(ip string) (*GeoIPResult, error) {

	// Skip private/loopback addresses.
	if isPrivateIP(ip) {
		return &GeoIPResult{IP: ip, Country: "Private", CountryCode: "LO"}, nil
	}

	// Check cache first.
	cached := getGeoIPCache(ip)
	if cached != nil {
		return cached, nil
	}

	// Fetch from ip-api.com (free, no auth needed).
	url := fmt.Sprintf("http://ip-api.com/json/%s?fields=status,country,countryCode,city,isp,proxy", ip)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("GeoIP lookup failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	var raw struct {
		Status      string `json:"status"`
		Country     string `json:"country"`
		CountryCode string `json:"countryCode"`
		City        string `json:"city"`
		ISP         string `json:"isp"`
		Proxy       bool   `json:"proxy"`
	}

	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}

	if raw.Status != "success" {
		return &GeoIPResult{IP: ip, Country: "Unknown"}, nil
	}

	result := &GeoIPResult{
		IP:          ip,
		Country:     raw.Country,
		CountryCode: raw.CountryCode,
		City:        raw.City,
		ISP:         raw.ISP,
		IsProxy:     raw.Proxy,
	}

	saveGeoIPCache(result)

	return result, nil
}

// EnrichConnections adds GeoIP data to a batch of external connections.
// Called after collecting connections — enriches in background.
func EnrichConnections(agentID int) {

	rows, err := database.DB.Query(`
		SELECT id, remote_address FROM endpoint_connections
		WHERE agent_id = $1 AND state = 'ESTABLISHED'
		AND (country IS NULL OR country = '')
		LIMIT 50
	`, agentID)
	if err != nil {
		return
	}

	type conn struct {
		ID      int
		Remote  string
	}
	var conns []conn
	for rows.Next() {
		var c conn
		if err := rows.Scan(&c.ID, &c.Remote); err == nil {
			conns = append(conns, c)
		}
	}
	rows.Close()

	for _, c := range conns {
		ip := c.Remote
		if idx := strings.LastIndex(ip, ":"); idx > 0 {
			ip = ip[:idx] // strip port
		}

		geo, err := LookupGeoIP(ip)
		if err != nil || geo == nil {
			continue
		}

		database.DB.Exec(`
			UPDATE endpoint_connections
			SET country=$1, country_code=$2, is_proxy=$3
			WHERE id=$4
		`, geo.Country, geo.CountryCode, geo.IsProxy, c.ID)

		// Small delay to respect ip-api rate limit.
		time.Sleep(100 * time.Millisecond)
	}
}

func getGeoIPCache(ip string) *GeoIPResult {
	var r GeoIPResult
	err := database.DB.QueryRow(`
		SELECT ip, country, country_code, city, isp, is_proxy
		FROM geoip_cache
		WHERE ip=$1 AND fetched_at > now() - INTERVAL '7 days'
	`, ip).Scan(&r.IP, &r.Country, &r.CountryCode, &r.City, &r.ISP, &r.IsProxy)
	if err != nil {
		return nil
	}
	return &r
}

func saveGeoIPCache(r *GeoIPResult) {
	database.DB.Exec(`
		INSERT INTO geoip_cache (ip, country, country_code, city, isp, is_proxy)
		VALUES ($1,$2,$3,$4,$5,$6)
		ON CONFLICT (ip) DO UPDATE SET
			country=EXCLUDED.country, country_code=EXCLUDED.country_code,
			city=EXCLUDED.city, isp=EXCLUDED.isp,
			is_proxy=EXCLUDED.is_proxy, fetched_at=now()
	`, r.IP, r.Country, r.CountryCode, r.City, r.ISP, r.IsProxy)
}

// isPrivateIP reports whether ip is RFC1918/loopback. Uses net.IP.IsPrivate
// (Go 1.17+) rather than a hand-rolled prefix check — a prior version
// treated the entire 172.x.x.x/8 as private instead of just the actual
// RFC1918 slice (172.16.0.0–172.31.255.255), e.g. misclassifying a public
// IP like 172.64.0.1 (Cloudflare) as internal.
func isPrivateIP(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	return parsed.IsPrivate() || parsed.IsLoopback() || ip == "0.0.0.0"
}

// GetTopExternalCountries returns the top external countries in connections for an agent.
func GetTopExternalCountries(agentID string) ([]map[string]interface{}, error) {
	rows, err := database.DB.Query(`
		SELECT country, country_code, COUNT(*) as count,
		       SUM(CASE WHEN is_proxy THEN 1 ELSE 0 END) as proxy_count
		FROM endpoint_connections
		WHERE agent_id = $1
		AND country != '' AND country != 'Private'
		GROUP BY country, country_code
		ORDER BY count DESC
		LIMIT 10
	`, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []map[string]interface{}
	for rows.Next() {
		var country, code string
		var count, proxyCount int
		if err := rows.Scan(&country, &code, &count, &proxyCount); err == nil {
			results = append(results, map[string]interface{}{
				"country": country, "country_code": code,
				"count": count, "proxy_count": proxyCount,
			})
		}
	}
	return results, nil
}
