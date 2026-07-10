package services

// Impossible Travel Detector
//
// Detects when the same user authenticates successfully from two geographically
// separate IP addresses within a time window that makes physical travel
// impossible (speed > 900 km/h — commercial aircraft max ≈ 900 km/h).
//
// Since we can't always do a live GeoIP lookup, we use a simple but highly
// effective heuristic: if the *IP subnet* changes dramatically between two
// successful logins for the same username in < N minutes, it is suspicious.
//
// Two modes:
//
//  Mode A — GeoIP (best): uses ip-api.com batch lookup (free, 15 req/min) to
//            get lat/lon for each IP and compute geodesic distance.
//
//  Mode B — Subnet heuristic (fallback): if two logins from same username have
//            different /16 subnets within 30 minutes, flag as suspicious. This
//            catches cross-region cloud IPs and geographically spread attacks.
//
// Runs every 10 minutes. Alert dedup TTL: 4 hours per (username, ip-pair).
//
// MITRE: T1078 — Valid Accounts (anomalous login location)

import (
	"fmt"
	"log"
	"math"
	"net"
	"strings"
	"time"

	"xcloak-platform/database"
	"xcloak-platform/models"
)

const (
	itDedupTTL        = 4 * time.Hour
	itWindow          = "30 minutes"
	itMaxSpeedKmH     = 900.0  // commercial aircraft
	itSubnetFallback  = true   // use subnet heuristic when GeoIP fails
)

var itDedup = newTTLMap(itDedupTTL)

// ipGeoCache caches GeoIP results to avoid hammering the free API.
var ipGeoCache = newTTLMap(24 * time.Hour)
var ipGeoCacheMap = make(map[string]geoPoint)

type geoPoint struct {
	Lat float64
	Lon float64
	City    string
	Country string
}

func StartImpossibleTravelScheduler() {
	go func() {
		time.Sleep(5 * time.Minute)
		for {
			runImpossibleTravelDetection()
			time.Sleep(10 * time.Minute)
		}
	}()
}

func runImpossibleTravelDetection() {
	rows, err := database.DB.Query(`SELECT id FROM tenants WHERE is_active = true`)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var tid int
		if rows.Scan(&tid) == nil {
			detectImpossibleTravel(tid)
		}
	}
}

func detectImpossibleTravel(tenantID int) {
	// Pull all successful logins per username in the past window, ordered by time.
	// We only need pairs where two logins share a username but differ in src_ip.
	rows, err := database.DB.Query(`
		SELECT el.agent_id,
		       el.parsed_fields->>'user'   AS username,
		       el.parsed_fields->>'src_ip' AS src_ip,
		       el.created_at               AS login_time
		FROM endpoint_logs el
		JOIN agents a ON a.id = el.agent_id AND a.tenant_id = $1
		WHERE el.parsed_fields->>'auth_result' = 'success'
		  AND el.parsed_fields->>'user'   IS NOT NULL
		  AND el.parsed_fields->>'src_ip' IS NOT NULL
		  AND el.created_at > NOW() - INTERVAL '`+itWindow+`'
		ORDER BY el.parsed_fields->>'user', el.created_at
	`, tenantID)
	if err != nil {
		return
	}
	defer rows.Close()

	type loginEvent struct {
		agentID   int
		srcIP     string
		loginTime time.Time
	}

	// Group logins by username
	byUser := map[string][]loginEvent{}
	for rows.Next() {
		var agentID int
		var username, srcIP string
		var loginTime time.Time
		if rows.Scan(&agentID, &username, &srcIP, &loginTime) != nil {
			continue
		}
		u := strings.ToLower(username)
		byUser[u] = append(byUser[u], loginEvent{agentID, srcIP, loginTime})
	}

	for username, events := range byUser {
		if len(events) < 2 {
			continue
		}
		// Compare each adjacent pair
		for i := 0; i < len(events)-1; i++ {
			a, b := events[i], events[i+1]
			if a.srcIP == b.srcIP {
				continue
			}
			elapsed := b.loginTime.Sub(a.loginTime).Minutes()
			if elapsed <= 0 {
				elapsed = 1
			}

			suspicious, reason := checkTravelImpossible(a.srcIP, b.srcIP, elapsed)
			if !suspicious {
				continue
			}

			key := fmt.Sprintf("%d:imptravel:%s:%s:%s", tenantID, username, a.srcIP, b.srcIP)
			if itDedup.touched(key) {
				continue
			}
			itDedup.touch(key)

			msg := fmt.Sprintf(
				"Impossible travel detected: user '%s' logged in from %s then %s %.0f minutes later — %s",
				username, a.srcIP, b.srcIP, elapsed, reason,
			)
			log.Printf("[ImpTravel] %s", msg)
			CreateAlert(models.Alert{
				AgentID:        b.agentID,
				TenantID:       tenantID,
				Severity:       "high",
				RuleName:       "Impossible Travel — Account Compromise",
				LogMessage:     msg,
				MitreTactic:    "Initial Access",
				MitreTechnique: "T1078",
				MitreName:      "Valid Accounts",
				Fingerprint:    fmt.Sprintf("imptravel-%s-%s-%s", username, a.srcIP, b.srcIP),
			})
		}
	}
}

// checkTravelImpossible returns (suspicious, reason) for two IPs elapsed minutes apart.
func checkTravelImpossible(ip1, ip2 string, elapsedMin float64) (bool, string) {
	// Try GeoIP first
	g1, ok1 := getGeoIP(ip1)
	g2, ok2 := getGeoIP(ip2)

	if ok1 && ok2 {
		if g1.Country == g2.Country && g1.City == g2.City {
			return false, ""
		}
		distKm := haversineKm(g1.Lat, g1.Lon, g2.Lat, g2.Lon)
		if distKm < 50 {
			return false, "" // same metro area
		}
		requiredSpeedKmH := distKm / (elapsedMin / 60.0)
		if requiredSpeedKmH > itMaxSpeedKmH {
			return true, fmt.Sprintf(
				"%.0fkm apart (%s→%s), requires %.0fkm/h",
				distKm, formatGeo(g1), formatGeo(g2), requiredSpeedKmH,
			)
		}
		return false, ""
	}

	// Fallback: /16 subnet heuristic
	if !itSubnetFallback {
		return false, ""
	}
	net1 := subnetSlash16(ip1)
	net2 := subnetSlash16(ip2)
	if net1 == "" || net2 == "" || net1 == net2 {
		return false, ""
	}
	// Both private / RFC1918 — skip (VPN split tunneling, etc.)
	if isPrivate(ip1) || isPrivate(ip2) {
		return false, ""
	}
	if elapsedMin < 5 {
		return true, fmt.Sprintf("different /16 subnets (%s vs %s) within %.0f minutes", net1, net2, elapsedMin)
	}
	return false, ""
}

// ── GeoIP via ip-api.com (reuses fetchIPAPI from ip_enrich.go) ─────────────

func getGeoIP(ip string) (geoPoint, bool) {
	if isPrivate(ip) {
		return geoPoint{}, false
	}
	if p, ok := ipGeoCacheMap[ip]; ok {
		return p, true
	}
	r := fetchIPAPI(ip)
	if r == nil {
		return geoPoint{}, false
	}
	p := geoPoint{Lat: r.Lat, Lon: r.Lon, City: r.City, Country: r.Country}
	ipGeoCacheMap[ip] = p
	return p, true
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func haversineKm(lat1, lon1, lat2, lon2 float64) float64 {
	const R = 6371.0
	dLat := (lat2 - lat1) * math.Pi / 180
	dLon := (lon2 - lon1) * math.Pi / 180
	a := math.Sin(dLat/2)*math.Sin(dLat/2) +
		math.Cos(lat1*math.Pi/180)*math.Cos(lat2*math.Pi/180)*
			math.Sin(dLon/2)*math.Sin(dLon/2)
	return R * 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))
}

func formatGeo(p geoPoint) string {
	if p.City != "" && p.Country != "" {
		return p.City + ", " + p.Country
	}
	if p.Country != "" {
		return p.Country
	}
	return fmt.Sprintf("%.2f,%.2f", p.Lat, p.Lon)
}

func subnetSlash16(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}
	ip = ip.To4()
	if ip == nil {
		return ""
	}
	return fmt.Sprintf("%d.%d", ip[0], ip[1])
}

func isPrivate(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	privateRanges := []string{
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"127.0.0.0/8", "169.254.0.0/16", "::1/128", "fc00::/7",
	}
	for _, cidr := range privateRanges {
		_, network, err := net.ParseCIDR(cidr)
		if err == nil && network.Contains(ip) {
			return true
		}
	}
	return false
}
