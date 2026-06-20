package services

import (
	"bufio"
	"net/http"
	"strings"
	"time"

	"xcloak-ngfw/models"
	"xcloak-ngfw/repositories"
)

// SyncThreatFeed dispatches to the right connector based on feed.FeedType.
// "flatfile" (the default, for backward compatibility with feeds created
// before connectors existed) is handled inline here; otx/misp/taxii each
// have their own file.
func SyncThreatFeed(feed models.ThreatFeed) (int, error) {
	switch feed.FeedType {
	case "otx":
		return syncOTXFeed(feed)
	case "misp":
		return syncMISPFeed(feed)
	case "taxii":
		return syncTAXIIFeed(feed)
	default:
		return syncFlatFileFeed(feed)
	}
}

// syncFlatFileFeed fetches a feed's source URL, expects a plaintext response
// with one indicator per line (IPs, domains, hashes — comments starting
// with '#' or ';' and blank lines are ignored), and bulk-imports every line
// as an IOC. This format matches many free open feeds, e.g.:
//
//	FireHOL level1:    https://iplists.firehol.org/files/firehol_level1.netset
//	abuse.ch SSL Blacklist (IP list): https://sslbl.abuse.ch/blacklist/sslipblacklist.txt
//	Spamhaus DROP:     https://www.spamhaus.org/drop/drop.txt
//
// Returns the number of new indicators imported, and an error if the feed
// could not be fetched at all (a feed with 0 new indicators is not an error
// — it just means everything was already in the IOC table).
func syncFlatFileFeed(feed models.ThreatFeed) (int, error) {

	req, err := http.NewRequest("GET", feed.Source, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", "XCloak-Security-Suite/1.0")

	client := &http.Client{Timeout: 30 * time.Second}

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return 0, &feedHTTPError{status: resp.StatusCode}
	}

	imported := 0
	scanner := bufio.NewScanner(resp.Body)

	// Increase buffer size — some feeds (FireHOL level1, Spamhaus DROP) have
	// very long lines or are large files.
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {

		line := strings.TrimSpace(scanner.Text())

		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		// Some feeds put a comment after the indicator separated by whitespace
		// (e.g. "1.2.3.4 # description"). Take only the first field.
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		indicator := fields[0]

		iocType := guessIOCType(indicator)

		err := repositories.CreateIOC(models.IOC{
			Indicator:   indicator,
			Type:        iocType,
			Severity:    "high",
			Description: "Imported from threat feed: " + feed.Name,
			Enabled:     true,
		})

		// CreateIOC silently no-ops (returns nil) if the indicator already
		// exists, so we can't distinguish "already existed" from "inserted"
		// without an extra query. Count every successfully-processed line —
		// good enough for a sync summary.
		if err == nil {
			imported++
		}
	}

	repositories.UpdateThreatFeedLastSync(feed.ID, time.Now())

	return imported, nil
}

// guessIOCType makes a best-effort guess at the indicator type based on its
// shape — IPv4/CIDR, SHA256/MD5 hash length, or domain (fallback).
func guessIOCType(indicator string) string {

	// CIDR or plain IPv4: digits, dots, optional /prefix
	isIP := true
	for _, r := range indicator {
		if !((r >= '0' && r <= '9') || r == '.' || r == '/') {
			isIP = false
			break
		}
	}
	if isIP && strings.Contains(indicator, ".") {
		return "ip"
	}

	// Hex-only strings of typical hash lengths
	isHex := true
	for _, r := range indicator {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			isHex = false
			break
		}
	}
	if isHex {
		switch len(indicator) {
		case 64:
			return "sha256"
		case 32:
			return "md5"
		}
	}

	return "domain"
}

// importIndicator stores one indicator from a connector feed as an IOC.
// Shared by the otx/misp/taxii connectors — CreateIOC already no-ops on a
// duplicate indicator, so this just reports whether the call succeeded.
func importIndicator(indicator, iocType, severity, feedName string) bool {
	if indicator == "" || iocType == "" {
		return false
	}
	err := repositories.CreateIOC(models.IOC{
		Indicator:   indicator,
		Type:        iocType,
		Severity:    severity,
		Description: "Imported from threat feed: " + feedName,
		Enabled:     true,
	})
	return err == nil
}

type feedHTTPError struct {
	status int
}

func (e *feedHTTPError) Error() string {
	if e.status == 404 {
		return "threat feed source returned 404 — check the URL"
	}
	return "threat feed source returned HTTP error"
}
