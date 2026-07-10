package services

// Hash enrichment — looks up file hashes (MD5, SHA1, SHA256) against
// VirusTotal and MalwareBazaar to give analysts immediate verdict context
// when reviewing process snapshot artifacts, FIM changes, or quarantined files.
//
// Sources:
//   VirusTotal v3  (env: VIRUSTOTAL_KEY)  — multi-AV scan results + file metadata
//   MalwareBazaar  (no key required)      — abuse.ch curated malware samples
//
// Results are cached in-process for 4 hours to avoid burning API quota on
// repeated lookups of the same hash during a busy incident.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// HashEnrichment is the full verdict for one file hash.
type HashEnrichment struct {
	Hash     string `json:"hash"`
	HashType string `json:"hash_type"` // md5 | sha1 | sha256

	// VirusTotal
	VTMalicious    *int     `json:"vt_malicious,omitempty"`
	VTSuspicious   *int     `json:"vt_suspicious,omitempty"`
	VTTotal        *int     `json:"vt_total,omitempty"`
	VTFileName     string   `json:"vt_file_name,omitempty"`
	VTFileType     string   `json:"vt_file_type,omitempty"`
	VTFileSizeBytes int64   `json:"vt_file_size,omitempty"`
	VTFirstSeen    string   `json:"vt_first_seen,omitempty"`
	VTLastSeen     string   `json:"vt_last_seen,omitempty"`
	VTFamilies     []string `json:"vt_families,omitempty"` // popular_threat_name

	// MalwareBazaar
	MBSeen         bool     `json:"mb_seen"`
	MBMalwareName  string   `json:"mb_malware_name,omitempty"`
	MBMalwareFamily string  `json:"mb_malware_family,omitempty"`
	MBTags         []string `json:"mb_tags,omitempty"`
	MBReporter     string   `json:"mb_reporter,omitempty"`
	MBFirstSeen    string   `json:"mb_first_seen,omitempty"`

	// Computed
	Verdict    string   `json:"verdict"`     // clean | suspicious | malicious | unknown
	Confidence string   `json:"confidence"`  // low | medium | high
	Tags       []string `json:"tags"`
	Sources    []string `json:"sources"`
}

var (
	hashCache    sync.Map
	hashCacheTTL = 4 * time.Hour
)

type hashCacheEntry struct {
	data    *HashEnrichment
	expires time.Time
}

// EnrichHash looks up a hash and returns a combined verdict. Hash type is
// auto-detected from length (32=md5, 40=sha1, 64=sha256).
func EnrichHash(hash string) (*HashEnrichment, error) {
	hash = strings.ToLower(strings.TrimSpace(hash))
	if len(hash) == 0 {
		return nil, fmt.Errorf("empty hash")
	}

	if v, ok := hashCache.Load(hash); ok {
		e := v.(hashCacheEntry)
		if time.Now().Before(e.expires) {
			return e.data, nil
		}
		hashCache.Delete(hash)
	}

	hashType := detectHashType(hash)
	if hashType == "" {
		return nil, fmt.Errorf("unrecognised hash length %d (expected 32/40/64 hex chars)", len(hash))
	}

	result := &HashEnrichment{
		Hash:     hash,
		HashType: hashType,
		Tags:     []string{},
		Sources:  []string{},
	}

	// 1. VirusTotal
	if key := os.Getenv("VIRUSTOTAL_KEY"); key != "" {
		fetchHashVirusTotal(hash, key, result)
	}

	// 2. MalwareBazaar (free, no key)
	fetchHashMalwareBazaar(hash, result)

	result.Verdict, result.Confidence = computeHashVerdict(result)
	hashCache.Store(hash, hashCacheEntry{data: result, expires: time.Now().Add(hashCacheTTL)})
	return result, nil
}

func detectHashType(hash string) string {
	for _, c := range hash {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return ""
		}
	}
	switch len(hash) {
	case 32:
		return "md5"
	case 40:
		return "sha1"
	case 64:
		return "sha256"
	default:
		return ""
	}
}

func computeHashVerdict(r *HashEnrichment) (verdict, confidence string) {
	if r.MBSeen {
		return "malicious", "high"
	}
	if r.VTMalicious != nil {
		switch {
		case *r.VTMalicious >= 10:
			return "malicious", "high"
		case *r.VTMalicious >= 3:
			return "malicious", "medium"
		case *r.VTMalicious >= 1:
			return "suspicious", "medium"
		}
		if r.VTSuspicious != nil && *r.VTSuspicious >= 3 {
			return "suspicious", "low"
		}
		if r.VTTotal != nil && *r.VTTotal > 0 {
			return "clean", "high"
		}
	}
	return "unknown", "low"
}

// ── VirusTotal hash lookup ────────────────────────────────────────────────────

func fetchHashVirusTotal(hash, key string, out *HashEnrichment) {
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET",
		fmt.Sprintf("https://www.virustotal.com/api/v3/files/%s", hash), nil)
	if err != nil {
		return
	}
	req.Header.Set("x-apikey", key)
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode == 404 {
		// 404 = hash not in VT database — not an error
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return
	}

	var body struct {
		Data struct {
			Attributes struct {
				LastAnalysisStats struct {
					Malicious  int `json:"malicious"`
					Suspicious int `json:"suspicious"`
					Undetected int `json:"undetected"`
					Harmless   int `json:"harmless"`
				} `json:"last_analysis_stats"`
				MeaningfulName  string   `json:"meaningful_name"`
				TypeDescription string   `json:"type_description"`
				Size            int64    `json:"size"`
				FirstSubmission string   `json:"first_submission_date"`
				LastAnalysis    string   `json:"last_analysis_date"`
				PopularThreatNames []struct {
					Value string `json:"value"`
				} `json:"popular_threat_name"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return
	}

	s := body.Data.Attributes.LastAnalysisStats
	malicious := s.Malicious
	suspicious := s.Suspicious
	total := s.Malicious + s.Suspicious + s.Undetected + s.Harmless

	out.VTMalicious = &malicious
	out.VTSuspicious = &suspicious
	out.VTTotal = &total
	out.VTFileName = body.Data.Attributes.MeaningfulName
	out.VTFileType = body.Data.Attributes.TypeDescription
	out.VTFileSizeBytes = body.Data.Attributes.Size
	out.Sources = append(out.Sources, "virustotal")

	for _, t := range body.Data.Attributes.PopularThreatNames {
		if t.Value != "" {
			out.VTFamilies = append(out.VTFamilies, t.Value)
			out.Tags = append(out.Tags, t.Value)
		}
	}
	if malicious > 0 {
		out.Tags = append(out.Tags, fmt.Sprintf("VT:%d/%d malicious", malicious, total))
	}
}

// ── MalwareBazaar ─────────────────────────────────────────────────────────────

func fetchHashMalwareBazaar(hash string, out *HashEnrichment) {
	client := &http.Client{Timeout: 10 * time.Second}

	body := bytes.NewBufferString("query=get_info&hash=" + hash)
	req, err := http.NewRequest("POST", "https://mb-api.abuse.ch/api/v1/", body)
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "XCloak-Security-Suite/1.0")

	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != 200 {
		return
	}
	defer resp.Body.Close()

	var mbResp struct {
		QueryStatus string `json:"query_status"`
		Data        []struct {
			SHA256        string   `json:"sha256_hash"`
			MalwareName   string   `json:"file_name"`
			Signature     string   `json:"signature"`
			Tags          []string `json:"tags"`
			Reporter      string   `json:"reporter"`
			FirstSeen     string   `json:"first_seen"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&mbResp); err != nil {
		return
	}
	if mbResp.QueryStatus != "ok" || len(mbResp.Data) == 0 {
		return
	}

	d := mbResp.Data[0]
	out.MBSeen = true
	out.MBMalwareName = d.MalwareName
	out.MBMalwareFamily = d.Signature
	out.MBTags = d.Tags
	out.MBReporter = d.Reporter
	out.MBFirstSeen = d.FirstSeen
	out.Sources = append(out.Sources, "malwarebazaar")

	if d.Signature != "" {
		out.Tags = append(out.Tags, "MB:"+d.Signature)
	}
}
