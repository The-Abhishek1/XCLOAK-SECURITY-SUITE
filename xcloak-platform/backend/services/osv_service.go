package services

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	osvBatchURL = "https://api.osv.dev/v1/querybatch"
	osvVulnURL  = "https://api.osv.dev/v1/vulns/"
	osvTimeout  = 15 * time.Second
)

// osvEcosystem is hardcoded to Debian because the only Linux package
// collector in this codebase (xcloak-agent-desktop's CollectPackages) shells out to
// dpkg-query — if an RPM-based or other collector is added later, this
// needs to vary per-agent based on the host's actual distro.
const osvEcosystem = "Debian"

type osvQuery struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Version string `json:"version"`
}

type osvBatchResponse struct {
	Results []struct {
		Vulns []struct {
			ID string `json:"id"`
		} `json:"vulns"`
	} `json:"results"`
}

// OSVVulnDetail is the subset of the OSV vulnerability schema this service
// uses to build a models.Vulnerability.
type OSVVulnDetail struct {
	ID       string   `json:"id"`
	Summary  string   `json:"summary"`
	Details  string   `json:"details"`
	Aliases  []string `json:"aliases"`
	Upstream []string `json:"upstream"`
	Affected []struct {
		Ranges []struct {
			Events []map[string]string `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
}

// queryOSVBatch looks up known vulnerabilities for every (name, version)
// pair in one request, returning a parallel slice of vuln-ID lists. OSV
// does real version-range comparison server-side — passing the installed
// version means a patched package correctly comes back with no hits,
// unlike the previous name-substring-only check.
func queryOSVBatch(pkgNames, pkgVersions []string) ([][]string, error) {
	queries := make([]osvQuery, len(pkgNames))
	for i := range pkgNames {
		queries[i].Package.Name = pkgNames[i]
		queries[i].Package.Ecosystem = osvEcosystem
		queries[i].Version = pkgVersions[i]
	}

	body, err := json.Marshal(struct {
		Queries []osvQuery `json:"queries"`
	}{Queries: queries})
	if err != nil {
		return nil, err
	}

	client := &http.Client{Timeout: osvTimeout}
	resp, err := client.Post(osvBatchURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("OSV batch query failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OSV batch query returned HTTP %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var parsed osvBatchResponse
	if err := json.Unmarshal(data, &parsed); err != nil {
		return nil, fmt.Errorf("failed to parse OSV batch response: %w", err)
	}

	out := make([][]string, len(pkgNames))
	for i, r := range parsed.Results {
		if i >= len(out) {
			break
		}
		for _, v := range r.Vulns {
			out[i] = append(out[i], v.ID)
		}
	}
	return out, nil
}

// getOSVVulnDetail fetches the full record for one OSV/Debian advisory ID —
// the batch endpoint only returns IDs, not severity/remediation data.
func getOSVVulnDetail(id string) (*OSVVulnDetail, error) {
	client := &http.Client{Timeout: osvTimeout}
	resp, err := client.Get(osvVulnURL + id)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OSV vuln lookup for %s returned HTTP %d", id, resp.StatusCode)
	}

	var detail OSVVulnDetail
	if err := json.NewDecoder(resp.Body).Decode(&detail); err != nil {
		return nil, err
	}
	return &detail, nil
}

// cveAliasFor returns the CVE ID associated with an OSV advisory if one
// exists (Debian advisories are usually namespaced as "DEBIAN-CVE-xxxx" or
// carry the CVE as an alias/upstream reference), falling back to the OSV
// ID itself for advisories with no CVE (e.g. pure GHSA/DSA).
func (d OSVVulnDetail) cveAliasFor() string {
	for _, a := range append(append([]string{}, d.Aliases...), d.Upstream...) {
		if strings.HasPrefix(a, "CVE-") {
			return a
		}
	}
	if idx := strings.Index(d.ID, "CVE-"); idx >= 0 {
		return d.ID[idx:]
	}
	return d.ID
}

// fixedVersion returns the first "fixed" version found in the advisory's
// affected ranges, if any — used to build a concrete remediation string
// instead of a generic "upgrade" suggestion.
func (d OSVVulnDetail) fixedVersion() string {
	for _, aff := range d.Affected {
		for _, r := range aff.Ranges {
			for _, ev := range r.Events {
				if v, ok := ev["fixed"]; ok && v != "" {
					return v
				}
			}
		}
	}
	return ""
}

func (d OSVVulnDetail) descriptionText() string {
	if d.Summary != "" {
		return d.Summary
	}
	return truncate(d.Details, 500)
}
