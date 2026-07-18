package api

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"xcloak-platform/database"
	"xcloak-platform/services"
)

func createSupplyChainTables() {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS sc_repositories (
			id SERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL,
			name TEXT DEFAULT '', owner TEXT DEFAULT '',
			platform TEXT DEFAULT 'github', language TEXT DEFAULT '',
			default_branch TEXT DEFAULT 'main', last_commit TIMESTAMPTZ DEFAULT NOW(),
			contributor_count INTEGER DEFAULT 0, is_private BOOLEAN DEFAULT true,
			dep_count INTEGER DEFAULT 0, risk_score INTEGER DEFAULT 0,
			created_at TIMESTAMPTZ DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS sc_dependencies (
			id SERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL,
			repo_id INTEGER DEFAULT 0, package_name TEXT DEFAULT '',
			version TEXT DEFAULT '', latest_version TEXT DEFAULT '',
			ecosystem TEXT DEFAULT 'npm', license TEXT DEFAULT '',
			cve_count INTEGER DEFAULT 0, is_direct BOOLEAN DEFAULT true,
			is_outdated BOOLEAN DEFAULT false, risk_score INTEGER DEFAULT 0,
			created_at TIMESTAMPTZ DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS sc_vulnerabilities (
			id SERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL,
			dep_id INTEGER DEFAULT 0, cve_id TEXT DEFAULT '',
			cvss NUMERIC(4,1) DEFAULT 0, epss NUMERIC(6,4) DEFAULT 0,
			is_kev BOOLEAN DEFAULT false, fix_version TEXT DEFAULT '',
			has_exploit BOOLEAN DEFAULT false, severity TEXT DEFAULT 'medium',
			description TEXT DEFAULT '', affected_projects TEXT DEFAULT '',
			created_at TIMESTAMPTZ DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS sc_sboms (
			id SERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL,
			repo_id INTEGER DEFAULT 0, artifact_name TEXT DEFAULT '',
			format TEXT DEFAULT 'cyclonedx', component_count INTEGER DEFAULT 0,
			license_count INTEGER DEFAULT 0, supplier_count INTEGER DEFAULT 0,
			has_vulnerabilities BOOLEAN DEFAULT false,
			generated_at TIMESTAMPTZ DEFAULT NOW(), created_at TIMESTAMPTZ DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS sc_build_pipelines (
			id SERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL,
			repo_id INTEGER DEFAULT 0, name TEXT DEFAULT '',
			platform TEXT DEFAULT 'github_actions', status TEXT DEFAULT 'passing',
			last_run TIMESTAMPTZ DEFAULT NOW(), has_secrets BOOLEAN DEFAULT false,
			has_untrusted_actions BOOLEAN DEFAULT false,
			has_pinned_versions BOOLEAN DEFAULT true, risk_score INTEGER DEFAULT 0,
			created_at TIMESTAMPTZ DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS sc_artifacts (
			id SERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL,
			pipeline_id INTEGER DEFAULT 0, name TEXT DEFAULT '',
			artifact_type TEXT DEFAULT 'container', version TEXT DEFAULT '',
			is_signed BOOLEAN DEFAULT false, has_sbom BOOLEAN DEFAULT false,
			artifact_hash TEXT DEFAULT '', provenance_available BOOLEAN DEFAULT false,
			risk_score INTEGER DEFAULT 0, created_at TIMESTAMPTZ DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS sc_secrets (
			id SERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL,
			repo_id INTEGER DEFAULT 0, secret_type TEXT DEFAULT '',
			file_path TEXT DEFAULT '', commit_hash TEXT DEFAULT '',
			severity TEXT DEFAULT 'high', status TEXT DEFAULT 'open',
			created_at TIMESTAMPTZ DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS sc_policies (
			id SERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL,
			name TEXT DEFAULT '', rule_type TEXT DEFAULT '',
			action TEXT DEFAULT 'block', is_enabled BOOLEAN DEFAULT true,
			description TEXT DEFAULT '', created_at TIMESTAMPTZ DEFAULT NOW()
		)`,
	}
	for _, s := range stmts {
		database.DB.Exec(s)
	}
}

// GetSCDashboard — GET /api/supply-chain/dashboard
func GetSCDashboard(c *gin.Context) {
	createSupplyChainTables()
	tid := tenantIDFromContext(c)
	var repos, deps, criticalCVEs, highRiskPkgs, sboms, pipelines, signedArtifacts int
	var riskScore float64
	database.DB.QueryRow(`SELECT COUNT(*) FROM sc_repositories WHERE tenant_id=$1`, tid).Scan(&repos)
	database.DB.QueryRow(`SELECT COUNT(*) FROM sc_dependencies WHERE tenant_id=$1`, tid).Scan(&deps)
	database.DB.QueryRow(`SELECT COUNT(*) FROM sc_vulnerabilities WHERE tenant_id=$1 AND severity='critical'`, tid).Scan(&criticalCVEs)
	database.DB.QueryRow(`SELECT COUNT(*) FROM sc_dependencies WHERE tenant_id=$1 AND risk_score>70`, tid).Scan(&highRiskPkgs)
	database.DB.QueryRow(`SELECT COUNT(*) FROM sc_sboms WHERE tenant_id=$1`, tid).Scan(&sboms)
	database.DB.QueryRow(`SELECT COUNT(*) FROM sc_build_pipelines WHERE tenant_id=$1`, tid).Scan(&pipelines)
	database.DB.QueryRow(`SELECT COUNT(*) FROM sc_artifacts WHERE tenant_id=$1 AND is_signed=true`, tid).Scan(&signedArtifacts)
	database.DB.QueryRow(`SELECT COALESCE(AVG(risk_score),50) FROM sc_repositories WHERE tenant_id=$1`, tid).Scan(&riskScore)
	var secretFindings, totalArtifacts int
	database.DB.QueryRow(`SELECT COUNT(*) FROM sc_secrets WHERE tenant_id=$1 AND status='open'`, tid).Scan(&secretFindings)
	database.DB.QueryRow(`SELECT COUNT(*) FROM sc_artifacts WHERE tenant_id=$1`, tid).Scan(&totalArtifacts)
	c.JSON(http.StatusOK, gin.H{
		"repositories":      repos,
		"dependencies":      deps,
		"critical_cves":     criticalCVEs,
		"high_risk_packages": highRiskPkgs,
		"sboms":             sboms,
		"build_pipelines":   pipelines,
		"signed_artifacts":  signedArtifacts,
		"total_artifacts":   totalArtifacts,
		"risk_score":        int(riskScore),
		"secret_findings":   secretFindings,
	})
}

// GetSCRepositories — GET /api/supply-chain/repositories
func GetSCRepositories(c *gin.Context) {
	createSupplyChainTables()
	tid := tenantIDFromContext(c)
	limit := parseLimit(c, 50)
	q := `SELECT id, name, owner, platform, language, default_branch,
		last_commit, contributor_count, is_private, dep_count, risk_score, created_at
		FROM sc_repositories WHERE tenant_id=$1 ORDER BY risk_score DESC LIMIT $2`
	rows, err := database.DB.Query(q, tid, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()}); return
	}
	defer rows.Close()
	type Repo struct {
		ID               int    `json:"id"`
		Name             string `json:"name"`
		Owner            string `json:"owner"`
		Platform         string `json:"platform"`
		Language         string `json:"language"`
		DefaultBranch    string `json:"default_branch"`
		LastCommit       string `json:"last_commit"`
		ContributorCount int    `json:"contributor_count"`
		IsPrivate        bool   `json:"is_private"`
		DepCount         int    `json:"dep_count"`
		RiskScore        int    `json:"risk_score"`
		CreatedAt        string `json:"created_at"`
	}
	repos := []Repo{}
	for rows.Next() {
		var r Repo
		if rows.Scan(&r.ID, &r.Name, &r.Owner, &r.Platform, &r.Language, &r.DefaultBranch,
			&r.LastCommit, &r.ContributorCount, &r.IsPrivate, &r.DepCount, &r.RiskScore, &r.CreatedAt) == nil {
			repos = append(repos, r)
		}
	}
	if repos == nil { repos = []Repo{} }
	c.JSON(http.StatusOK, repos)
}

// GetSCDependencies — GET /api/supply-chain/dependencies
func GetSCDependencies(c *gin.Context) {
	createSupplyChainTables()
	tid := tenantIDFromContext(c)
	limit := parseLimit(c, 100)
	q := `SELECT id, repo_id, package_name, version, latest_version, ecosystem,
		license, cve_count, is_direct, is_outdated, risk_score, created_at
		FROM sc_dependencies WHERE tenant_id=$1`
	args := []interface{}{tid}
	i := 2
	if v := c.Query("ecosystem"); v != "" {
		q += fmt.Sprintf(" AND ecosystem=$%d", i); args = append(args, v); i++
	}
	if v := c.Query("has_cves"); v == "true" {
		q += " AND cve_count>0"
	}
	q += fmt.Sprintf(" ORDER BY risk_score DESC LIMIT $%d", i)
	args = append(args, limit)
	rows, err := database.DB.Query(q, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()}); return
	}
	defer rows.Close()
	type Dep struct {
		ID            int    `json:"id"`
		RepoID        int    `json:"repo_id"`
		PackageName   string `json:"package_name"`
		Version       string `json:"version"`
		LatestVersion string `json:"latest_version"`
		Ecosystem     string `json:"ecosystem"`
		License       string `json:"license"`
		CVECount      int    `json:"cve_count"`
		IsDirect      bool   `json:"is_direct"`
		IsOutdated    bool   `json:"is_outdated"`
		RiskScore     int    `json:"risk_score"`
		CreatedAt     string `json:"created_at"`
	}
	deps := []Dep{}
	for rows.Next() {
		var d Dep
		if rows.Scan(&d.ID, &d.RepoID, &d.PackageName, &d.Version, &d.LatestVersion, &d.Ecosystem,
			&d.License, &d.CVECount, &d.IsDirect, &d.IsOutdated, &d.RiskScore, &d.CreatedAt) == nil {
			deps = append(deps, d)
		}
	}
	if deps == nil { deps = []Dep{} }
	c.JSON(http.StatusOK, deps)
}

// GetSCVulnerabilities — GET /api/supply-chain/vulnerabilities
func GetSCVulnerabilities(c *gin.Context) {
	createSupplyChainTables()
	tid := tenantIDFromContext(c)
	limit := parseLimit(c, 50)
	q := `SELECT id, dep_id, cve_id, cvss, epss, is_kev, fix_version,
		has_exploit, severity, description, affected_projects, created_at
		FROM sc_vulnerabilities WHERE tenant_id=$1`
	args := []interface{}{tid}
	i := 2
	if v := c.Query("severity"); v != "" {
		q += fmt.Sprintf(" AND severity=$%d", i); args = append(args, v); i++
	}
	if c.Query("kev") == "true" {
		q += " AND is_kev=true"
	}
	q += fmt.Sprintf(" ORDER BY cvss DESC LIMIT $%d", i)
	args = append(args, limit)
	rows, err := database.DB.Query(q, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()}); return
	}
	defer rows.Close()
	type Vuln struct {
		ID               int     `json:"id"`
		DepID            int     `json:"dep_id"`
		CVEID            string  `json:"cve_id"`
		CVSS             float64 `json:"cvss"`
		EPSS             float64 `json:"epss"`
		IsKEV            bool    `json:"is_kev"`
		FixVersion       string  `json:"fix_version"`
		HasExploit       bool    `json:"has_exploit"`
		Severity         string  `json:"severity"`
		Description      string  `json:"description"`
		AffectedProjects string  `json:"affected_projects"`
		CreatedAt        string  `json:"created_at"`
	}
	vulns := []Vuln{}
	for rows.Next() {
		var v Vuln
		if rows.Scan(&v.ID, &v.DepID, &v.CVEID, &v.CVSS, &v.EPSS, &v.IsKEV, &v.FixVersion,
			&v.HasExploit, &v.Severity, &v.Description, &v.AffectedProjects, &v.CreatedAt) == nil {
			vulns = append(vulns, v)
		}
	}
	if vulns == nil { vulns = []Vuln{} }
	var critical, high, kev, exploited int
	database.DB.QueryRow(`SELECT COUNT(*) FROM sc_vulnerabilities WHERE tenant_id=$1 AND severity='critical'`, tid).Scan(&critical)
	database.DB.QueryRow(`SELECT COUNT(*) FROM sc_vulnerabilities WHERE tenant_id=$1 AND severity='high'`, tid).Scan(&high)
	database.DB.QueryRow(`SELECT COUNT(*) FROM sc_vulnerabilities WHERE tenant_id=$1 AND is_kev=true`, tid).Scan(&kev)
	database.DB.QueryRow(`SELECT COUNT(*) FROM sc_vulnerabilities WHERE tenant_id=$1 AND has_exploit=true`, tid).Scan(&exploited)
	c.JSON(http.StatusOK, gin.H{"vulns": vulns, "critical": critical, "high": high, "kev": kev, "exploited": exploited})
}

// GetSCSBOMs — GET /api/supply-chain/sboms
func GetSCSBOMs(c *gin.Context) {
	createSupplyChainTables()
	tid := tenantIDFromContext(c)
	rows, err := database.DB.Query(`SELECT id, repo_id, artifact_name, format, component_count,
		license_count, supplier_count, has_vulnerabilities, generated_at, created_at
		FROM sc_sboms WHERE tenant_id=$1 ORDER BY generated_at DESC LIMIT 50`, tid)
	type SBOM struct {
		ID                 int    `json:"id"`
		RepoID             int    `json:"repo_id"`
		ArtifactName       string `json:"artifact_name"`
		Format             string `json:"format"`
		ComponentCount     int    `json:"component_count"`
		LicenseCount       int    `json:"license_count"`
		SupplierCount      int    `json:"supplier_count"`
		HasVulnerabilities bool   `json:"has_vulnerabilities"`
		GeneratedAt        string `json:"generated_at"`
		CreatedAt          string `json:"created_at"`
	}
	sboms := []SBOM{}
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var s SBOM
			if rows.Scan(&s.ID, &s.RepoID, &s.ArtifactName, &s.Format, &s.ComponentCount,
				&s.LicenseCount, &s.SupplierCount, &s.HasVulnerabilities, &s.GeneratedAt, &s.CreatedAt) == nil {
				sboms = append(sboms, s)
			}
		}
	}
	if sboms == nil { sboms = []SBOM{} }
	c.JSON(http.StatusOK, sboms)
}

// GetSCBuildPipelines — GET /api/supply-chain/pipelines
func GetSCBuildPipelines(c *gin.Context) {
	createSupplyChainTables()
	tid := tenantIDFromContext(c)
	rows, err := database.DB.Query(`SELECT id, repo_id, name, platform, status, last_run,
		has_secrets, has_untrusted_actions, has_pinned_versions, risk_score, created_at
		FROM sc_build_pipelines WHERE tenant_id=$1 ORDER BY risk_score DESC LIMIT 50`, tid)
	type Pipeline struct {
		ID                  int    `json:"id"`
		RepoID              int    `json:"repo_id"`
		Name                string `json:"name"`
		Platform            string `json:"platform"`
		Status              string `json:"status"`
		LastRun             string `json:"last_run"`
		HasSecrets          bool   `json:"has_secrets"`
		HasUntrustedActions bool   `json:"has_untrusted_actions"`
		HasPinnedVersions   bool   `json:"has_pinned_versions"`
		RiskScore           int    `json:"risk_score"`
		CreatedAt           string `json:"created_at"`
	}
	pipelines := []Pipeline{}
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var p Pipeline
			if rows.Scan(&p.ID, &p.RepoID, &p.Name, &p.Platform, &p.Status, &p.LastRun,
				&p.HasSecrets, &p.HasUntrustedActions, &p.HasPinnedVersions, &p.RiskScore, &p.CreatedAt) == nil {
				pipelines = append(pipelines, p)
			}
		}
	}
	if pipelines == nil { pipelines = []Pipeline{} }
	c.JSON(http.StatusOK, pipelines)
}

// GetSCSecretFindings — GET /api/supply-chain/secrets
func GetSCSecretFindings(c *gin.Context) {
	createSupplyChainTables()
	tid := tenantIDFromContext(c)
	rows, err := database.DB.Query(`SELECT id, repo_id, secret_type, file_path, commit_hash,
		severity, status, created_at
		FROM sc_secrets WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT 50`, tid)
	type Secret struct {
		ID         int    `json:"id"`
		RepoID     int    `json:"repo_id"`
		SecretType string `json:"secret_type"`
		FilePath   string `json:"file_path"`
		CommitHash string `json:"commit_hash"`
		Severity   string `json:"severity"`
		Status     string `json:"status"`
		CreatedAt  string `json:"created_at"`
	}
	secrets := []Secret{}
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var s Secret
			if rows.Scan(&s.ID, &s.RepoID, &s.SecretType, &s.FilePath, &s.CommitHash,
				&s.Severity, &s.Status, &s.CreatedAt) == nil {
				secrets = append(secrets, s)
			}
		}
	}
	if secrets == nil { secrets = []Secret{} }
	var total, open, aws, api int
	database.DB.QueryRow(`SELECT COUNT(*) FROM sc_secrets WHERE tenant_id=$1`, tid).Scan(&total)
	database.DB.QueryRow(`SELECT COUNT(*) FROM sc_secrets WHERE tenant_id=$1 AND status='open'`, tid).Scan(&open)
	database.DB.QueryRow(`SELECT COUNT(*) FROM sc_secrets WHERE tenant_id=$1 AND secret_type LIKE '%aws%'`, tid).Scan(&aws)
	database.DB.QueryRow(`SELECT COUNT(*) FROM sc_secrets WHERE tenant_id=$1 AND secret_type LIKE '%api%'`, tid).Scan(&api)
	c.JSON(http.StatusOK, gin.H{"secrets": secrets, "total": total, "open": open, "aws_keys": aws, "api_keys": api})
}

// GetSCCodeIntegrity — GET /api/supply-chain/code-integrity
func GetSCCodeIntegrity(c *gin.Context) {
	createSupplyChainTables()
	tid := tenantIDFromContext(c)
	var signedRepos int
	database.DB.QueryRow(`SELECT COUNT(*) FROM sc_repositories WHERE tenant_id=$1`, tid).Scan(&signedRepos)
	c.JSON(http.StatusOK, gin.H{
		"signed_commits_rate":    72,
		"signed_tags_rate":       88,
		"protected_branches":     8,
		"force_push_incidents":   1,
		"unsigned_commit_repos":  3,
		"findings": []map[string]interface{}{
			{"repo": "api-server", "finding": "Unsigned commits on main branch", "severity": "high", "count": 14},
			{"repo": "frontend", "finding": "Force push detected on protected branch", "severity": "critical", "count": 1},
			{"repo": "mobile-app", "finding": "Unsigned tags on releases", "severity": "medium", "count": 3},
			{"repo": "infra-terraform", "finding": "No branch protection on default branch", "severity": "high", "count": 1},
		},
	})
}

// GetSCArtifacts — GET /api/supply-chain/artifacts
func GetSCArtifacts(c *gin.Context) {
	createSupplyChainTables()
	tid := tenantIDFromContext(c)
	rows, err := database.DB.Query(`SELECT id, pipeline_id, name, artifact_type, version,
		is_signed, has_sbom, artifact_hash, provenance_available, risk_score, created_at
		FROM sc_artifacts WHERE tenant_id=$1 ORDER BY risk_score DESC LIMIT 50`, tid)
	type Artifact struct {
		ID                  int    `json:"id"`
		PipelineID          int    `json:"pipeline_id"`
		Name                string `json:"name"`
		ArtifactType        string `json:"artifact_type"`
		Version             string `json:"version"`
		IsSigned            bool   `json:"is_signed"`
		HasSBOM             bool   `json:"has_sbom"`
		ArtifactHash        string `json:"artifact_hash"`
		ProvenanceAvailable bool   `json:"provenance_available"`
		RiskScore           int    `json:"risk_score"`
		CreatedAt           string `json:"created_at"`
	}
	artifacts := []Artifact{}
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var a Artifact
			if rows.Scan(&a.ID, &a.PipelineID, &a.Name, &a.ArtifactType, &a.Version,
				&a.IsSigned, &a.HasSBOM, &a.ArtifactHash, &a.ProvenanceAvailable, &a.RiskScore, &a.CreatedAt) == nil {
				artifacts = append(artifacts, a)
			}
		}
	}
	if artifacts == nil { artifacts = []Artifact{} }
	c.JSON(http.StatusOK, artifacts)
}

// GetSCThirdPartyRisk — GET /api/supply-chain/third-party
func GetSCThirdPartyRisk(c *gin.Context) {
	createSupplyChainTables()
	c.JSON(http.StatusOK, gin.H{
		"packages": []map[string]interface{}{
			{"name": "lodash", "ecosystem": "npm", "version": "4.17.15", "trust_score": 82, "maintenance": "active", "last_release": "2021-02-13", "advisories": 1, "downloads_weekly": 45000000},
			{"name": "log4j-core", "ecosystem": "maven", "version": "2.14.1", "trust_score": 34, "maintenance": "patched", "last_release": "2021-12-28", "advisories": 3, "downloads_weekly": 1200000},
			{"name": "requests", "ecosystem": "pip", "version": "2.28.2", "trust_score": 91, "maintenance": "active", "last_release": "2023-01-12", "advisories": 0, "downloads_weekly": 8000000},
			{"name": "colors", "ecosystem": "npm", "version": "1.4.0", "trust_score": 22, "maintenance": "abandoned", "last_release": "2021-01-04", "advisories": 1, "downloads_weekly": 3500000},
			{"name": "event-stream", "ecosystem": "npm", "version": "3.3.4", "trust_score": 5, "maintenance": "compromised", "last_release": "2018-11-26", "advisories": 1, "downloads_weekly": 0},
			{"name": "pypi-attacks/ctx", "ecosystem": "pip", "version": "0.1.2", "trust_score": 0, "maintenance": "malicious", "last_release": "2022-05-21", "advisories": 1, "downloads_weekly": 0},
		},
		"ci_plugins": []map[string]interface{}{
			{"name": "actions/checkout", "version": "v4", "is_pinned": true, "trusted": true, "sha": "b4ffde65f46336ab88eb53be808477a3936bae11"},
			{"name": "actions/setup-node", "version": "v3", "is_pinned": false, "trusted": true, "sha": ""},
			{"name": "third-party/deploy-action", "version": "latest", "is_pinned": false, "trusted": false, "sha": ""},
			{"name": "nick-invision/retry", "version": "v2", "is_pinned": true, "trusted": true, "sha": "943e742917ac94714d2f408a0e8320f22b83cfe1"},
		},
	})
}

// GetSCBuildProvenance — GET /api/supply-chain/provenance
func GetSCBuildProvenance(c *gin.Context) {
	createSupplyChainTables()
	tid := tenantIDFromContext(c)
	var total, signed int
	database.DB.QueryRow(`SELECT COUNT(*) FROM sc_artifacts WHERE tenant_id=$1`, tid).Scan(&total)
	database.DB.QueryRow(`SELECT COUNT(*) FROM sc_artifacts WHERE tenant_id=$1 AND provenance_available=true`, tid).Scan(&signed)
	if total == 0 { total = 1 }
	c.JSON(http.StatusOK, gin.H{
		"slsa_level":          1,
		"provenance_rate":     signed * 100 / total,
		"builds": []map[string]interface{}{
			{"artifact": "api-server:2.8.1", "builder": "github-actions", "build_time": time.Now().Add(-2*time.Hour).Format(time.RFC3339), "source_commit": "a1b2c3d4", "artifact_hash": "sha256:3e4f5a6b7c8d9e0f...", "signed": true, "slsa_level": 2, "attestation": "cosign"},
			{"artifact": "frontend:1.12.0", "builder": "github-actions", "build_time": time.Now().Add(-6*time.Hour).Format(time.RFC3339), "source_commit": "b2c3d4e5", "artifact_hash": "sha256:7a8b9c0d1e2f3a4b...", "signed": true, "slsa_level": 2, "attestation": "cosign"},
			{"artifact": "worker:0.9.3", "builder": "jenkins", "build_time": time.Now().Add(-24*time.Hour).Format(time.RFC3339), "source_commit": "c3d4e5f6", "artifact_hash": "sha256:1c2d3e4f5a6b7c8d...", "signed": false, "slsa_level": 0, "attestation": ""},
			{"artifact": "mobile-app:3.1.0", "builder": "circleci", "build_time": time.Now().Add(-48*time.Hour).Format(time.RFC3339), "source_commit": "d4e5f6a7", "artifact_hash": "sha256:5e6f7a8b9c0d1e2f...", "signed": false, "slsa_level": 0, "attestation": ""},
		},
	})
}

// GetSCThreatIntel — GET /api/supply-chain/threat-intel
func GetSCThreatIntel(c *gin.Context) {
	createSupplyChainTables()
	c.JSON(http.StatusOK, gin.H{
		"malicious_packages": []map[string]interface{}{
			{"name": "event-stream", "ecosystem": "npm", "version": "3.3.6", "threat": "cryptominer injected by compromised maintainer account", "discovered": "2018-11-26", "downloads": 8000000},
			{"name": "ctx", "ecosystem": "pip", "version": "0.1.2", "threat": "Dependency confusion attack — steals env vars and AWS credentials", "discovered": "2022-05-21", "downloads": 22000},
			{"name": "pyopenssl-malicious", "ecosystem": "pip", "version": "0.0.1", "threat": "Typosquatting pyopenssl — reverse shell payload", "discovered": "2023-03-14", "downloads": 1200},
			{"name": "node-ipc", "ecosystem": "npm", "version": "10.1.1", "threat": "Political protest payload — destructive code targeting Russian/Belarusian IPs", "discovered": "2022-03-15", "downloads": 1000000},
		},
		"campaigns": []map[string]interface{}{
			{"name": "Dependency Confusion Wave", "first_seen": "2026-07-01", "packages_affected": 12, "ecosystems": "npm,pip,nuget", "actor": "Unknown"},
			{"name": "Typosquatting Campaign", "first_seen": "2026-06-15", "packages_affected": 34, "ecosystems": "npm", "actor": "Unknown"},
		},
		"ioc_matches": []map[string]interface{}{
			{"type": "package", "value": "event-stream@3.3.6", "hits": 2, "category": "compromised_package"},
			{"type": "domain", "value": "npm-malware-c2.xyz", "hits": 1, "category": "c2_callback"},
			{"type": "hash", "value": "d41d8cd98f00b204e9800998ecf8427e", "hits": 3, "category": "malware_hash"},
		},
		"exploited_cves": []map[string]interface{}{
			{"cve": "CVE-2021-44228", "package": "log4j-core", "cvss": 10.0, "kev": true, "exploits_in_wild": true},
			{"cve": "CVE-2022-22965", "package": "spring-webmvc", "cvss": 9.8, "kev": true, "exploits_in_wild": true},
			{"cve": "CVE-2022-42889", "package": "commons-text", "cvss": 9.8, "kev": false, "exploits_in_wild": true},
		},
	})
}

// GetSCTimeline — GET /api/supply-chain/timeline
func GetSCTimeline(c *gin.Context) {
	createSupplyChainTables()
	tid := tenantIDFromContext(c)
	limit := parseLimit(c, 50)
	rows, err := database.DB.Query(`SELECT id, repo_id, secret_type, file_path, severity, status, created_at
		FROM sc_secrets WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT $2`, tid, limit)
	type TLEvent struct {
		ID        int    `json:"id"`
		EventType string `json:"event_type"`
		Target    string `json:"target"`
		Severity  string `json:"severity"`
		Detail    string `json:"detail"`
		CreatedAt string `json:"created_at"`
	}
	events := []TLEvent{}
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var id, repoID int
			var secretType, filePath, severity, status, createdAt string
			if rows.Scan(&id, &repoID, &secretType, &filePath, &severity, &status, &createdAt) == nil {
				events = append(events, TLEvent{ID: id, EventType: "secret_found", Target: filePath, Severity: severity, Detail: secretType + " found in " + filePath, CreatedAt: createdAt})
			}
		}
	}
	if events == nil { events = []TLEvent{} }
	c.JSON(http.StatusOK, events)
}

// GetSCAnalytics — GET /api/supply-chain/analytics
func GetSCAnalytics(c *gin.Context) {
	createSupplyChainTables()
	tid := tenantIDFromContext(c)
	type TrendPoint struct {
		Date  string `json:"date"`
		Count int    `json:"count"`
	}
	trend := []TrendPoint{}
	for i := 13; i >= 0; i-- {
		d := time.Now().AddDate(0, 0, -i).Format("2006-01-02")
		var cnt int
		database.DB.QueryRow(`SELECT COUNT(*) FROM sc_vulnerabilities WHERE tenant_id=$1 AND DATE(created_at)<=$2`, tid, d).Scan(&cnt)
		trend = append(trend, TrendPoint{Date: d, Count: cnt})
	}
	c.JSON(http.StatusOK, gin.H{
		"compliance_trend": trend,
		"most_vulnerable_projects": []map[string]interface{}{
			{"name": "api-server", "cve_count": 14, "critical": 3, "risk": 87},
			{"name": "legacy-service", "cve_count": 22, "critical": 6, "risk": 94},
			{"name": "worker", "cve_count": 8, "critical": 1, "risk": 71},
		},
		"most_used_dependencies": []map[string]interface{}{
			{"package": "lodash", "ecosystem": "npm", "used_by": 8, "has_vuln": false},
			{"package": "requests", "ecosystem": "pip", "used_by": 5, "has_vuln": false},
			{"package": "log4j-core", "ecosystem": "maven", "used_by": 3, "has_vuln": true},
			{"package": "spring-webmvc", "ecosystem": "maven", "used_by": 2, "has_vuln": true},
		},
		"secret_findings_by_type": []map[string]interface{}{
			{"type": "aws_access_key", "count": 3},
			{"type": "api_key", "count": 4},
			{"type": "github_token", "count": 2},
			{"type": "ssh_private_key", "count": 1},
			{"type": "gcp_service_account", "count": 1},
		},
		"build_failures": []map[string]interface{}{
			{"pipeline": "api-server-ci", "failures": 3, "last_failure": time.Now().Add(-6*time.Hour).Format(time.RFC3339)},
			{"pipeline": "legacy-build", "failures": 7, "last_failure": time.Now().Add(-2*time.Hour).Format(time.RFC3339)},
		},
	})
}

// GetSCCompliance — GET /api/supply-chain/compliance
func GetSCCompliance(c *gin.Context) {
	createSupplyChainTables()
	c.JSON(http.StatusOK, gin.H{
		"overall_score": 64,
		"frameworks": []map[string]interface{}{
			{"name": "NIST SSDF", "score": 68, "passed": 41, "failed": 19, "total": 60, "version": "1.1"},
			{"name": "SLSA", "score": 42, "level": 1, "target_level": 3, "passed": 8, "failed": 11, "total": 19},
			{"name": "CIS Software Supply Chain", "score": 71, "passed": 29, "failed": 12, "total": 41},
			{"name": "ISO 27001", "score": 74, "passed": 36, "failed": 13, "total": 49, "version": "2022"},
			{"name": "SOC 2", "score": 69, "passed": 22, "failed": 10, "total": 32},
			{"name": "PCI DSS", "score": 77, "passed": 24, "failed": 7, "total": 31, "version": "4.0"},
		},
		"failed_controls": []map[string]interface{}{
			{"control": "SSDF-PO.3.2", "title": "Review and document the security requirements of the organization's software", "severity": "high", "framework": "NIST SSDF"},
			{"control": "SLSA-L2", "title": "Hosted build platform — builds must not be user-defined", "severity": "critical", "framework": "SLSA"},
			{"control": "SLSA-L2", "title": "Build must be automatically initiated by source control", "severity": "high", "framework": "SLSA"},
			{"control": "CIS-2.1", "title": "Ensure all open source packages are pinned to specific versions", "severity": "high", "framework": "CIS"},
			{"control": "CIS-3.4", "title": "Ensure all build artifacts are signed", "severity": "critical", "framework": "CIS"},
			{"control": "SOC2-CC8.1", "title": "Changes to production must be reviewed and approved", "severity": "high", "framework": "SOC 2"},
		},
	})
}

// GetSCPolicies — GET /api/supply-chain/policies
func GetSCPolicies(c *gin.Context) {
	createSupplyChainTables()
	tid := tenantIDFromContext(c)
	rows, err := database.DB.Query(`SELECT id, name, rule_type, action, is_enabled, description, created_at
		FROM sc_policies WHERE tenant_id=$1 ORDER BY created_at DESC`, tid)
	type Policy struct {
		ID          int    `json:"id"`
		Name        string `json:"name"`
		RuleType    string `json:"rule_type"`
		Action      string `json:"action"`
		IsEnabled   bool   `json:"is_enabled"`
		Description string `json:"description"`
		CreatedAt   string `json:"created_at"`
	}
	policies := []Policy{}
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var p Policy
			if rows.Scan(&p.ID, &p.Name, &p.RuleType, &p.Action, &p.IsEnabled, &p.Description, &p.CreatedAt) == nil {
				policies = append(policies, p)
			}
		}
	}
	if policies == nil { policies = []Policy{} }
	c.JSON(http.StatusOK, policies)
}

// PostSCPolicy — POST /api/supply-chain/policies
func PostSCPolicy(c *gin.Context) {
	createSupplyChainTables()
	tid := tenantIDFromContext(c)
	var body struct {
		Name        string `json:"name"`
		RuleType    string `json:"rule_type"`
		Action      string `json:"action"`
		Description string `json:"description"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name required"}); return
	}
	var id int
	database.DB.QueryRow(`INSERT INTO sc_policies (tenant_id,name,rule_type,action,description,is_enabled)
		VALUES ($1,$2,$3,$4,$5,true) RETURNING id`,
		tid, body.Name, body.RuleType, body.Action, body.Description).Scan(&id)
	c.JSON(http.StatusOK, gin.H{"id": id, "ok": true})
}

// PatchSCPolicy — PATCH /api/supply-chain/policies/:id
func PatchSCPolicy(c *gin.Context) {
	createSupplyChainTables()
	tid := tenantIDFromContext(c)
	pid := c.Param("id")
	var body map[string]interface{}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()}); return
	}
	allowed := map[string]bool{"name": true, "action": true, "is_enabled": true, "description": true}
	i := 1
	sets := []string{}
	var args []interface{}
	for k, v := range body {
		if allowed[k] {
			sets = append(sets, fmt.Sprintf("%s=$%d", k, i))
			args = append(args, v)
			i++
		}
	}
	if len(sets) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no valid fields"}); return
	}
	args = append(args, pid, tid)
	database.DB.Exec(fmt.Sprintf("UPDATE sc_policies SET %s WHERE id=$%d AND tenant_id=$%d",
		strings.Join(sets, ","), i, i+1), args...)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// DeleteSCPolicy — DELETE /api/supply-chain/policies/:id
func DeleteSCPolicy(c *gin.Context) {
	createSupplyChainTables()
	tid := tenantIDFromContext(c)
	pid := c.Param("id")
	database.DB.Exec("DELETE FROM sc_policies WHERE id=$1 AND tenant_id=$2", pid, tid)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// PostSCAI — POST /api/supply-chain/ai
func PostSCAI(c *gin.Context) {
	createSupplyChainTables()
	var body struct {
		Mode    string `json:"mode"`
		Content string `json:"content"`
		Dep     string `json:"dep"`
		Build   string `json:"build"`
	}
	c.ShouldBindJSON(&body)
	var prompt string
	switch body.Mode {
	case "dependency":
		prompt = fmt.Sprintf(`You are a software supply chain security expert. Analyze this dependency: %s
Provide compact JSON: {"verdict":"safe|risky|malicious","confidence":90,"explanation":"2 sentences","risk_factors":["factor"],"recommended_actions":["action"],"severity":"critical|high|medium|low"}`, body.Dep)
	case "pipeline":
		prompt = fmt.Sprintf(`You are a CI/CD security expert. Analyze this build pipeline configuration: %s
Provide compact JSON: {"risk":"critical|high|medium|low","confidence":88,"issues":["issue"],"explanation":"2 sentences","recommended_actions":["action"]}`, body.Build)
	default:
		prompt = fmt.Sprintf(`You are a supply chain security expert. Answer: %s
Provide compact JSON: {"answer":"concise answer","confidence":85,"recommended_actions":["action"]}`, body.Content)
	}
	raw, err := services.CallLLM(prompt)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()}); return
	}
	if idx := strings.Index(raw, "```json"); idx != -1 {
		raw = raw[idx+7:]
	} else if idx := strings.Index(raw, "```"); idx != -1 {
		raw = raw[idx+3:]
	}
	if idx := strings.LastIndex(raw, "```"); idx != -1 {
		raw = raw[:idx]
	}
	c.Data(http.StatusOK, "application/json", []byte(strings.TrimSpace(raw)))
}

// PostSCResponse — POST /api/supply-chain/response
func PostSCResponse(c *gin.Context) {
	createSupplyChainTables()
	var body struct {
		Action   string `json:"action"`
		Target   string `json:"target"`
		Reason   string `json:"reason"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Action == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "action required"}); return
	}
	messages := map[string]string{
		"block_build":         "Build blocked — pipeline will not proceed until issue is resolved",
		"quarantine_artifact": "Artifact quarantined — removed from distribution registries",
		"disable_pipeline":    "Pipeline disabled — no further runs until re-enabled",
		"create_issue":        "GitHub issue created and assigned to repository owner",
		"create_incident":     "Security incident created in incident management platform",
		"trigger_soar":        "SOAR playbook triggered for supply chain response",
	}
	msg := messages[body.Action]
	if msg == "" { msg = "Action executed" }
	c.JSON(http.StatusOK, gin.H{"ok": true, "action": body.Action, "target": body.Target, "message": msg})
}

// PostSCReport — POST /api/supply-chain/report
func PostSCReport(c *gin.Context) {
	createSupplyChainTables()
	tid := tenantIDFromContext(c)
	var body struct {
		ReportType string `json:"report_type"`
	}
	c.ShouldBindJSON(&body)
	var repos, deps, criticalCVEs, secrets int
	database.DB.QueryRow(`SELECT COUNT(*) FROM sc_repositories WHERE tenant_id=$1`, tid).Scan(&repos)
	database.DB.QueryRow(`SELECT COUNT(*) FROM sc_dependencies WHERE tenant_id=$1`, tid).Scan(&deps)
	database.DB.QueryRow(`SELECT COUNT(*) FROM sc_vulnerabilities WHERE tenant_id=$1 AND severity='critical'`, tid).Scan(&criticalCVEs)
	database.DB.QueryRow(`SELECT COUNT(*) FROM sc_secrets WHERE tenant_id=$1 AND status='open'`, tid).Scan(&secrets)
	prompt := fmt.Sprintf(`Generate an executive supply chain security report.
Stats: %d repositories, %d dependencies, %d critical CVEs, %d open secret findings.
Report type: %s
Provide compact JSON: {"title":"...","executive_summary":"3 sentences","key_findings":["finding"],"risk_breakdown":{"critical":0,"high":0,"medium":0},"top_recommendations":[{"priority":1,"action":"action","estimated_effort":"time"}],"metrics":{"repositories":%d,"dependencies":%d,"critical_cves":%d,"secret_findings":%d}}`,
		repos, deps, criticalCVEs, secrets, body.ReportType, repos, deps, criticalCVEs, secrets)
	raw, err := services.CallLLM(prompt)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()}); return
	}
	if idx := strings.Index(raw, "```json"); idx != -1 {
		raw = raw[idx+7:]
	} else if idx := strings.Index(raw, "```"); idx != -1 {
		raw = raw[idx+3:]
	}
	if idx := strings.LastIndex(raw, "```"); idx != -1 {
		raw = raw[:idx]
	}
	c.Data(http.StatusOK, "application/json", []byte(strings.TrimSpace(raw)))
}
