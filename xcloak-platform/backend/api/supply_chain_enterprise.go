package api

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"xcloak-platform/database"
	"xcloak-platform/models"
	"xcloak-platform/repositories"
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
		"repositories":       repos,
		"dependencies":       deps,
		"critical_cves":      criticalCVEs,
		"high_risk_packages": highRiskPkgs,
		"sboms":              sboms,
		"build_pipelines":    pipelines,
		"signed_artifacts":   signedArtifacts,
		"total_artifacts":    totalArtifacts,
		"risk_score":         int(riskScore),
		"secret_findings":    secretFindings,
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
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
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
	if repos == nil {
		repos = []Repo{}
	}
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
		q += fmt.Sprintf(" AND ecosystem=$%d", i)
		args = append(args, v)
		i++
	}
	if v := c.Query("has_cves"); v == "true" {
		q += " AND cve_count>0"
	}
	q += fmt.Sprintf(" ORDER BY risk_score DESC LIMIT $%d", i)
	args = append(args, limit)
	rows, err := database.DB.Query(q, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
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
	if deps == nil {
		deps = []Dep{}
	}
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
		q += fmt.Sprintf(" AND severity=$%d", i)
		args = append(args, v)
		i++
	}
	if c.Query("kev") == "true" {
		q += " AND is_kev=true"
	}
	q += fmt.Sprintf(" ORDER BY cvss DESC LIMIT $%d", i)
	args = append(args, limit)
	rows, err := database.DB.Query(q, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
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
	if vulns == nil {
		vulns = []Vuln{}
	}
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
	if sboms == nil {
		sboms = []SBOM{}
	}
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
	if pipelines == nil {
		pipelines = []Pipeline{}
	}
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
	if secrets == nil {
		secrets = []Secret{}
	}
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
	var totalRepos int
	database.DB.QueryRow(`SELECT COUNT(*) FROM sc_repositories WHERE tenant_id=$1`, tid).Scan(&totalRepos)
	// This schema has no per-repo commit-signing / branch-protection tracking table,
	// so report honest zeros and an empty findings list instead of fabricated repo data.
	c.JSON(http.StatusOK, gin.H{
		"total_repositories":    totalRepos,
		"signed_commits_rate":   0,
		"signed_tags_rate":      0,
		"protected_branches":    0,
		"force_push_incidents":  0,
		"unsigned_commit_repos": 0,
		"findings":              []map[string]interface{}{},
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
	if artifacts == nil {
		artifacts = []Artifact{}
	}
	c.JSON(http.StatusOK, artifacts)
}

// GetSCThirdPartyRisk — GET /api/supply-chain/third-party
func GetSCThirdPartyRisk(c *gin.Context) {
	createSupplyChainTables()
	tid := tenantIDFromContext(c)
	rows, err := database.DB.Query(`SELECT package_name, ecosystem, version, license, cve_count, is_outdated, risk_score
		FROM sc_dependencies WHERE tenant_id=$1 ORDER BY risk_score DESC LIMIT 50`, tid)
	type Pkg struct {
		Name       string `json:"name"`
		Ecosystem  string `json:"ecosystem"`
		Version    string `json:"version"`
		License    string `json:"license"`
		CVECount   int    `json:"advisories"`
		IsOutdated bool   `json:"is_outdated"`
		TrustScore int    `json:"trust_score"`
	}
	packages := []Pkg{}
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var p Pkg
			var riskScore int
			if rows.Scan(&p.Name, &p.Ecosystem, &p.Version, &p.License, &p.CVECount, &p.IsOutdated, &riskScore) == nil {
				p.TrustScore = 100 - riskScore
				if p.TrustScore < 0 {
					p.TrustScore = 0
				}
				packages = append(packages, p)
			}
		}
	}
	// No real CI-plugin/action inventory table exists in this schema; report an
	// honest empty list rather than fabricated plugin names.
	c.JSON(http.StatusOK, gin.H{
		"packages":   packages,
		"ci_plugins": []map[string]interface{}{},
	})
}

// GetSCBuildProvenance — GET /api/supply-chain/provenance
func GetSCBuildProvenance(c *gin.Context) {
	createSupplyChainTables()
	tid := tenantIDFromContext(c)
	var total, signed, withProvenance int
	database.DB.QueryRow(`SELECT COUNT(*) FROM sc_artifacts WHERE tenant_id=$1`, tid).Scan(&total)
	database.DB.QueryRow(`SELECT COUNT(*) FROM sc_artifacts WHERE tenant_id=$1 AND is_signed=true`, tid).Scan(&signed)
	database.DB.QueryRow(`SELECT COUNT(*) FROM sc_artifacts WHERE tenant_id=$1 AND provenance_available=true`, tid).Scan(&withProvenance)

	rows, err := database.DB.Query(`SELECT name, artifact_type, version, is_signed, has_sbom,
		artifact_hash, provenance_available, created_at
		FROM sc_artifacts WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT 50`, tid)
	type Build struct {
		Artifact     string `json:"artifact"`
		ArtifactType string `json:"artifact_type"`
		BuildTime    string `json:"build_time"`
		ArtifactHash string `json:"artifact_hash"`
		Signed       bool   `json:"signed"`
		HasSBOM      bool   `json:"has_sbom"`
		Provenance   bool   `json:"provenance_available"`
	}
	builds := []Build{}
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var name, atype, version, hash, createdAt string
			var isSigned, hasSBOM, provAvail bool
			if rows.Scan(&name, &atype, &version, &isSigned, &hasSBOM, &hash, &provAvail, &createdAt) == nil {
				builds = append(builds, Build{
					Artifact: name + ":" + version, ArtifactType: atype, BuildTime: createdAt,
					ArtifactHash: hash, Signed: isSigned, HasSBOM: hasSBOM, Provenance: provAvail,
				})
			}
		}
	}

	slsaLevel := 0
	provenanceRate := 0
	if total > 0 {
		provenanceRate = withProvenance * 100 / total
		switch {
		case withProvenance == total && signed == total:
			slsaLevel = 3
		case withProvenance > 0:
			slsaLevel = 2
		case signed > 0:
			slsaLevel = 1
		}
	}
	c.JSON(http.StatusOK, gin.H{
		"slsa_level":      slsaLevel,
		"provenance_rate": provenanceRate,
		"builds":          builds,
	})
}

// GetSCThreatIntel — GET /api/supply-chain/threat-intel
func GetSCThreatIntel(c *gin.Context) {
	createSupplyChainTables()
	tid := tenantIDFromContext(c)

	// Publicly known malicious/compromised package incidents, used only as
	// match criteria against this tenant's real dependency inventory below.
	knownMalicious := []map[string]interface{}{
		{"name": "event-stream", "ecosystem": "npm", "version": "3.3.6", "threat": "cryptominer injected by compromised maintainer account", "discovered": "2018-11-26", "downloads": 8000000},
		{"name": "ctx", "ecosystem": "pip", "version": "0.1.2", "threat": "Dependency confusion attack — steals env vars and AWS credentials", "discovered": "2022-05-21", "downloads": 22000},
		{"name": "pyopenssl-malicious", "ecosystem": "pip", "version": "0.0.1", "threat": "Typosquatting pyopenssl — reverse shell payload", "discovered": "2023-03-14", "downloads": 1200},
		{"name": "node-ipc", "ecosystem": "npm", "version": "10.1.1", "threat": "Political protest payload — destructive code targeting Russian/Belarusian IPs", "discovered": "2022-03-15", "downloads": 1000000},
	}
	exploitedCVEs := []map[string]interface{}{
		{"cve": "CVE-2021-44228", "package": "log4j-core", "cvss": 10.0, "kev": true, "exploits_in_wild": true},
		{"cve": "CVE-2022-22965", "package": "spring-webmvc", "cvss": 9.8, "kev": true, "exploits_in_wild": true},
		{"cve": "CVE-2022-42889", "package": "commons-text", "cvss": 9.8, "kev": false, "exploits_in_wild": true},
	}

	// Real per-tenant IOC matching: check this tenant's actual sc_dependencies
	// rows against the known-malicious package names above. Only emit a match
	// when a real row for this tenant exists — no placeholder rows.
	iocMatches := []map[string]interface{}{}
	for _, m := range knownMalicious {
		name, _ := m["name"].(string)
		var count int
		database.DB.QueryRow(`SELECT COUNT(*) FROM sc_dependencies WHERE tenant_id=$1 AND package_name=$2`, tid, name).Scan(&count)
		if count > 0 {
			iocMatches = append(iocMatches, map[string]interface{}{
				"type": "package", "value": name, "hits": count, "category": "known_malicious_package",
			})
		}
	}

	// No real campaign-tracking table exists in this schema; report an honest
	// empty list rather than fabricated campaign data.
	c.JSON(http.StatusOK, gin.H{
		"malicious_packages": knownMalicious,
		"campaigns":          []map[string]interface{}{},
		"ioc_matches":        iocMatches,
		"exploited_cves":     exploitedCVEs,
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
	if events == nil {
		events = []TLEvent{}
	}
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
	type projRow struct {
		Name     string `json:"name"`
		CVECount int    `json:"cve_count"`
		Critical int    `json:"critical"`
		Risk     int    `json:"risk"`
	}
	mostVulnerableProjects := []projRow{}
	prows, _ := database.DB.Query(`
		SELECT r.name, COUNT(v.id) AS cve_count,
			COUNT(*) FILTER (WHERE v.severity='critical') AS critical,
			COALESCE(AVG(r.risk_score),0) AS risk
		FROM sc_vulnerabilities v
		JOIN sc_dependencies d ON d.id=v.dep_id AND d.tenant_id=v.tenant_id
		JOIN sc_repositories r ON r.id=d.repo_id AND r.tenant_id=v.tenant_id
		WHERE v.tenant_id=$1
		GROUP BY r.name ORDER BY cve_count DESC LIMIT 10`, tid)
	if prows != nil {
		defer prows.Close()
		for prows.Next() {
			var p projRow
			if prows.Scan(&p.Name, &p.CVECount, &p.Critical, &p.Risk) == nil {
				mostVulnerableProjects = append(mostVulnerableProjects, p)
			}
		}
	}

	type depRow struct {
		Package   string `json:"package"`
		Ecosystem string `json:"ecosystem"`
		UsedBy    int    `json:"used_by"`
		HasVuln   bool   `json:"has_vuln"`
	}
	mostUsedDependencies := []depRow{}
	drows, _ := database.DB.Query(`
		SELECT package_name, ecosystem, COUNT(DISTINCT repo_id) AS used_by, BOOL_OR(cve_count>0) AS has_vuln
		FROM sc_dependencies WHERE tenant_id=$1
		GROUP BY package_name, ecosystem ORDER BY used_by DESC LIMIT 10`, tid)
	if drows != nil {
		defer drows.Close()
		for drows.Next() {
			var d depRow
			if drows.Scan(&d.Package, &d.Ecosystem, &d.UsedBy, &d.HasVuln) == nil {
				mostUsedDependencies = append(mostUsedDependencies, d)
			}
		}
	}

	type secretTypeRow struct {
		Type  string `json:"type"`
		Count int    `json:"count"`
	}
	secretFindingsByType := []secretTypeRow{}
	srows, _ := database.DB.Query(`
		SELECT secret_type, COUNT(*) FROM sc_secrets WHERE tenant_id=$1
		GROUP BY secret_type ORDER BY COUNT(*) DESC`, tid)
	if srows != nil {
		defer srows.Close()
		for srows.Next() {
			var s secretTypeRow
			if srows.Scan(&s.Type, &s.Count) == nil {
				secretFindingsByType = append(secretFindingsByType, s)
			}
		}
	}

	type buildFailureRow struct {
		Pipeline    string `json:"pipeline"`
		LastFailure string `json:"last_failure"`
	}
	buildFailures := []buildFailureRow{}
	brows, _ := database.DB.Query(`
		SELECT name, last_run FROM sc_build_pipelines
		WHERE tenant_id=$1 AND status NOT IN ('passing','success')
		ORDER BY last_run DESC LIMIT 10`, tid)
	if brows != nil {
		defer brows.Close()
		for brows.Next() {
			var b buildFailureRow
			if brows.Scan(&b.Pipeline, &b.LastFailure) == nil {
				buildFailures = append(buildFailures, b)
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"compliance_trend":         trend,
		"most_vulnerable_projects": mostVulnerableProjects,
		"most_used_dependencies":   mostUsedDependencies,
		"secret_findings_by_type":  secretFindingsByType,
		"build_failures":           buildFailures,
	})
}

// GetSCCompliance — GET /api/supply-chain/compliance
func GetSCCompliance(c *gin.Context) {
	createSupplyChainTables()
	createFCETables()
	tid := tenantIDFromContext(c)
	db := database.DB

	type fwRow struct {
		Name   string `json:"name"`
		Score  int    `json:"score"`
		Passed int    `json:"passed"`
		Failed int    `json:"failed"`
		Total  int    `json:"total"`
		Status string `json:"status"`
	}
	frows, _ := db.Query(`SELECT name, overall_score, passed_controls, failed_controls, total_controls, compliance_status
		FROM fce_frameworks WHERE tenant_id=$1 AND is_active=TRUE ORDER BY overall_score ASC`, tid)
	frameworks := []fwRow{}
	if frows != nil {
		defer frows.Close()
		for frows.Next() {
			var r fwRow
			if frows.Scan(&r.Name, &r.Score, &r.Passed, &r.Failed, &r.Total, &r.Status) == nil {
				frameworks = append(frameworks, r)
			}
		}
	}

	var overallScore float64
	db.QueryRow(`SELECT COALESCE(AVG(overall_score),0) FROM fce_frameworks WHERE tenant_id=$1 AND is_active=TRUE`, tid).Scan(&overallScore)

	type ctrlRow struct {
		Control   string `json:"control"`
		Title     string `json:"title"`
		Severity  string `json:"severity"`
		Framework string `json:"framework"`
	}
	crows, _ := db.Query(`SELECT c.control_id, c.name, c.risk_level, f.name
		FROM fce_controls c JOIN fce_frameworks f ON f.id=c.framework_id
		WHERE c.tenant_id=$1 AND c.assessment_status='failed'
		ORDER BY CASE c.risk_level WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END LIMIT 20`, tid)
	failedControls := []ctrlRow{}
	if crows != nil {
		defer crows.Close()
		for crows.Next() {
			var r ctrlRow
			if crows.Scan(&r.Control, &r.Title, &r.Severity, &r.Framework) == nil {
				failedControls = append(failedControls, r)
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"overall_score":   int(overallScore),
		"frameworks":      frameworks,
		"failed_controls": failedControls,
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
	if policies == nil {
		policies = []Policy{}
	}
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
		c.JSON(http.StatusBadRequest, gin.H{"error": "name required"})
		return
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
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
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
		c.JSON(http.StatusBadRequest, gin.H{"error": "no valid fields"})
		return
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
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
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
	tid := tenantIDFromContext(c)
	var body struct {
		Action string `json:"action"`
		Target string `json:"target"`
		Reason string `json:"reason"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Action == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "action required"})
		return
	}

	switch body.Action {
	case "block_build":
		if body.Target == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "target required"})
			return
		}
		res, _ := database.DB.Exec(`UPDATE sc_build_pipelines SET status='blocked' WHERE tenant_id=$1 AND name=$2`, tid, body.Target)
		if n, _ := res.RowsAffected(); n == 0 {
			c.JSON(http.StatusNotFound, gin.H{"error": "no matching pipeline found"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true, "action": body.Action, "target": body.Target, "message": "Build blocked — pipeline will not proceed until issue is resolved"})
	case "disable_pipeline":
		if body.Target == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "target required"})
			return
		}
		res, _ := database.DB.Exec(`UPDATE sc_build_pipelines SET status='disabled' WHERE tenant_id=$1 AND name=$2`, tid, body.Target)
		if n, _ := res.RowsAffected(); n == 0 {
			c.JSON(http.StatusNotFound, gin.H{"error": "no matching pipeline found"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true, "action": body.Action, "target": body.Target, "message": "Pipeline disabled — no further runs until re-enabled"})
	case "quarantine_artifact":
		if body.Target == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "target required"})
			return
		}
		var hash string
		database.DB.QueryRow(`SELECT artifact_hash FROM sc_artifacts WHERE tenant_id=$1 AND name=$2 AND artifact_hash != ''`, tid, body.Target).Scan(&hash)
		if hash == "" {
			c.JSON(http.StatusNotFound, gin.H{"error": "no matching artifact with a known hash found"})
			return
		}
		if err := repositories.CreateIOC(models.IOC{
			Indicator: hash, Type: services.GuessIOCType(hash), Severity: "high", Enabled: true,
			Description: "Quarantined via Supply Chain Security",
		}, tid); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true, "action": body.Action, "target": body.Target, "message": "Artifact quarantined — hash blocked from distribution"})
	case "create_incident":
		var incidentID int
		if err := database.DB.QueryRow(`
			INSERT INTO incidents (tenant_id, title, description, severity, status)
			VALUES ($1,$2,$3,'high','open') RETURNING id`,
			tid, "Supply Chain Escalation: "+body.Target,
			fmt.Sprintf("Escalated from Supply Chain Security. Target: %s, Reason: %s", body.Target, body.Reason),
		).Scan(&incidentID); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true, "action": body.Action, "target": body.Target, "message": fmt.Sprintf("Security incident #%d created", incidentID)})
	case "create_issue":
		c.JSON(http.StatusNotImplemented, gin.H{"error": "no real GitHub/GitLab API integration configured for this action"})
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "unknown action"})
	}
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
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
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
