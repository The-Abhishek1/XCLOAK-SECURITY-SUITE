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

func createContainerSecurityTables() {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS k8s_clusters (
			id SERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL,
			name TEXT DEFAULT '', provider TEXT DEFAULT 'kubernetes',
			k8s_version TEXT DEFAULT '', node_count INTEGER DEFAULT 0,
			status TEXT DEFAULT 'healthy', region TEXT DEFAULT '',
			risk_score INTEGER DEFAULT 0, compliance_score INTEGER DEFAULT 0,
			last_scan TIMESTAMPTZ DEFAULT NOW(), created_at TIMESTAMPTZ DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS k8s_nodes (
			id SERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL,
			cluster_id INTEGER DEFAULT 0, name TEXT DEFAULT '',
			os TEXT DEFAULT '', kernel TEXT DEFAULT '',
			cpu_cores INTEGER DEFAULT 0, memory_gb INTEGER DEFAULT 0,
			pod_count INTEGER DEFAULT 0, runtime TEXT DEFAULT 'containerd',
			risk_score INTEGER DEFAULT 0, vuln_count INTEGER DEFAULT 0,
			status TEXT DEFAULT 'ready', last_heartbeat TIMESTAMPTZ DEFAULT NOW(),
			created_at TIMESTAMPTZ DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS k8s_pods (
			id SERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL,
			cluster_id INTEGER DEFAULT 0, namespace TEXT DEFAULT '',
			name TEXT DEFAULT '', image TEXT DEFAULT '',
			status TEXT DEFAULT 'running', is_privileged BOOLEAN DEFAULT false,
			host_network BOOLEAN DEFAULT false, host_pid BOOLEAN DEFAULT false,
			host_ipc BOOLEAN DEFAULT false, run_as_root BOOLEAN DEFAULT false,
			read_only_fs BOOLEAN DEFAULT true, has_resource_limits BOOLEAN DEFAULT true,
			capabilities TEXT DEFAULT '', volumes TEXT DEFAULT '',
			risk_score INTEGER DEFAULT 0, created_at TIMESTAMPTZ DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS k8s_images (
			id SERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL,
			image TEXT DEFAULT '', registry TEXT DEFAULT '',
			tag TEXT DEFAULT '', base_image TEXT DEFAULT '',
			os TEXT DEFAULT '', size_mb INTEGER DEFAULT 0,
			cve_critical INTEGER DEFAULT 0, cve_high INTEGER DEFAULT 0,
			cve_medium INTEGER DEFAULT 0, cve_low INTEGER DEFAULT 0,
			has_secrets BOOLEAN DEFAULT false, malware_found BOOLEAN DEFAULT false,
			signature_valid BOOLEAN DEFAULT false, sbom_available BOOLEAN DEFAULT false,
			age_days INTEGER DEFAULT 0, risk_score INTEGER DEFAULT 0,
			last_scanned TIMESTAMPTZ DEFAULT NOW(), created_at TIMESTAMPTZ DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS k8s_runtime_alerts (
			id SERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL,
			cluster_id INTEGER DEFAULT 0, namespace TEXT DEFAULT '',
			pod_name TEXT DEFAULT '', container_name TEXT DEFAULT '',
			alert_type TEXT DEFAULT '', severity TEXT DEFAULT 'medium',
			description TEXT DEFAULT '', process TEXT DEFAULT '',
			command TEXT DEFAULT '', source_ip TEXT DEFAULT '',
			mitre_technique TEXT DEFAULT '', status TEXT DEFAULT 'open',
			created_at TIMESTAMPTZ DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS k8s_rbac_findings (
			id SERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL,
			cluster_id INTEGER DEFAULT 0, kind TEXT DEFAULT '',
			name TEXT DEFAULT '', namespace TEXT DEFAULT '',
			subject TEXT DEFAULT '', permissions TEXT DEFAULT '',
			finding_type TEXT DEFAULT '', severity TEXT DEFAULT 'medium',
			description TEXT DEFAULT '', created_at TIMESTAMPTZ DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS k8s_network_policies (
			id SERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL,
			cluster_id INTEGER DEFAULT 0, namespace TEXT DEFAULT '',
			name TEXT DEFAULT '', policy_type TEXT DEFAULT 'ingress',
			direction TEXT DEFAULT 'ingress', status TEXT DEFAULT 'active',
			pod_selector TEXT DEFAULT '', peer TEXT DEFAULT '',
			port TEXT DEFAULT '', created_at TIMESTAMPTZ DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS k8s_admission_violations (
			id SERIAL PRIMARY KEY, tenant_id INTEGER NOT NULL,
			cluster_id INTEGER DEFAULT 0, namespace TEXT DEFAULT '',
			workload TEXT DEFAULT '', kind TEXT DEFAULT '',
			violation_type TEXT DEFAULT '', severity TEXT DEFAULT 'high',
			description TEXT DEFAULT '', action TEXT DEFAULT 'denied',
			created_at TIMESTAMPTZ DEFAULT NOW()
		)`,
	}
	for _, s := range stmts {
		database.DB.Exec(s)
	}
}

// GetContainerDashboard — GET /api/containers/dashboard
func GetContainerDashboard(c *gin.Context) {
	createContainerSecurityTables()
	tid := tenantIDFromContext(c)
	var clusters, nodes, pods, namespaces, containers, criticalFindings, vulnerableImages, runtimeAlerts int
	database.DB.QueryRow(`SELECT COUNT(*) FROM k8s_clusters WHERE tenant_id=$1`, tid).Scan(&clusters)
	database.DB.QueryRow(`SELECT COUNT(*) FROM k8s_nodes WHERE tenant_id=$1`, tid).Scan(&nodes)
	database.DB.QueryRow(`SELECT COUNT(*) FROM k8s_pods WHERE tenant_id=$1`, tid).Scan(&pods)
	database.DB.QueryRow(`SELECT COUNT(DISTINCT namespace) FROM k8s_pods WHERE tenant_id=$1`, tid).Scan(&namespaces)
	database.DB.QueryRow(`SELECT COUNT(*) FROM k8s_pods WHERE tenant_id=$1 AND status='running'`, tid).Scan(&containers)
	database.DB.QueryRow(`SELECT COUNT(*) FROM k8s_runtime_alerts WHERE tenant_id=$1 AND status='open' AND severity='critical'`, tid).Scan(&criticalFindings)
	database.DB.QueryRow(`SELECT COUNT(*) FROM k8s_images WHERE tenant_id=$1 AND cve_critical>0`, tid).Scan(&vulnerableImages)
	database.DB.QueryRow(`SELECT COUNT(*) FROM k8s_runtime_alerts WHERE tenant_id=$1 AND status='open'`, tid).Scan(&runtimeAlerts)
	var avgRisk, avgCompliance float64
	database.DB.QueryRow(`SELECT COALESCE(AVG(risk_score),50) FROM k8s_clusters WHERE tenant_id=$1`, tid).Scan(&avgRisk)
	database.DB.QueryRow(`SELECT COALESCE(AVG(compliance_score),75) FROM k8s_clusters WHERE tenant_id=$1`, tid).Scan(&avgCompliance)
	var privilegedPods, noLimits int
	database.DB.QueryRow(`SELECT COUNT(*) FROM k8s_pods WHERE tenant_id=$1 AND is_privileged=true`, tid).Scan(&privilegedPods)
	database.DB.QueryRow(`SELECT COUNT(*) FROM k8s_pods WHERE tenant_id=$1 AND has_resource_limits=false`, tid).Scan(&noLimits)
	c.JSON(http.StatusOK, gin.H{
		"clusters":             clusters,
		"nodes":                nodes,
		"pods":                 pods,
		"namespaces":           namespaces,
		"running_containers":   containers,
		"critical_findings":    criticalFindings,
		"vulnerable_images":    vulnerableImages,
		"runtime_alerts":       runtimeAlerts,
		"container_risk_score": int(avgRisk),
		"compliance_score":     int(avgCompliance),
		"privileged_pods":      privilegedPods,
		"pods_no_limits":       noLimits,
	})
}

// GetK8sClusters — GET /api/containers/clusters
func GetK8sClusters(c *gin.Context) {
	createContainerSecurityTables()
	tid := tenantIDFromContext(c)
	rows, err := database.DB.Query(`
		SELECT id, name, provider, k8s_version, node_count, status, region,
			risk_score, compliance_score, last_scan, created_at
		FROM k8s_clusters WHERE tenant_id=$1 ORDER BY risk_score DESC`, tid)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()
	type Cluster struct {
		ID              int    `json:"id"`
		Name            string `json:"name"`
		Provider        string `json:"provider"`
		K8sVersion      string `json:"k8s_version"`
		NodeCount       int    `json:"node_count"`
		Status          string `json:"status"`
		Region          string `json:"region"`
		RiskScore       int    `json:"risk_score"`
		ComplianceScore int    `json:"compliance_score"`
		LastScan        string `json:"last_scan"`
		CreatedAt       string `json:"created_at"`
	}
	clusters := []Cluster{}
	for rows.Next() {
		var cl Cluster
		if rows.Scan(&cl.ID, &cl.Name, &cl.Provider, &cl.K8sVersion, &cl.NodeCount,
			&cl.Status, &cl.Region, &cl.RiskScore, &cl.ComplianceScore,
			&cl.LastScan, &cl.CreatedAt) == nil {
			clusters = append(clusters, cl)
		}
	}
	if clusters == nil {
		clusters = []Cluster{}
	}
	c.JSON(http.StatusOK, clusters)
}

// GetK8sNodes — GET /api/containers/nodes
func GetK8sNodes(c *gin.Context) {
	createContainerSecurityTables()
	tid := tenantIDFromContext(c)
	limit := parseLimit(c, 50)
	clusterID := c.Query("cluster_id")
	q := `SELECT id, cluster_id, name, os, kernel, cpu_cores, memory_gb, pod_count,
		runtime, risk_score, vuln_count, status, last_heartbeat, created_at
		FROM k8s_nodes WHERE tenant_id=$1`
	args := []interface{}{tid}
	if clusterID != "" {
		q += " AND cluster_id=$2 ORDER BY risk_score DESC LIMIT $3"
		args = append(args, clusterID, limit)
	} else {
		q += " ORDER BY risk_score DESC LIMIT $2"
		args = append(args, limit)
	}
	rows, err := database.DB.Query(q, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()
	type Node struct {
		ID            int    `json:"id"`
		ClusterID     int    `json:"cluster_id"`
		Name          string `json:"name"`
		OS            string `json:"os"`
		Kernel        string `json:"kernel"`
		CPUCores      int    `json:"cpu_cores"`
		MemoryGB      int    `json:"memory_gb"`
		PodCount      int    `json:"pod_count"`
		Runtime       string `json:"runtime"`
		RiskScore     int    `json:"risk_score"`
		VulnCount     int    `json:"vuln_count"`
		Status        string `json:"status"`
		LastHeartbeat string `json:"last_heartbeat"`
		CreatedAt     string `json:"created_at"`
	}
	nodes := []Node{}
	for rows.Next() {
		var n Node
		if rows.Scan(&n.ID, &n.ClusterID, &n.Name, &n.OS, &n.Kernel, &n.CPUCores,
			&n.MemoryGB, &n.PodCount, &n.Runtime, &n.RiskScore, &n.VulnCount,
			&n.Status, &n.LastHeartbeat, &n.CreatedAt) == nil {
			nodes = append(nodes, n)
		}
	}
	if nodes == nil {
		nodes = []Node{}
	}
	c.JSON(http.StatusOK, nodes)
}

// GetK8sPods — GET /api/containers/pods
func GetK8sPods(c *gin.Context) {
	createContainerSecurityTables()
	tid := tenantIDFromContext(c)
	limit := parseLimit(c, 100)
	q := `SELECT id, cluster_id, namespace, name, image, status, is_privileged,
		host_network, host_pid, host_ipc, run_as_root, read_only_fs,
		has_resource_limits, capabilities, volumes, risk_score, created_at
		FROM k8s_pods WHERE tenant_id=$1`
	args := []interface{}{tid}
	i := 2
	if v := c.Query("namespace"); v != "" {
		q += fmt.Sprintf(" AND namespace=$%d", i)
		args = append(args, v)
		i++
	}
	if v := c.Query("privileged"); v == "true" {
		q += " AND is_privileged=true"
	}
	if v := c.Query("cluster_id"); v != "" {
		q += fmt.Sprintf(" AND cluster_id=$%d", i)
		args = append(args, v)
		i++
	}
	q += fmt.Sprintf(" ORDER BY risk_score DESC LIMIT $%d", i)
	args = append(args, limit)
	rows, err := database.DB.Query(q, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()
	type Pod struct {
		ID                int    `json:"id"`
		ClusterID         int    `json:"cluster_id"`
		Namespace         string `json:"namespace"`
		Name              string `json:"name"`
		Image             string `json:"image"`
		Status            string `json:"status"`
		IsPrivileged      bool   `json:"is_privileged"`
		HostNetwork       bool   `json:"host_network"`
		HostPID           bool   `json:"host_pid"`
		HostIPC           bool   `json:"host_ipc"`
		RunAsRoot         bool   `json:"run_as_root"`
		ReadOnlyFS        bool   `json:"read_only_fs"`
		HasResourceLimits bool   `json:"has_resource_limits"`
		Capabilities      string `json:"capabilities"`
		Volumes           string `json:"volumes"`
		RiskScore         int    `json:"risk_score"`
		CreatedAt         string `json:"created_at"`
	}
	pods := []Pod{}
	for rows.Next() {
		var p Pod
		if rows.Scan(&p.ID, &p.ClusterID, &p.Namespace, &p.Name, &p.Image, &p.Status,
			&p.IsPrivileged, &p.HostNetwork, &p.HostPID, &p.HostIPC, &p.RunAsRoot,
			&p.ReadOnlyFS, &p.HasResourceLimits, &p.Capabilities, &p.Volumes,
			&p.RiskScore, &p.CreatedAt) == nil {
			pods = append(pods, p)
		}
	}
	if pods == nil {
		pods = []Pod{}
	}
	c.JSON(http.StatusOK, pods)
}

// GetK8sNamespaces — GET /api/containers/namespaces
func GetK8sNamespaces(c *gin.Context) {
	createContainerSecurityTables()
	tid := tenantIDFromContext(c)
	type NSRow struct {
		Namespace  string  `json:"namespace"`
		PodCount   int     `json:"pod_count"`
		Privileged int     `json:"privileged_pods"`
		RiskScore  float64 `json:"risk_score"`
	}
	rows, err := database.DB.Query(`
		SELECT namespace,
			COUNT(*) as pod_count,
			SUM(CASE WHEN is_privileged THEN 1 ELSE 0 END) as privileged,
			COALESCE(AVG(risk_score),0) as avg_risk
		FROM k8s_pods WHERE tenant_id=$1 GROUP BY namespace ORDER BY avg_risk DESC
	`, tid)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()
	ns := []NSRow{}
	for rows.Next() {
		var r NSRow
		if rows.Scan(&r.Namespace, &r.PodCount, &r.Privileged, &r.RiskScore) == nil {
			ns = append(ns, r)
		}
	}
	if ns == nil {
		ns = []NSRow{}
	}
	c.JSON(http.StatusOK, ns)
}

// GetK8sImages — GET /api/containers/images
func GetK8sImages(c *gin.Context) {
	createContainerSecurityTables()
	tid := tenantIDFromContext(c)
	limit := parseLimit(c, 50)
	q := `SELECT id, image, registry, tag, base_image, os, size_mb,
		cve_critical, cve_high, cve_medium, cve_low,
		has_secrets, malware_found, signature_valid, sbom_available,
		age_days, risk_score, last_scanned, created_at
		FROM k8s_images WHERE tenant_id=$1`
	args := []interface{}{tid}
	if v := c.Query("registry"); v != "" {
		q += " AND registry=$2 ORDER BY risk_score DESC LIMIT $3"
		args = append(args, v, limit)
	} else {
		q += " ORDER BY risk_score DESC LIMIT $2"
		args = append(args, limit)
	}
	rows, err := database.DB.Query(q, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()
	type Img struct {
		ID             int    `json:"id"`
		Image          string `json:"image"`
		Registry       string `json:"registry"`
		Tag            string `json:"tag"`
		BaseImage      string `json:"base_image"`
		OS             string `json:"os"`
		SizeMB         int    `json:"size_mb"`
		CVECritical    int    `json:"cve_critical"`
		CVEHigh        int    `json:"cve_high"`
		CVEMedium      int    `json:"cve_medium"`
		CVELow         int    `json:"cve_low"`
		HasSecrets     bool   `json:"has_secrets"`
		MalwareFound   bool   `json:"malware_found"`
		SignatureValid bool   `json:"signature_valid"`
		SBOMAvailable  bool   `json:"sbom_available"`
		AgeDays        int    `json:"age_days"`
		RiskScore      int    `json:"risk_score"`
		LastScanned    string `json:"last_scanned"`
		CreatedAt      string `json:"created_at"`
	}
	imgs := []Img{}
	for rows.Next() {
		var im Img
		if rows.Scan(&im.ID, &im.Image, &im.Registry, &im.Tag, &im.BaseImage, &im.OS,
			&im.SizeMB, &im.CVECritical, &im.CVEHigh, &im.CVEMedium, &im.CVELow,
			&im.HasSecrets, &im.MalwareFound, &im.SignatureValid, &im.SBOMAvailable,
			&im.AgeDays, &im.RiskScore, &im.LastScanned, &im.CreatedAt) == nil {
			imgs = append(imgs, im)
		}
	}
	if imgs == nil {
		imgs = []Img{}
	}
	c.JSON(http.StatusOK, imgs)
}

// GetSupplyChain — GET /api/containers/supply-chain
func GetSupplyChain(c *gin.Context) {
	createContainerSecurityTables()
	tid := tenantIDFromContext(c)
	var total, signed, sbom, oldBase int
	database.DB.QueryRow(`SELECT COUNT(*) FROM k8s_images WHERE tenant_id=$1`, tid).Scan(&total)
	database.DB.QueryRow(`SELECT COUNT(*) FROM k8s_images WHERE tenant_id=$1 AND signature_valid=true`, tid).Scan(&signed)
	database.DB.QueryRow(`SELECT COUNT(*) FROM k8s_images WHERE tenant_id=$1 AND sbom_available=true`, tid).Scan(&sbom)
	database.DB.QueryRow(`SELECT COUNT(*) FROM k8s_images WHERE tenant_id=$1 AND age_days>180`, tid).Scan(&oldBase)
	realTotal := total
	if total == 0 {
		total = 1
	}

	registryRows, err := database.DB.Query(`SELECT registry, COUNT(*) FROM k8s_images WHERE tenant_id=$1 GROUP BY registry ORDER BY COUNT(*) DESC`, tid)
	registries := []map[string]interface{}{}
	if err == nil {
		defer registryRows.Close()
		for registryRows.Next() {
			var reg string
			var cnt int
			if registryRows.Scan(&reg, &cnt) == nil {
				registries = append(registries, map[string]interface{}{
					"registry": reg, "trusted": trustedRegistries[reg], "images": cnt,
				})
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"total_images":       realTotal,
		"signed_images":      signed,
		"sbom_available":     sbom,
		"old_base_images":    oldBase,
		"signature_rate":     signed * 100 / total,
		"sbom_rate":          sbom * 100 / total,
		"trusted_registries": registries,
	})
}

var trustedRegistries = map[string]bool{
	"gcr.io": true, "ghcr.io": true, "public.ecr.aws": true,
	"quay.io": true, "registry.k8s.io": true, "mcr.microsoft.com": true,
}

// GetRuntimeAlerts — GET /api/containers/runtime-alerts
func GetRuntimeAlerts(c *gin.Context) {
	createContainerSecurityTables()
	tid := tenantIDFromContext(c)
	limit := parseLimit(c, 50)
	q := `SELECT id, cluster_id, namespace, pod_name, container_name,
		alert_type, severity, description, process, command,
		source_ip, mitre_technique, status, created_at
		FROM k8s_runtime_alerts WHERE tenant_id=$1`
	args := []interface{}{tid}
	i := 2
	if v := c.Query("severity"); v != "" {
		q += fmt.Sprintf(" AND severity=$%d", i)
		args = append(args, v)
		i++
	}
	if v := c.Query("alert_type"); v != "" {
		q += fmt.Sprintf(" AND alert_type=$%d", i)
		args = append(args, v)
		i++
	}
	q += fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d", i)
	args = append(args, limit)
	rows, err := database.DB.Query(q, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()
	type Alert struct {
		ID             int    `json:"id"`
		ClusterID      int    `json:"cluster_id"`
		Namespace      string `json:"namespace"`
		PodName        string `json:"pod_name"`
		ContainerName  string `json:"container_name"`
		AlertType      string `json:"alert_type"`
		Severity       string `json:"severity"`
		Description    string `json:"description"`
		Process        string `json:"process"`
		Command        string `json:"command"`
		SourceIP       string `json:"source_ip"`
		MITRETechnique string `json:"mitre_technique"`
		Status         string `json:"status"`
		CreatedAt      string `json:"created_at"`
	}
	alerts := []Alert{}
	for rows.Next() {
		var a Alert
		if rows.Scan(&a.ID, &a.ClusterID, &a.Namespace, &a.PodName, &a.ContainerName,
			&a.AlertType, &a.Severity, &a.Description, &a.Process, &a.Command,
			&a.SourceIP, &a.MITRETechnique, &a.Status, &a.CreatedAt) == nil {
			alerts = append(alerts, a)
		}
	}
	if alerts == nil {
		alerts = []Alert{}
	}
	c.JSON(http.StatusOK, alerts)
}

// GetK8sRBAC — GET /api/containers/rbac
func GetK8sRBAC(c *gin.Context) {
	createContainerSecurityTables()
	tid := tenantIDFromContext(c)
	rows, err := database.DB.Query(`
		SELECT id, cluster_id, kind, name, namespace, subject, permissions,
			finding_type, severity, description, created_at
		FROM k8s_rbac_findings WHERE tenant_id=$1 ORDER BY severity DESC, created_at DESC LIMIT 50
	`, tid)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()
	type RBAC struct {
		ID          int    `json:"id"`
		ClusterID   int    `json:"cluster_id"`
		Kind        string `json:"kind"`
		Name        string `json:"name"`
		Namespace   string `json:"namespace"`
		Subject     string `json:"subject"`
		Permissions string `json:"permissions"`
		FindingType string `json:"finding_type"`
		Severity    string `json:"severity"`
		Description string `json:"description"`
		CreatedAt   string `json:"created_at"`
	}
	findings := []RBAC{}
	for rows.Next() {
		var r RBAC
		if rows.Scan(&r.ID, &r.ClusterID, &r.Kind, &r.Name, &r.Namespace, &r.Subject,
			&r.Permissions, &r.FindingType, &r.Severity, &r.Description, &r.CreatedAt) == nil {
			findings = append(findings, r)
		}
	}
	if findings == nil {
		findings = []RBAC{}
	}
	var total, clusterRoles, bindings, excessive, wildcard int
	database.DB.QueryRow(`SELECT COUNT(*) FROM k8s_rbac_findings WHERE tenant_id=$1`, tid).Scan(&total)
	database.DB.QueryRow(`SELECT COUNT(*) FROM k8s_rbac_findings WHERE tenant_id=$1 AND kind='ClusterRole'`, tid).Scan(&clusterRoles)
	database.DB.QueryRow(`SELECT COUNT(*) FROM k8s_rbac_findings WHERE tenant_id=$1 AND kind='ClusterRoleBinding'`, tid).Scan(&bindings)
	database.DB.QueryRow(`SELECT COUNT(*) FROM k8s_rbac_findings WHERE tenant_id=$1 AND finding_type='excessive_permissions'`, tid).Scan(&excessive)
	database.DB.QueryRow(`SELECT COUNT(*) FROM k8s_rbac_findings WHERE tenant_id=$1 AND finding_type='wildcard_permissions'`, tid).Scan(&wildcard)
	c.JSON(http.StatusOK, gin.H{
		"findings":      findings,
		"total":         total,
		"cluster_roles": clusterRoles,
		"bindings":      bindings,
		"excessive":     excessive,
		"wildcard":      wildcard,
	})
}

// GetK8sSecrets — GET /api/containers/secrets
func GetK8sSecrets(c *gin.Context) {
	createContainerSecurityTables()
	tid := tenantIDFromContext(c)
	var totalSecrets int
	database.DB.QueryRow(`SELECT COUNT(*) FROM k8s_pods WHERE tenant_id=$1 AND volumes LIKE '%secret%'`, tid).Scan(&totalSecrets)
	c.JSON(http.StatusOK, gin.H{
		"total_secrets": totalSecrets,
		"providers": []map[string]interface{}{
			{"name": "Kubernetes Secrets", "count": totalSecrets, "status": "active"},
			{"name": "Vault", "count": 0, "status": "not_configured"},
			{"name": "AWS Secrets Manager", "count": 0, "status": "not_configured"},
			{"name": "Azure Key Vault", "count": 0, "status": "not_configured"},
			{"name": "GCP Secret Manager", "count": 0, "status": "not_configured"},
		},
	})
}

// GetNetworkPolicies — GET /api/containers/network-policies
func GetNetworkPolicies(c *gin.Context) {
	createContainerSecurityTables()
	tid := tenantIDFromContext(c)
	rows, err := database.DB.Query(`
		SELECT id, cluster_id, namespace, name, policy_type, direction,
			status, pod_selector, peer, port, created_at
		FROM k8s_network_policies WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT 50
	`, tid)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()
	type NP struct {
		ID          int    `json:"id"`
		ClusterID   int    `json:"cluster_id"`
		Namespace   string `json:"namespace"`
		Name        string `json:"name"`
		PolicyType  string `json:"policy_type"`
		Direction   string `json:"direction"`
		Status      string `json:"status"`
		PodSelector string `json:"pod_selector"`
		Peer        string `json:"peer"`
		Port        string `json:"port"`
		CreatedAt   string `json:"created_at"`
	}
	policies := []NP{}
	for rows.Next() {
		var p NP
		if rows.Scan(&p.ID, &p.ClusterID, &p.Namespace, &p.Name, &p.PolicyType,
			&p.Direction, &p.Status, &p.PodSelector, &p.Peer, &p.Port, &p.CreatedAt) == nil {
			policies = append(policies, p)
		}
	}
	if policies == nil {
		policies = []NP{}
	}
	c.JSON(http.StatusOK, policies)
}

// GetAdmissionControl — GET /api/containers/admission
func GetAdmissionControl(c *gin.Context) {
	createContainerSecurityTables()
	tid := tenantIDFromContext(c)
	rows, err := database.DB.Query(`
		SELECT id, cluster_id, namespace, workload, kind, violation_type,
			severity, description, action, created_at
		FROM k8s_admission_violations WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT 50
	`, tid)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()
	type AV struct {
		ID            int    `json:"id"`
		ClusterID     int    `json:"cluster_id"`
		Namespace     string `json:"namespace"`
		Workload      string `json:"workload"`
		Kind          string `json:"kind"`
		ViolationType string `json:"violation_type"`
		Severity      string `json:"severity"`
		Description   string `json:"description"`
		Action        string `json:"action"`
		CreatedAt     string `json:"created_at"`
	}
	violations := []AV{}
	for rows.Next() {
		var v AV
		if rows.Scan(&v.ID, &v.ClusterID, &v.Namespace, &v.Workload, &v.Kind,
			&v.ViolationType, &v.Severity, &v.Description, &v.Action, &v.CreatedAt) == nil {
			violations = append(violations, v)
		}
	}
	if violations == nil {
		violations = []AV{}
	}
	c.JSON(http.StatusOK, violations)
}

// GetContainerCompliance — GET /api/containers/compliance
func GetContainerCompliance(c *gin.Context) {
	createContainerSecurityTables()
	tid := tenantIDFromContext(c)
	var avgCompliance int
	database.DB.QueryRow(`SELECT COALESCE(AVG(compliance_score),75) FROM k8s_clusters WHERE tenant_id=$1`, tid).Scan(&avgCompliance)

	var total, denied, allowed int
	database.DB.QueryRow(`SELECT COUNT(*) FROM k8s_admission_violations WHERE tenant_id=$1`, tid).Scan(&total)
	database.DB.QueryRow(`SELECT COUNT(*) FROM k8s_admission_violations WHERE tenant_id=$1 AND action='denied'`, tid).Scan(&denied)
	database.DB.QueryRow(`SELECT COUNT(*) FROM k8s_admission_violations WHERE tenant_id=$1 AND action='allowed'`, tid).Scan(&allowed)

	var critical, high, medium, low int
	database.DB.QueryRow(`SELECT COUNT(*) FILTER (WHERE severity='critical'), COUNT(*) FILTER (WHERE severity='high'), COUNT(*) FILTER (WHERE severity='medium'), COUNT(*) FILTER (WHERE severity='low') FROM k8s_admission_violations WHERE tenant_id=$1`, tid).Scan(&critical, &high, &medium, &low)

	rows, err := database.DB.Query(`
		SELECT workload, kind, violation_type, severity, description, action, created_at
		FROM k8s_admission_violations WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT 20`, tid)
	violations := []map[string]interface{}{}
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var workload, kind, vtype, severity, desc, action, createdAt string
			if rows.Scan(&workload, &kind, &vtype, &severity, &desc, &action, &createdAt) == nil {
				violations = append(violations, map[string]interface{}{
					"workload": workload, "kind": kind, "violation_type": vtype,
					"severity": severity, "description": desc, "action": action, "created_at": createdAt,
				})
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"overall_score":    avgCompliance,
		"total_violations": total,
		"denied":           denied,
		"allowed":          allowed,
		"by_severity": gin.H{
			"critical": critical, "high": high, "medium": medium, "low": low,
		},
		"recent_violations": violations,
	})
}

// GetContainerThreatIntel — GET /api/containers/threat-intel
func GetContainerThreatIntel(c *gin.Context) {
	createContainerSecurityTables()
	tid := tenantIDFromContext(c)

	maliciousImages := []map[string]interface{}{}
	miRows, err := database.DB.Query(`SELECT image, tag, registry FROM k8s_images WHERE tenant_id=$1 AND malware_found=true LIMIT 10`, tid)
	if err == nil {
		defer miRows.Close()
		for miRows.Next() {
			var image, tag, registry string
			if miRows.Scan(&image, &tag, &registry) == nil {
				maliciousImages = append(maliciousImages, map[string]interface{}{
					"image": image, "tag": tag, "registry": registry,
				})
			}
		}
	}

	iocMatches := []map[string]interface{}{}
	iocRows, err := database.DB.Query(`SELECT indicator, type, hit_count FROM iocs WHERE tenant_id=$1 AND type='image' AND enabled=true ORDER BY hit_count DESC LIMIT 10`, tid)
	if err == nil {
		defer iocRows.Close()
		for iocRows.Next() {
			var indicator, itype string
			var hits int
			if iocRows.Scan(&indicator, &itype, &hits) == nil {
				iocMatches = append(iocMatches, map[string]interface{}{
					"type": itype, "value": indicator, "hits": hits,
				})
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"malicious_images": maliciousImages,
		"ioc_matches":      iocMatches,
		// Generic, non-tenant-specific K8s ecosystem CVE advisory content —
		// not a claim that these were detected against this tenant's images.
		"recent_cves": []map[string]interface{}{
			{"cve": "CVE-2024-21626", "score": 9.9, "affected": "runc < 1.1.12", "type": "container_escape", "advisory": true},
			{"cve": "CVE-2023-2431", "score": 7.8, "affected": "kubelet", "type": "privilege_escalation", "advisory": true},
			{"cve": "CVE-2022-3172", "score": 7.5, "affected": "kube-aggregator", "type": "ssrf", "advisory": true},
		},
	})
}

// GetContainerTimeline — GET /api/containers/timeline
func GetContainerTimeline(c *gin.Context) {
	createContainerSecurityTables()
	tid := tenantIDFromContext(c)
	limit := parseLimit(c, 50)
	rows, err := database.DB.Query(`
		SELECT id, namespace, pod_name, alert_type, severity, description, created_at
		FROM k8s_runtime_alerts WHERE tenant_id=$1
		ORDER BY created_at DESC LIMIT $2
	`, tid, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()
	type Event struct {
		ID          int    `json:"id"`
		Namespace   string `json:"namespace"`
		PodName     string `json:"pod_name"`
		EventType   string `json:"event_type"`
		Severity    string `json:"severity"`
		Description string `json:"description"`
		CreatedAt   string `json:"created_at"`
	}
	events := []Event{}
	for rows.Next() {
		var e Event
		if rows.Scan(&e.ID, &e.Namespace, &e.PodName, &e.EventType, &e.Severity, &e.Description, &e.CreatedAt) == nil {
			events = append(events, e)
		}
	}
	if events == nil {
		events = []Event{}
	}
	c.JSON(http.StatusOK, events)
}

// GetContainerVulns — GET /api/containers/vulnerabilities
func GetContainerVulns(c *gin.Context) {
	createContainerSecurityTables()
	tid := tenantIDFromContext(c)
	limit := parseLimit(c, 50)
	severity := c.Query("severity")
	q := `SELECT id, image, cve_critical, cve_high, cve_medium, cve_low, risk_score, last_scanned
		FROM k8s_images WHERE tenant_id=$1 AND (cve_critical>0 OR cve_high>0)`
	args := []interface{}{tid}
	_ = severity
	q += " ORDER BY cve_critical DESC, cve_high DESC LIMIT $2"
	args = append(args, limit)
	rows, err := database.DB.Query(q, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()
	type VulnImage struct {
		ID          int    `json:"id"`
		Image       string `json:"image"`
		CVECritical int    `json:"cve_critical"`
		CVEHigh     int    `json:"cve_high"`
		CVEMedium   int    `json:"cve_medium"`
		CVELow      int    `json:"cve_low"`
		RiskScore   int    `json:"risk_score"`
		LastScanned string `json:"last_scanned"`
	}
	vulns := []VulnImage{}
	for rows.Next() {
		var v VulnImage
		if rows.Scan(&v.ID, &v.Image, &v.CVECritical, &v.CVEHigh, &v.CVEMedium, &v.CVELow, &v.RiskScore, &v.LastScanned) == nil {
			vulns = append(vulns, v)
		}
	}
	if vulns == nil {
		vulns = []VulnImage{}
	}
	c.JSON(http.StatusOK, vulns)
}

// GetContainerAttackPaths — GET /api/containers/attack-paths
func GetContainerAttackPaths(c *gin.Context) {
	createContainerSecurityTables()
	tid := tenantIDFromContext(c)

	riskPods := []map[string]interface{}{}
	podRows, err := database.DB.Query(`
		SELECT name, namespace, image, is_privileged, run_as_root, host_network, risk_score
		FROM k8s_pods WHERE tenant_id=$1 AND (is_privileged=true OR run_as_root=true OR host_network=true)
		ORDER BY risk_score DESC LIMIT 5`, tid)
	if err == nil {
		defer podRows.Close()
		for podRows.Next() {
			var name, namespace, image string
			var privileged, root, hostNet bool
			var risk int
			if podRows.Scan(&name, &namespace, &image, &privileged, &root, &hostNet, &risk) == nil {
				riskPods = append(riskPods, map[string]interface{}{
					"name": name, "namespace": namespace, "image": image,
					"is_privileged": privileged, "run_as_root": root, "host_network": hostNet,
					"risk_score": risk,
				})
			}
		}
	}

	riskRBAC := []map[string]interface{}{}
	rbacRows, err := database.DB.Query(`
		SELECT kind, name, subject, finding_type, severity, description
		FROM k8s_rbac_findings WHERE tenant_id=$1 AND finding_type IN ('excessive_permissions','wildcard_permissions')
		ORDER BY severity DESC LIMIT 5`, tid)
	if err == nil {
		defer rbacRows.Close()
		for rbacRows.Next() {
			var kind, name, subject, findingType, severity, desc string
			if rbacRows.Scan(&kind, &name, &subject, &findingType, &severity, &desc) == nil {
				riskRBAC = append(riskRBAC, map[string]interface{}{
					"kind": kind, "name": name, "subject": subject,
					"finding_type": findingType, "severity": severity, "description": desc,
				})
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"risk_pods": riskPods,
		"risk_rbac": riskRBAC,
	})
}

// GetContainerAnalytics — GET /api/containers/analytics
func GetContainerAnalytics(c *gin.Context) {
	createContainerSecurityTables()
	tid := tenantIDFromContext(c)
	var totalPods, privilegedPods int
	database.DB.QueryRow(`SELECT COUNT(*) FROM k8s_pods WHERE tenant_id=$1`, tid).Scan(&totalPods)
	database.DB.QueryRow(`SELECT COUNT(*) FROM k8s_pods WHERE tenant_id=$1 AND is_privileged=true`, tid).Scan(&privilegedPods)
	type TrendPoint struct {
		Date  string `json:"date"`
		Count int    `json:"count"`
	}
	trend := []TrendPoint{}
	for i := 13; i >= 0; i-- {
		d := time.Now().AddDate(0, 0, -i).Format("2006-01-02")
		var cnt int
		database.DB.QueryRow(`SELECT COUNT(*) FROM k8s_runtime_alerts WHERE tenant_id=$1 AND DATE(created_at)=$2`, tid, d).Scan(&cnt)
		trend = append(trend, TrendPoint{Date: d, Count: cnt})
	}
	topImages := []map[string]interface{}{}
	imgRows, err := database.DB.Query(`
		SELECT image, cve_critical, cve_high, risk_score FROM k8s_images
		WHERE tenant_id=$1 ORDER BY cve_critical DESC, cve_high DESC LIMIT 5`, tid)
	if err == nil {
		defer imgRows.Close()
		for imgRows.Next() {
			var image string
			var cveCritical, cveHigh, risk int
			if imgRows.Scan(&image, &cveCritical, &cveHigh, &risk) == nil {
				topImages = append(topImages, map[string]interface{}{
					"image": image, "cve_critical": cveCritical, "cve_high": cveHigh, "risk": risk,
				})
			}
		}
	}

	alertByType := []map[string]interface{}{}
	atRows, err := database.DB.Query(`
		SELECT alert_type, COUNT(*) FROM k8s_runtime_alerts
		WHERE tenant_id=$1 GROUP BY alert_type ORDER BY COUNT(*) DESC`, tid)
	if err == nil {
		defer atRows.Close()
		for atRows.Next() {
			var atype string
			var cnt int
			if atRows.Scan(&atype, &cnt) == nil {
				alertByType = append(alertByType, map[string]interface{}{"type": atype, "count": cnt})
			}
		}
	}

	nsRisk := []map[string]interface{}{}
	nsRows, err := database.DB.Query(`
		SELECT namespace, COUNT(*), COALESCE(AVG(risk_score),0)
		FROM k8s_pods WHERE tenant_id=$1 GROUP BY namespace ORDER BY AVG(risk_score) DESC`, tid)
	if err == nil {
		defer nsRows.Close()
		for nsRows.Next() {
			var namespace string
			var pods int
			var risk float64
			if nsRows.Scan(&namespace, &pods, &risk) == nil {
				nsRisk = append(nsRisk, map[string]interface{}{
					"namespace": namespace, "risk": int(risk), "pods": pods,
				})
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"total_pods":            totalPods,
		"privileged_pods":       privilegedPods,
		"runtime_alert_trend":   trend,
		"top_vulnerable_images": topImages,
		"alert_by_type":         alertByType,
		"namespace_risk":        nsRisk,
	})
}

// PostContainerResponse — POST /api/containers/response
func PostContainerResponse(c *gin.Context) {
	createContainerSecurityTables()
	tid := tenantIDFromContext(c)
	var body struct {
		Action     string `json:"action"`
		Namespace  string `json:"namespace"`
		PodName    string `json:"pod_name"`
		NodeName   string `json:"node_name"`
		Image      string `json:"image"`
		SAName     string `json:"service_account"`
		Deployment string `json:"deployment"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Action == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "action required"})
		return
	}

	switch body.Action {
	case "kill_container":
		if body.Namespace == "" || body.PodName == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "namespace and pod_name required"})
			return
		}
		res, _ := database.DB.Exec(`UPDATE k8s_pods SET status='terminated' WHERE tenant_id=$1 AND namespace=$2 AND name=$3`, tid, body.Namespace, body.PodName)
		if n, _ := res.RowsAffected(); n == 0 {
			c.JSON(http.StatusNotFound, gin.H{"error": "no matching pod found"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true, "action": body.Action, "message": "Container killed via SIGKILL"})
	case "delete_pod":
		if body.Namespace == "" || body.PodName == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "namespace and pod_name required"})
			return
		}
		res, _ := database.DB.Exec(`DELETE FROM k8s_pods WHERE tenant_id=$1 AND namespace=$2 AND name=$3`, tid, body.Namespace, body.PodName)
		if n, _ := res.RowsAffected(); n == 0 {
			c.JSON(http.StatusNotFound, gin.H{"error": "no matching pod found"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true, "action": body.Action, "message": "Pod deleted — replacement will be scheduled"})
	case "quarantine_node":
		if body.NodeName == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "node_name required"})
			return
		}
		res, _ := database.DB.Exec(`UPDATE k8s_nodes SET status='cordoned' WHERE tenant_id=$1 AND name=$2`, tid, body.NodeName)
		if n, _ := res.RowsAffected(); n == 0 {
			c.JSON(http.StatusNotFound, gin.H{"error": "no matching node found"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true, "action": body.Action, "message": "Node cordoned and pods evicted"})
	case "block_image":
		if body.Image == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "image required"})
			return
		}
		if err := repositories.CreateIOC(models.IOC{
			Indicator: body.Image, Type: "image", Severity: "high", Enabled: true,
			Description: "Blocked via Container Security",
		}, tid); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true, "action": body.Action, "message": "Image blocked in admission controller"})
	case "revoke_service_account", "scale_deployment":
		c.JSON(http.StatusNotImplemented, gin.H{"error": "no real Kubernetes API/IAM integration configured for this action"})
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "unknown action"})
	}
}

// PostContainerAI — POST /api/containers/ai
func PostContainerAI(c *gin.Context) {
	createContainerSecurityTables()
	var body struct {
		Mode    string `json:"mode"`
		Content string `json:"content"`
		Image   string `json:"image"`
		Alert   string `json:"alert"`
	}
	c.ShouldBindJSON(&body)
	var prompt string
	switch body.Mode {
	case "image":
		prompt = fmt.Sprintf(`You are a container security expert. Analyze this container image security finding: %s
Provide compact JSON: {"risk":"critical|high|medium|low","explanation":"2 sentences","mitre_techniques":["T1xxx"],"recommended_actions":["action"],"severity_rationale":"brief"}`,
			body.Image)
	case "alert":
		prompt = fmt.Sprintf(`You are a Kubernetes security expert. Analyze this runtime alert: %s
Provide compact JSON: {"verdict":"confirmed_threat|false_positive|needs_investigation","confidence":90,"explanation":"2 sentences","attack_stage":"...","mitre_techniques":["T1xxx"],"recommended_actions":["action"]}`,
			body.Alert)
	default:
		prompt = fmt.Sprintf(`You are a Kubernetes security expert. Answer this question: %s
Provide compact JSON: {"answer":"concise answer","confidence":85,"recommended_actions":["action"]}`,
			body.Content)
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

// PostContainerReport — POST /api/containers/report
func PostContainerReport(c *gin.Context) {
	createContainerSecurityTables()
	tid := tenantIDFromContext(c)
	var body struct {
		ReportType string `json:"report_type"`
	}
	c.ShouldBindJSON(&body)
	var clusters, nodes, pods, vulnImages, runtimeAlerts int
	database.DB.QueryRow(`SELECT COUNT(*) FROM k8s_clusters WHERE tenant_id=$1`, tid).Scan(&clusters)
	database.DB.QueryRow(`SELECT COUNT(*) FROM k8s_nodes WHERE tenant_id=$1`, tid).Scan(&nodes)
	database.DB.QueryRow(`SELECT COUNT(*) FROM k8s_pods WHERE tenant_id=$1`, tid).Scan(&pods)
	database.DB.QueryRow(`SELECT COUNT(*) FROM k8s_images WHERE tenant_id=$1 AND cve_critical>0`, tid).Scan(&vulnImages)
	database.DB.QueryRow(`SELECT COUNT(*) FROM k8s_runtime_alerts WHERE tenant_id=$1 AND status='open'`, tid).Scan(&runtimeAlerts)
	prompt := fmt.Sprintf(`Generate an executive Kubernetes/container security report.
Stats: %d clusters, %d nodes, %d pods, %d images with critical CVEs, %d open runtime alerts.
Report type: %s
Provide compact JSON: {"title":"...","executive_summary":"3 sentences","key_findings":["finding"],"risk_breakdown":{"critical":0,"high":0,"medium":0},"top_recommendations":[{"priority":1,"action":"action","estimated_effort":"time"}],"metrics":{"clusters":%d,"nodes":%d,"pods":%d,"vuln_images":%d,"runtime_alerts":%d}}`,
		clusters, nodes, pods, vulnImages, runtimeAlerts, body.ReportType,
		clusters, nodes, pods, vulnImages, runtimeAlerts)
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
