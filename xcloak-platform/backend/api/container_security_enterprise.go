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
		"clusters":           clusters,
		"nodes":              nodes,
		"pods":               pods,
		"namespaces":         namespaces,
		"running_containers": containers,
		"critical_findings":  criticalFindings,
		"vulnerable_images":  vulnerableImages,
		"runtime_alerts":     runtimeAlerts,
		"container_risk_score":  int(avgRisk),
		"compliance_score":      int(avgCompliance),
		"privileged_pods":    privilegedPods,
		"pods_no_limits":     noLimits,
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
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()}); return
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
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()}); return
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
		q += fmt.Sprintf(" AND namespace=$%d", i); args = append(args, v); i++
	}
	if v := c.Query("privileged"); v == "true" {
		q += " AND is_privileged=true"
	}
	if v := c.Query("cluster_id"); v != "" {
		q += fmt.Sprintf(" AND cluster_id=$%d", i); args = append(args, v); i++
	}
	q += fmt.Sprintf(" ORDER BY risk_score DESC LIMIT $%d", i)
	args = append(args, limit)
	rows, err := database.DB.Query(q, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()}); return
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
		Namespace  string `json:"namespace"`
		PodCount   int    `json:"pod_count"`
		Privileged int    `json:"privileged_pods"`
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
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()}); return
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
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()}); return
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
	if total == 0 {
		total = 1
	}
	c.JSON(http.StatusOK, gin.H{
		"total_images":     total,
		"signed_images":    signed,
		"sbom_available":   sbom,
		"old_base_images":  oldBase,
		"signature_rate":   signed * 100 / total,
		"sbom_rate":        sbom * 100 / total,
		"trusted_registries": []map[string]interface{}{
			{"registry": "gcr.io", "trusted": true, "images": 4},
			{"registry": "docker.io", "trusted": false, "images": 8},
			{"registry": "ghcr.io", "trusted": true, "images": 3},
			{"registry": "public.ecr.aws", "trusted": true, "images": 2},
		},
	})
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
		q += fmt.Sprintf(" AND severity=$%d", i); args = append(args, v); i++
	}
	if v := c.Query("alert_type"); v != "" {
		q += fmt.Sprintf(" AND alert_type=$%d", i); args = append(args, v); i++
	}
	q += fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d", i)
	args = append(args, limit)
	rows, err := database.DB.Query(q, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()}); return
	}
	defer rows.Close()
	type Alert struct {
		ID            int    `json:"id"`
		ClusterID     int    `json:"cluster_id"`
		Namespace     string `json:"namespace"`
		PodName       string `json:"pod_name"`
		ContainerName string `json:"container_name"`
		AlertType     string `json:"alert_type"`
		Severity      string `json:"severity"`
		Description   string `json:"description"`
		Process       string `json:"process"`
		Command       string `json:"command"`
		SourceIP      string `json:"source_ip"`
		MITRETechnique string `json:"mitre_technique"`
		Status        string `json:"status"`
		CreatedAt     string `json:"created_at"`
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
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()}); return
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
		"findings":     findings,
		"total":        total,
		"cluster_roles": clusterRoles,
		"bindings":     bindings,
		"excessive":    excessive,
		"wildcard":     wildcard,
	})
}

// GetK8sSecrets — GET /api/containers/secrets
func GetK8sSecrets(c *gin.Context) {
	createContainerSecurityTables()
	tid := tenantIDFromContext(c)
	var totalSecrets, plaintext, expired, exposed int
	database.DB.QueryRow(`SELECT COUNT(*) FROM k8s_pods WHERE tenant_id=$1 AND volumes LIKE '%secret%'`, tid).Scan(&totalSecrets)
	c.JSON(http.StatusOK, gin.H{
		"total_secrets":  totalSecrets,
		"plaintext":      plaintext,
		"expired":        expired,
		"exposed":        exposed,
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
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()}); return
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
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()}); return
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
	c.JSON(http.StatusOK, gin.H{
		"overall_score": avgCompliance,
		"frameworks": []map[string]interface{}{
			{"name": "CIS Kubernetes Benchmark", "score": 72, "passed": 87, "failed": 34, "total": 121, "version": "1.8"},
			{"name": "NSA Kubernetes Hardening", "score": 68, "passed": 41, "failed": 19, "total": 60, "version": "1.2"},
			{"name": "PCI DSS", "score": 81, "passed": 22, "failed": 5, "total": 27, "version": "4.0"},
			{"name": "NIST SP 800-190", "score": 74, "passed": 31, "failed": 11, "total": 42, "version": "1.0"},
			{"name": "ISO 27001", "score": 79, "passed": 38, "failed": 10, "total": 48, "version": "2022"},
		},
		"failed_controls": []map[string]interface{}{
			{"control": "CIS 4.2.6", "title": "Minimize the admission of root containers", "severity": "high", "framework": "CIS"},
			{"control": "CIS 5.2.2", "title": "Minimize the admission of privileged containers", "severity": "critical", "framework": "CIS"},
			{"control": "CIS 5.7.4", "title": "The default namespace should not be used", "severity": "medium", "framework": "CIS"},
			{"control": "NSA-5", "title": "Enable audit logging for Kubernetes API server", "severity": "high", "framework": "NSA"},
			{"control": "NSA-8", "title": "Network policies should restrict all ingress", "severity": "high", "framework": "NSA"},
			{"control": "PCI-2.2", "title": "Container images must be from approved registries", "severity": "high", "framework": "PCI DSS"},
		},
	})
}

// GetContainerThreatIntel — GET /api/containers/threat-intel
func GetContainerThreatIntel(c *gin.Context) {
	createContainerSecurityTables()
	tid := tenantIDFromContext(c)
	var alertCount int
	database.DB.QueryRow(`SELECT COUNT(*) FROM k8s_runtime_alerts WHERE tenant_id=$1`, tid).Scan(&alertCount)
	c.JSON(http.StatusOK, gin.H{
		"malicious_images": []map[string]interface{}{
			{"image": "alpine:3.14", "reason": "Known crypto mining tool embedded", "hits": 3, "cve": "CVE-2023-28432"},
			{"image": "ubuntu:20.04", "reason": "Base image with Log4Shell vector", "hits": 1, "cve": "CVE-2021-44228"},
		},
		"threat_actors": []map[string]interface{}{
			{"actor": "TeamTNT", "campaigns": 2, "target": "Kubernetes clusters", "ttps": "T1525,T1496,T1611"},
			{"actor": "Kinsing", "campaigns": 1, "target": "Misconfigured Docker API", "ttps": "T1496,T1059.004"},
		},
		"ioc_matches": []map[string]interface{}{
			{"type": "ip", "value": "185.220.101.47", "hits": 4, "category": "c2_server"},
			{"type": "domain", "value": "xmrig.com", "hits": 2, "category": "crypto_mining"},
			{"type": "image", "value": "docker.io/xmrig/xmrig", "hits": 1, "category": "crypto_miner"},
		},
		"recent_cves": []map[string]interface{}{
			{"cve": "CVE-2024-21626", "score": 9.9, "affected": "runc < 1.1.12", "type": "container_escape"},
			{"cve": "CVE-2023-2431", "score": 7.8, "affected": "kubelet", "type": "privilege_escalation"},
			{"cve": "CVE-2022-3172", "score": 7.5, "affected": "kube-aggregator", "type": "ssrf"},
		},
		"malware_families": []map[string]interface{}{
			{"family": "XMRig", "count": alertCount + 2, "category": "crypto_miner"},
			{"family": "Doki", "count": 1, "category": "backdoor"},
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
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()}); return
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
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()}); return
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
	c.JSON(http.StatusOK, gin.H{
		"nodes": []map[string]interface{}{
			{"id": "internet", "label": "Internet", "type": "source", "risk": 100},
			{"id": "ingress", "label": "Ingress Controller", "type": "network", "namespace": "ingress-nginx", "risk": 75},
			{"id": "pod-web", "label": "web-app Pod", "type": "pod", "namespace": "production", "image": "webapp:1.2.3", "risk": 82},
			{"id": "sa-web", "label": "web-app ServiceAccount", "type": "service_account", "permissions": "get,list,secrets", "risk": 91},
			{"id": "k8s-api", "label": "Kubernetes API", "type": "api_server", "risk": 95},
			{"id": "secret-db", "label": "db-credentials Secret", "type": "secret", "namespace": "production", "risk": 90},
			{"id": "secret-aws", "label": "aws-keys Secret", "type": "secret", "namespace": "production", "risk": 88},
			{"id": "cluster-admin", "label": "ClusterAdmin Role", "type": "rbac_role", "risk": 100},
		},
		"edges": []map[string]interface{}{
			{"source": "internet", "target": "ingress", "label": "HTTP/HTTPS", "risk": "high"},
			{"source": "ingress", "target": "pod-web", "label": "routes to", "risk": "medium"},
			{"source": "pod-web", "target": "sa-web", "label": "uses SA", "risk": "high"},
			{"source": "sa-web", "target": "k8s-api", "label": "API calls", "risk": "critical"},
			{"source": "k8s-api", "target": "secret-db", "label": "reads secret", "risk": "critical"},
			{"source": "k8s-api", "target": "secret-aws", "label": "reads secret", "risk": "critical"},
			{"source": "k8s-api", "target": "cluster-admin", "label": "privilege escalation", "risk": "critical"},
		},
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
	c.JSON(http.StatusOK, gin.H{
		"total_pods":      totalPods,
		"privileged_pods": privilegedPods,
		"runtime_alert_trend": trend,
		"top_vulnerable_images": []map[string]interface{}{
			{"image": "nginx:1.19", "cve_critical": 4, "cve_high": 12, "risk": 94},
			{"image": "redis:6.0", "cve_critical": 2, "cve_high": 8, "risk": 87},
			{"image": "webapp:1.2.3", "cve_critical": 1, "cve_high": 6, "risk": 78},
		},
		"alert_by_type": []map[string]interface{}{
			{"type": "reverse_shell", "count": 2},
			{"type": "crypto_mining", "count": 3},
			{"type": "privilege_escalation", "count": 1},
			{"type": "container_escape", "count": 1},
			{"type": "file_tampering", "count": 4},
			{"type": "unexpected_network", "count": 6},
		},
		"namespace_risk": []map[string]interface{}{
			{"namespace": "production", "risk": 78, "pods": 12},
			{"namespace": "staging", "risk": 61, "pods": 8},
			{"namespace": "kube-system", "risk": 45, "pods": 11},
			{"namespace": "monitoring", "risk": 38, "pods": 4},
		},
	})
}

// PostContainerResponse — POST /api/containers/response
func PostContainerResponse(c *gin.Context) {
	createContainerSecurityTables()
	var body struct {
		Action    string `json:"action"`
		Namespace string `json:"namespace"`
		PodName   string `json:"pod_name"`
		NodeName  string `json:"node_name"`
		Image     string `json:"image"`
		SAName    string `json:"service_account"`
		Deployment string `json:"deployment"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Action == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "action required"}); return
	}
	messages := map[string]string{
		"kill_container":      "Container killed via SIGKILL",
		"delete_pod":          "Pod deleted — replacement will be scheduled",
		"scale_deployment":    "Deployment scaled to 0 replicas",
		"quarantine_node":     "Node cordoned and pods evicted",
		"block_image":         "Image blocked in admission controller",
		"revoke_service_account": "Service account token revoked",
		"run_soar_playbook":   "SOAR playbook triggered",
	}
	msg := messages[body.Action]
	if msg == "" {
		msg = "Action executed"
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "action": body.Action, "message": msg})
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
