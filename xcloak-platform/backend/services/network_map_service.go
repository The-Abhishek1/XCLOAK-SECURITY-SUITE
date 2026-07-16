package services

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"xcloak-platform/database"
	"xcloak-platform/models"
	"xcloak-platform/repositories"
)

type NetworkMapNode struct {
	ID          string `json:"id"`
	Type        string `json:"type"` // "agent"|"external_ip"|"firewall"|"router"|"switch"|"vpn"|"wireless"|"cloud"|"wan"
	AgentID     int    `json:"agent_id,omitempty"`
	Hostname    string `json:"hostname,omitempty"`
	IP          string `json:"ip,omitempty"`
	Zone        string `json:"zone"` // "internal" | "dmz" | "external"
	Country     string `json:"country,omitempty"`
	RiskScore   int    `json:"risk_score"`
	RiskLevel   string `json:"risk_level"`
	Status      string `json:"status,omitempty"`     // "online" | "offline"
	AlertCount  int    `json:"alert_count"`           // unacknowledged alerts
	IsIOC       bool   `json:"is_ioc"`
	IOCSeverity string `json:"ioc_severity,omitempty"`
	Role        string `json:"role,omitempty"`        // "server"|"workstation"|"mobile"|"network"|"endpoint"
	VLAN        string `json:"vlan,omitempty"`        // /24 subnet used as VLAN grouping label
}

type NetworkMapEdge struct {
	Source          string    `json:"source"`
	Target          string    `json:"target"`
	Protocol        string    `json:"protocol"`
	Port            string    `json:"port"`
	Service         string    `json:"service,omitempty"`          // human name, e.g. "HTTPS"
	PortSensitivity string    `json:"port_sensitivity,omitempty"` // safe|neutral|sensitive|critical
	PortNote        string    `json:"port_note,omitempty"`        // reason string
	Process         string    `json:"process"`
	Count           int       `json:"count"`
	LastSeen        time.Time `json:"last_seen"`
	EdgeType        string    `json:"edge_type"` // "internal" | "external"
}

type NetworkMapSummary struct {
	TotalAgents   int `json:"total_agents"`
	OnlineAgents  int `json:"online_agents"`
	ExternalIPs   int `json:"external_ips"`
	TotalEdges    int `json:"total_edges"`
	IOCHits       int `json:"ioc_hits"`
	AlertingNodes int `json:"alerting_nodes"`
}

type NetworkMapGraph struct {
	Nodes       []NetworkMapNode  `json:"nodes"`
	Edges       []NetworkMapEdge  `json:"edges"`
	Summary     NetworkMapSummary `json:"summary"`
	GeneratedAt time.Time         `json:"generated_at"`
}

const maxNetworkMapEdges = 500

// ── Node classification helpers ──────────────────────────────────────────────

// hostnameKeywords maps substrings (lower-cased) found in hostnames to node
// types. Ordered so more-specific matches (e.g. "openvpn") come before their
// prefixes (e.g. "vpn").
var hostnameKeywords = []struct {
	substr   string
	nodeType string
}{
	// Firewall
	{"firewall", "firewall"}, {"pfsense", "firewall"}, {"fortigate", "firewall"},
	{"paloalto", "firewall"}, {"-asa-", "firewall"}, {"asa01", "firewall"},
	{"asa02", "firewall"}, {"checkpoint", "firewall"}, {"sonicwall", "firewall"},
	// fw prefix/suffix patterns
	{"fw-", "firewall"}, {"-fw-", "firewall"}, {"-fw", "firewall"},
	// Router / gateway
	{"router", "router"}, {"-rtr", "router"}, {"rtr-", "router"},
	{"gateway", "router"}, {"-gw-", "router"}, {"-gw", "router"},
	{"gw-", "router"}, {"core-r", "router"}, {"dist-r", "router"},
	{"edge-r", "router"},
	// Switch
	{"switch", "switch"}, {"-sw-", "switch"}, {"sw-", "switch"},
	{"-sw", "switch"}, {"core-sw", "switch"}, {"dist-sw", "switch"},
	{"access-sw", "switch"},
	// VPN (check after "openvpn" fragment would match "vpn" anyway, so order fine)
	{"openvpn", "vpn"}, {"wireguard", "vpn"}, {"-vpn-", "vpn"},
	{"vpn-", "vpn"}, {"-vpn", "vpn"},
	// Wireless / access-point
	{"wireless", "wireless"}, {"wifi", "wireless"}, {"wlan", "wireless"},
	{"-ap-", "wireless"}, {"ap-", "wireless"}, {"-ap", "wireless"},
	{"access-point", "wireless"}, {"accesspoint", "wireless"},
}

// cloudCIDRs holds the parsed CIDR blocks for major cloud providers.
// Initialised once in init(); covers AWS, Azure, GCP, and Cloudflare.
var cloudCIDRs []*net.IPNet

func init() {
	raw := []string{
		// AWS
		"3.0.0.0/8", "13.32.0.0/15", "13.64.0.0/11", "18.0.0.0/8",
		"52.0.0.0/8", "54.0.0.0/8", "99.77.128.0/17", "143.204.0.0/16",
		// Azure
		"13.64.0.0/11", "20.0.0.0/8", "40.64.0.0/10", "51.0.0.0/8",
		"104.40.0.0/13", "168.61.0.0/16",
		// GCP
		"34.0.0.0/8", "35.184.0.0/13", "104.154.0.0/15", "104.196.0.0/14",
		"108.170.192.0/18", "172.217.0.0/16", "173.194.0.0/16",
		// Cloudflare
		"104.16.0.0/12", "141.101.64.0/18", "162.158.0.0/15",
		"172.64.0.0/13", "198.41.128.0/17",
		// Digital Ocean
		"104.131.0.0/16", "159.65.0.0/16", "167.99.0.0/16",
		// Hetzner
		"95.216.0.0/16", "116.202.0.0/15", "157.90.0.0/16",
		// Linode / Akamai
		"45.33.0.0/17", "45.56.0.0/21", "96.126.96.0/19", "172.104.0.0/14",
	}
	for _, cidr := range raw {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err == nil {
			cloudCIDRs = append(cloudCIDRs, ipNet)
		}
	}
}

// isCloudIP returns true if ip falls within a known cloud provider CIDR.
func isCloudIP(ip net.IP) bool {
	for _, cidr := range cloudCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// inferAgentNodeType classifies an enrolled agent into the most specific node
// type available, falling back to "agent" when no signal is found.
func inferAgentNodeType(hostname, platformCategory string, vpnActive *bool) string {
	// Android agents with VPN active are VPN endpoints.
	if vpnActive != nil && *vpnActive {
		return "vpn"
	}
	h := strings.ToLower(hostname)
	for _, kw := range hostnameKeywords {
		if strings.Contains(h, kw.substr) {
			return kw.nodeType
		}
	}
	return "agent"
}

// inferNodeRole returns a coarse device role derived from OS/platform metadata.
// "server" | "workstation" | "mobile" | "network" | "endpoint"
func inferNodeRole(hostname, os, platformCategory string) string {
	switch strings.ToLower(platformCategory) {
	case "android":
		return "mobile"
	case "macos":
		return "workstation"
	}
	osLower := strings.ToLower(os)
	h := strings.ToLower(hostname)

	// Explicit network device keywords in hostname → network role.
	for _, kw := range hostnameKeywords {
		if strings.Contains(h, kw.substr) {
			return "network"
		}
	}

	if strings.Contains(osLower, "server") ||
		strings.Contains(osLower, "ubuntu") ||
		strings.Contains(osLower, "debian") ||
		strings.Contains(osLower, "centos") ||
		strings.Contains(osLower, "rhel") ||
		strings.Contains(osLower, "alpine") ||
		platformCategory == "linux" {
		return "server"
	}
	if strings.Contains(osLower, "windows") {
		if strings.Contains(osLower, "server") || strings.Contains(h, "srv") ||
			strings.Contains(h, "server") || strings.Contains(h, "dc") {
			return "server"
		}
		return "workstation"
	}
	return "endpoint"
}

// inferVLAN returns a /24 subnet label used as a VLAN-like grouping key.
// e.g. "192.168.1.0/24". Returns "" for IPv6 or unparseable addresses.
func inferVLAN(ipStr string) string {
	ip := net.ParseIP(ipStr).To4()
	if ip == nil {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.0/24", ip[0], ip[1], ip[2])
}

// portEdgeInfo returns the service name, sensitivity, and note for a port.
// Uses the shared portInfoMap from ip_enrich.go; falls back to empty strings.
func portEdgeInfo(port string) (service, sensitivity, note string) {
	if info := GetPortInfo(port); info != nil {
		return info.Service, info.Sensitivity, info.Note
	}
	return "", "", ""
}

// alertCountsByAgent returns a map of agent_id → unacked alert count for a tenant.
func alertCountsByAgent(tenantID int) (map[int]int, error) {
	rows, err := database.DB.Query(
		`SELECT agent_id, COUNT(*) FROM alerts
		 WHERE tenant_id=$1 AND acknowledged=false
		 GROUP BY agent_id`,
		tenantID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int]int{}
	for rows.Next() {
		var id, cnt int
		if err := rows.Scan(&id, &cnt); err == nil {
			out[id] = cnt
		}
	}
	return out, nil
}

// iocIPSet returns a set of enabled IP-type IOC indicators for the tenant,
// mapping indicator → severity so the frontend can color-code them.
func iocIPSet(tenantID int) (map[string]string, error) {
	rows, err := database.DB.Query(
		`SELECT indicator, severity FROM iocs
		 WHERE tenant_id=$1 AND enabled=true AND type='ip'`,
		tenantID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var indicator, severity string
		if err := rows.Scan(&indicator, &severity); err == nil {
			out[indicator] = severity
		}
	}
	return out, nil
}

func BuildNetworkMap(tenantID int, since time.Time, limit int) (*NetworkMapGraph, error) {

	agents, err := repositories.GetAgents(tenantID)
	if err != nil {
		return nil, fmt.Errorf("loading agents: %w", err)
	}

	risks, err := repositories.GetRiskScoresByTenant(tenantID)
	if err != nil {
		return nil, fmt.Errorf("loading risk scores: %w", err)
	}

	events, err := repositories.GetConnectEventsByTenant(tenantID, since, limit)
	if err != nil {
		return nil, fmt.Errorf("loading connect events: %w", err)
	}

	// Always supplement with endpoint_connections (the periodic ss-snapshot
	// collector). This is the primary data source when the eBPF module is not
	// running (non-root / non-Linux agents). Deduplication is handled by the
	// edge aggregation map below.
	epConns, err := repositories.GetEndpointConnectionsByTenant(tenantID, limit)
	if err == nil {
		events = append(events, epConns...)
	}

	alertCounts, err := alertCountsByAgent(tenantID)
	if err != nil {
		alertCounts = map[int]int{} // non-fatal
	}

	iocIPs, err := iocIPSet(tenantID)
	if err != nil {
		iocIPs = map[string]string{} // non-fatal
	}

	riskByAgent := map[int]models.AssetRiskScore{}
	for _, r := range risks {
		riskByAgent[r.AgentID] = r
	}

	agentNodeID := func(agentID int) string { return fmt.Sprintf("agent-%d", agentID) }
	externalNodeID := func(host string) string { return "ext-" + host }

	agentByIP := map[string]models.Agent{}
	nodes := map[string]*NetworkMapNode{}
	for _, a := range agents {
		if a.IPAddress != "" {
			agentByIP[a.IPAddress] = a
		}
		n := &NetworkMapNode{
			ID:         agentNodeID(a.ID),
			Type:       inferAgentNodeType(a.Hostname, a.PlatformCategory, a.VPNActive),
			AgentID:    a.ID,
			Hostname:   a.Hostname,
			IP:         a.IPAddress,
			Zone:       "internal",
			RiskLevel:  "unknown",
			Status:     a.Status,
			AlertCount: alertCounts[a.ID],
			Role:       inferNodeRole(a.Hostname, a.OS, a.PlatformCategory),
			VLAN:       inferVLAN(a.IPAddress),
		}
		if r, ok := riskByAgent[a.ID]; ok {
			n.RiskScore = r.RiskScore
			n.RiskLevel = r.RiskLevel
		}
		nodes[n.ID] = n
	}

	type edgeAgg struct {
		count    int
		lastSeen time.Time
	}
	edgeAggs := map[string]*edgeAgg{}
	edgeMeta := map[string]NetworkMapEdge{}

	for _, ev := range events {
		srcID := agentNodeID(ev.AgentID)
		src, ok := nodes[srcID]
		if !ok {
			continue
		}

		host := hostFromAddress(ev.RemoteAddress)
		if isListenPlaceholder(host) {
			continue
		}
		// Drop any address that doesn't parse as a valid IP (hex artefacts, brackets, etc.)
		if net.ParseIP(host) == nil {
			continue
		}

		port := ""
		if idx := strings.LastIndex(ev.RemoteAddress, ":"); idx >= 0 {
			port = ev.RemoteAddress[idx+1:]
		}

		var dstID string
		edgeType := "external"
		if remoteAgent, ok := agentByIP[host]; ok {
			if remoteAgent.ID == ev.AgentID {
				continue
			}
			dstID = agentNodeID(remoteAgent.ID)
			edgeType = "internal"
		} else {
			dstID = externalNodeID(host)
			if _, exists := nodes[dstID]; !exists {
				iocSev := iocIPs[host]
				parsedIP := net.ParseIP(host)
				extType := "external_ip"
				if parsedIP != nil && isCloudIP(parsedIP) {
					extType = "cloud"
				}
				nodes[dstID] = &NetworkMapNode{
					ID:          dstID,
					Type:        extType,
					IP:          host,
					Zone:        "external",
					RiskLevel:   "unknown",
					IsIOC:       iocSev != "",
					IOCSeverity: iocSev,
				}
			}
			src.Zone = "dmz"
		}

		key := srcID + "|" + dstID + "|" + port + "|" + ev.Protocol + "|" + ev.Comm
		agg, ok := edgeAggs[key]
		if !ok {
			agg = &edgeAgg{}
			edgeAggs[key] = agg
			svc, sensitivity, note := portEdgeInfo(port)
			edgeMeta[key] = NetworkMapEdge{
				Source:          srcID,
				Target:          dstID,
				Protocol:        ev.Protocol,
				Port:            port,
				Service:         svc,
				PortSensitivity: sensitivity,
				PortNote:        note,
				Process:         ev.Comm,
				EdgeType:        edgeType,
			}
		}
		agg.count++
		if ev.CreatedAt.After(agg.lastSeen) {
			agg.lastSeen = ev.CreatedAt
		}
	}

	// Cache-only GeoIP enrichment for external nodes.
	for _, n := range nodes {
		if n.Type != "external_ip" {
			continue
		}
		if cached := getGeoIPCache(n.IP); cached != nil {
			n.Country = cached.Country
		}
	}

	edges := make([]NetworkMapEdge, 0, len(edgeMeta))
	for key, meta := range edgeMeta {
		agg := edgeAggs[key]
		meta.Count = agg.count
		meta.LastSeen = agg.lastSeen
		edges = append(edges, meta)
	}
	sort.Slice(edges, func(i, j int) bool { return edges[i].Count > edges[j].Count })
	if len(edges) > maxNetworkMapEdges {
		edges = edges[:maxNetworkMapEdges]
	}

	outNodes := make([]NetworkMapNode, 0, len(nodes))
	for _, n := range nodes {
		outNodes = append(outNodes, *n)
	}
	sort.Slice(outNodes, func(i, j int) bool { return outNodes[i].ID < outNodes[j].ID })

	// Build summary.
	summary := NetworkMapSummary{TotalEdges: len(edges)}
	for _, n := range outNodes {
		switch n.Type {
		case "agent":
			summary.TotalAgents++
			if n.Status == "online" {
				summary.OnlineAgents++
			}
			if n.AlertCount > 0 {
				summary.AlertingNodes++
			}
		case "external_ip":
			summary.ExternalIPs++
			if n.IsIOC {
				summary.IOCHits++
			}
		}
	}

	return &NetworkMapGraph{
		Nodes:       outNodes,
		Edges:       edges,
		Summary:     summary,
		GeneratedAt: time.Now(),
	}, nil
}
