package services

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"xcloak-platform/database"
	"xcloak-platform/models"
	"xcloak-platform/repositories"
)

type NetworkMapNode struct {
	ID          string `json:"id"`
	Type        string `json:"type"` // "agent" | "external_ip"
	AgentID     int    `json:"agent_id,omitempty"`
	Hostname    string `json:"hostname,omitempty"`
	IP          string `json:"ip,omitempty"`
	Zone        string `json:"zone"` // "internal" | "dmz" | "external"
	Country     string `json:"country,omitempty"`
	RiskScore   int    `json:"risk_score"`
	RiskLevel   string `json:"risk_level"`
	Status      string `json:"status,omitempty"`   // "online" | "offline"
	AlertCount  int    `json:"alert_count"`         // unacknowledged alerts
	IsIOC       bool   `json:"is_ioc"`
	IOCSeverity string `json:"ioc_severity,omitempty"`
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
			Type:       "agent",
			AgentID:    a.ID,
			Hostname:   a.Hostname,
			IP:         a.IPAddress,
			Zone:       "internal",
			RiskLevel:  "unknown",
			Status:     a.Status,
			AlertCount: alertCounts[a.ID],
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
				nodes[dstID] = &NetworkMapNode{
					ID:          dstID,
					Type:        "external_ip",
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
