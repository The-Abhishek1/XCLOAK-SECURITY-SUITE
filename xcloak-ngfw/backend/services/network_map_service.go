package services

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"xcloak-ngfw/models"
	"xcloak-ngfw/repositories"
)

// NetworkMapNode is one host in the fleet-wide network map — either a real
// agent or an external IP observed in outbound connect events.
type NetworkMapNode struct {
	ID        string `json:"id"`
	Type      string `json:"type"` // "agent" | "external_ip"
	AgentID   int    `json:"agent_id,omitempty"`
	Hostname  string `json:"hostname,omitempty"`
	IP        string `json:"ip,omitempty"`
	Zone      string `json:"zone"` // "internal" | "dmz" | "external"
	Country   string `json:"country,omitempty"`
	RiskScore int    `json:"risk_score"`
	RiskLevel string `json:"risk_level"`
}

// NetworkMapEdge is an aggregated view of every connect event sharing the
// same source agent, destination host, port, protocol, and process — the
// raw network_connect_events stream is a pure append log, so a "map" needs
// to collapse repeated connects into one edge with a count and last-seen
// time rather than rendering every individual event.
type NetworkMapEdge struct {
	Source   string    `json:"source"`
	Target   string    `json:"target"`
	Protocol string    `json:"protocol"`
	Port     string    `json:"port"`
	Process  string    `json:"process"`
	Count    int       `json:"count"`
	LastSeen time.Time `json:"last_seen"`
}

type NetworkMapGraph struct {
	Nodes       []NetworkMapNode `json:"nodes"`
	Edges       []NetworkMapEdge `json:"edges"`
	GeneratedAt time.Time        `json:"generated_at"`
}

const maxNetworkMapEdges = 500

// BuildNetworkMap aggregates the eBPF-sourced network_connect_events stream
// into a fleet-wide graph: one node per agent plus one per distinct external
// IP, edges collapsed by source/destination/port/protocol/process, nodes
// zoned internal/dmz/external and colored by the same asset risk score used
// by the attack-path graph.
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
			ID:        agentNodeID(a.ID),
			Type:      "agent",
			AgentID:   a.ID,
			Hostname:  a.Hostname,
			IP:        a.IPAddress,
			Zone:      "internal",
			RiskLevel: "unknown",
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
			continue // event from an agent outside this tenant's current agent list
		}

		host := hostFromAddress(ev.RemoteAddress)
		if isListenPlaceholder(host) {
			continue
		}

		var dstID string
		if remoteAgent, ok := agentByIP[host]; ok {
			if remoteAgent.ID == ev.AgentID {
				continue // loopback to self, not a meaningful edge
			}
			dstID = agentNodeID(remoteAgent.ID)
		} else {
			dstID = externalNodeID(host)
			if _, exists := nodes[dstID]; !exists {
				nodes[dstID] = &NetworkMapNode{
					ID:        dstID,
					Type:      "external_ip",
					IP:        host,
					Zone:      "external",
					RiskLevel: "unknown",
				}
			}
			// An internal agent reaching an external IP is, by definition,
			// internet-exposed — promote it out of the plain "internal"
			// zone so it reads differently on the map than an agent that
			// only ever talks to other internal agents.
			src.Zone = "dmz"
		}

		port := ""
		if idx := strings.LastIndex(ev.RemoteAddress, ":"); idx >= 0 {
			port = ev.RemoteAddress[idx+1:]
		}

		key := srcID + "|" + dstID + "|" + port + "|" + ev.Protocol + "|" + ev.Comm
		agg, ok := edgeAggs[key]
		if !ok {
			agg = &edgeAgg{}
			edgeAggs[key] = agg
			edgeMeta[key] = NetworkMapEdge{
				Source: srcID, Target: dstID, Protocol: ev.Protocol,
				Port: port, Process: ev.Comm,
			}
		}
		agg.count++
		if ev.CreatedAt.After(agg.lastSeen) {
			agg.lastSeen = ev.CreatedAt
		}
	}

	// Cache-only GeoIP enrichment for external nodes — no live lookups
	// during graph build, so the endpoint stays fast even with many
	// never-before-seen external IPs.
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

	return &NetworkMapGraph{
		Nodes:       outNodes,
		Edges:       edges,
		GeneratedAt: time.Now(),
	}, nil
}
