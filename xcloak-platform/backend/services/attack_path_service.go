package services

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"xcloak-platform/models"
	"xcloak-platform/repositories"
)

// AttackPathNode is one host in the attack-path graph — either the
// synthetic "internet" entry point or a real agent annotated with the
// exploitability signal (EPSS/KEV/risk score) that determines how easy it
// is for an attacker who has reached this node to pivot further.
type AttackPathNode struct {
	ID             string  `json:"id"`
	Type           string  `json:"type"` // "internet" | "agent"
	AgentID        int     `json:"agent_id,omitempty"`
	Hostname       string  `json:"hostname,omitempty"`
	RiskScore      int     `json:"risk_score"`
	RiskLevel      string  `json:"risk_level"`
	MaxEPSS        float64 `json:"max_epss"`
	HasKEV         bool    `json:"has_kev"`
	KEVCount       int     `json:"kev_count"`
	Exposed        bool    `json:"exposed"` // has at least one observed connection to a public IP
	CompromiseCost float64 `json:"compromise_cost"`
}

// AttackPathEdge is reachability, not necessarily live traffic direction —
// built from observed connections (agent-to-agent = lateral movement
// opportunity; internet-to-agent = an externally-reachable entry point).
type AttackPathEdge struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Kind   string `json:"kind"` // "internet_exposure" | "lateral"
}

// RankedAttackPath is one candidate route an attacker could take from the
// internet to a real asset, ranked by how cheap the path is to traverse
// relative to how valuable (risky/KEV-exposed) the target is.
type RankedAttackPath struct {
	Hops            []string `json:"hops"` // node IDs, internet -> ... -> target
	TotalCost       float64  `json:"total_cost"`
	TargetHostname  string   `json:"target_hostname"`
	TargetRiskLevel string   `json:"target_risk_level"`
	Score           float64  `json:"score"`
}

type AttackPathGraph struct {
	Nodes         []AttackPathNode   `json:"nodes"`
	Edges         []AttackPathEdge   `json:"edges"`
	TopPaths      []RankedAttackPath `json:"top_paths"`
	HasEntryPoint bool               `json:"has_entry_point"`
}

const internetNodeID = "internet"

// hostFromAddress strips the ":port" from an "ip:port" or "[ipv6]:port"
// address using net.SplitHostPort. Also strips the interface-scope suffix
// that ss/ip occasionally produces (e.g. "192.168.1.1%eth0:68").
func hostFromAddress(addr string) string {
	// Strip scope ID before SplitHostPort ("1.2.3.4%eth0:68" → "1.2.3.4:68").
	if pct := strings.Index(addr, "%"); pct >= 0 {
		if colon := strings.LastIndex(addr, ":"); colon > pct {
			addr = addr[:pct] + addr[colon:]
		}
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		if idx := strings.LastIndex(addr, ":"); idx >= 0 {
			return addr[:idx]
		}
		return addr
	}
	return host
}

func isListenPlaceholder(ip string) bool {
	if ip == "" || ip == "0.0.0.0" || ip == "::" {
		return true
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	return parsed.IsLoopback()
}

// BuildAttackPathGraph composes observed network connections, EPSS/KEV
// exploitability, and risk scores into a graph of how an attacker could
// pivot from the public internet to the tenant's assets — and ranks the
// cheapest paths to the most valuable targets. Grounded entirely in data
// this codebase already collects; no synthetic/sample paths are invented.
func BuildAttackPathGraph(tenantID int) (*AttackPathGraph, error) {

	agents, err := repositories.GetAgents(tenantID)
	if err != nil {
		return nil, fmt.Errorf("loading agents: %w", err)
	}

	conns, err := repositories.GetConnectionsByTenant(tenantID)
	if err != nil {
		return nil, fmt.Errorf("loading connections: %w", err)
	}

	vulns, err := repositories.GetVulnerabilities(tenantID)
	if err != nil {
		return nil, fmt.Errorf("loading vulnerabilities: %w", err)
	}

	risks, err := repositories.GetRiskScoresByTenant(tenantID)
	if err != nil {
		return nil, fmt.Errorf("loading risk scores: %w", err)
	}

	agentByIP := map[string]models.Agent{}
	for _, a := range agents {
		if a.IPAddress != "" {
			agentByIP[a.IPAddress] = a
		}
	}

	riskByAgent := map[int]models.AssetRiskScore{}
	for _, r := range risks {
		riskByAgent[r.AgentID] = r
	}

	type vulnStats struct {
		maxEPSS  float64
		hasKEV   bool
		kevCount int
	}
	statsByAgent := map[int]*vulnStats{}
	for _, v := range vulns {
		s, ok := statsByAgent[v.AgentID]
		if !ok {
			s = &vulnStats{}
			statsByAgent[v.AgentID] = s
		}
		if v.EPSSScore > s.maxEPSS {
			s.maxEPSS = v.EPSSScore
		}
		if v.IsKEV {
			s.hasKEV = true
			s.kevCount++
		}
	}

	nodeID := func(agentID int) string { return fmt.Sprintf("agent-%d", agentID) }

	nodes := make(map[string]*AttackPathNode, len(agents)+1)
	nodes[internetNodeID] = &AttackPathNode{ID: internetNodeID, Type: "internet"}

	for _, a := range agents {
		n := &AttackPathNode{
			ID:        nodeID(a.ID),
			Type:      "agent",
			AgentID:   a.ID,
			Hostname:  a.Hostname,
			RiskLevel: "unknown",
		}
		if r, ok := riskByAgent[a.ID]; ok {
			n.RiskScore = r.RiskScore
			n.RiskLevel = r.RiskLevel
		}
		if s, ok := statsByAgent[a.ID]; ok {
			n.MaxEPSS = s.maxEPSS
			n.HasKEV = s.hasKEV
			n.KEVCount = s.kevCount
		}

		// Cheaper to traverse into a node that's already known-risky,
		// has a confirmed-actively-exploited (KEV) vuln, or a high EPSS
		// score — those are the realistic weak links, not a guess.
		cost := 100.0
		if n.HasKEV {
			cost -= 50
		}
		cost -= n.MaxEPSS * 30
		cost -= float64(n.RiskScore) * 0.3
		if cost < 1 {
			cost = 1
		}
		n.CompromiseCost = cost

		nodes[n.ID] = n
	}

	edgeSeen := map[string]bool{}
	edges := []AttackPathEdge{}
	adjacency := map[string][]string{} // undirected agent-agent + outgoing internet->agent

	addEdge := func(source, target, kind string) {
		key := kind + "|" + source + "|" + target
		revKey := kind + "|" + target + "|" + source
		if edgeSeen[key] || edgeSeen[revKey] {
			return
		}
		edgeSeen[key] = true
		edges = append(edges, AttackPathEdge{Source: source, Target: target, Kind: kind})
		adjacency[source] = append(adjacency[source], target)
		if kind == "lateral" {
			adjacency[target] = append(adjacency[target], source)
		}
	}

	for _, c := range conns {
		host := hostFromAddress(c.RemoteAddress)
		if isListenPlaceholder(host) {
			continue
		}
		srcID := nodeID(c.AgentID)
		if _, ok := nodes[srcID]; !ok {
			continue
		}

		if remoteAgent, ok := agentByIP[host]; ok {
			if remoteAgent.ID == c.AgentID {
				continue
			}
			addEdge(srcID, nodeID(remoteAgent.ID), "lateral")
			continue
		}

		if !isPrivateIP(host) {
			nodes[srcID].Exposed = true
			addEdge(internetNodeID, srcID, "internet_exposure")
		}
	}

	hasEntryPoint := len(adjacency[internetNodeID]) > 0

	dist, prev := dijkstraFromInternet(nodes, adjacency)

	topPaths := rankAttackPaths(nodes, dist, prev)

	outNodes := make([]AttackPathNode, 0, len(nodes))
	for _, n := range nodes {
		outNodes = append(outNodes, *n)
	}
	sort.Slice(outNodes, func(i, j int) bool { return outNodes[i].ID < outNodes[j].ID })

	return &AttackPathGraph{
		Nodes:         outNodes,
		Edges:         edges,
		TopPaths:      topPaths,
		HasEntryPoint: hasEntryPoint,
	}, nil
}

// dijkstraFromInternet computes the cheapest (easiest-to-traverse) path
// from the synthetic internet node to every agent node, where the cost of
// entering a node is that node's CompromiseCost. Graphs here are small
// (tenant's own fleet), so a plain O(V^2) Dijkstra without a heap is fine.
func dijkstraFromInternet(nodes map[string]*AttackPathNode, adjacency map[string][]string) (map[string]float64, map[string]string) {

	const inf = 1e18

	dist := map[string]float64{}
	prev := map[string]string{}
	visited := map[string]bool{}

	for id := range nodes {
		dist[id] = inf
	}
	dist[internetNodeID] = 0

	for {
		// Pick the closest unvisited node.
		var u string
		best := inf + 1
		for id, d := range dist {
			if !visited[id] && d < best {
				best = d
				u = id
			}
		}
		if u == "" || best >= inf {
			break
		}
		visited[u] = true

		for _, v := range adjacency[u] {
			if visited[v] {
				continue
			}
			cost := 0.0
			if n, ok := nodes[v]; ok && n.Type == "agent" {
				cost = n.CompromiseCost
			}
			alt := dist[u] + cost
			if alt < dist[v] {
				dist[v] = alt
				prev[v] = u
			}
		}
	}

	return dist, prev
}

// rankAttackPaths scores every internet-reachable agent by how valuable a
// target it is relative to how cheap the path to it was, and returns the
// top 5 with their full hop sequence reconstructed from Dijkstra's
// predecessor map.
func rankAttackPaths(nodes map[string]*AttackPathNode, dist map[string]float64, prev map[string]string) []RankedAttackPath {

	const inf = 1e18

	type candidate struct {
		id    string
		score float64
	}
	var candidates []candidate

	for id, n := range nodes {
		if n.Type != "agent" || dist[id] >= inf {
			continue
		}
		value := float64(n.RiskScore)
		if n.HasKEV {
			value += 50
		}
		if value <= 0 {
			continue // no signal this target is worth reaching
		}
		candidates = append(candidates, candidate{id: id, score: value / dist[id]})
	}

	sort.Slice(candidates, func(i, j int) bool { return candidates[i].score > candidates[j].score })

	limit := 5
	if len(candidates) < limit {
		limit = len(candidates)
	}

	out := make([]RankedAttackPath, 0, limit)
	for _, c := range candidates[:limit] {
		var hops []string
		for at := c.id; at != ""; at = prev[at] {
			hops = append([]string{at}, hops...)
			if at == internetNodeID {
				break
			}
		}
		target := nodes[c.id]
		out = append(out, RankedAttackPath{
			Hops:            hops,
			TotalCost:       dist[c.id],
			TargetHostname:  target.Hostname,
			TargetRiskLevel: target.RiskLevel,
			Score:           c.score,
		})
	}

	return out
}
