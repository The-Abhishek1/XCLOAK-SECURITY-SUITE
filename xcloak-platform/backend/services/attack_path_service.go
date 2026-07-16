package services

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"xcloak-platform/database"
	"xcloak-platform/models"
	"xcloak-platform/repositories"
)

// TechniqueRef is a minimal MITRE ATT&CK reference attached to an edge or path.
type TechniqueRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// portTechniques maps well-known lateral-movement ports to the most specific
// MITRE ATT&CK (sub-)technique for that channel.
var portTechniques = map[string]TechniqueRef{
	"3389": {ID: "T1021.001", Name: "Remote Desktop Protocol"},
	"445":  {ID: "T1021.002", Name: "SMB / Windows Admin Shares"},
	"139":  {ID: "T1021.002", Name: "SMB / Windows Admin Shares"},
	"22":   {ID: "T1021.004", Name: "SSH"},
	"23":   {ID: "T1021.003", Name: "Telnet"},
	"5985": {ID: "T1021.006", Name: "Windows Remote Management"},
	"5986": {ID: "T1021.006", Name: "Windows Remote Management"},
	"135":  {ID: "T1047", Name: "Windows Management Instrumentation"},
	"5900": {ID: "T1021.005", Name: "VNC"},
	"4444": {ID: "T1059", Name: "Command and Scripting Interpreter"},
	"4445": {ID: "T1059", Name: "Command and Scripting Interpreter"},
	"8080": {ID: "T1190", Name: "Exploit Public-Facing Application"},
	"8443": {ID: "T1190", Name: "Exploit Public-Facing Application"},
}

// kindTechniques is the fallback when no port-level match is found.
var kindTechniques = map[string]TechniqueRef{
	"internet_exposure": {ID: "T1190", Name: "Exploit Public-Facing Application"},
	"lateral":           {ID: "T1021", Name: "Remote Services"},
	"priv_esc":          {ID: "T1068", Name: "Exploitation for Privilege Escalation"},
	"cloud_jump":        {ID: "T1078.004", Name: "Valid Accounts: Cloud Accounts"},
	"container_escape":  {ID: "T1611", Name: "Escape to Host"},
}

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
	Exposed        bool    `json:"exposed"`
	CompromiseCost float64 `json:"compromise_cost"`
	OpenAlertCount int     `json:"open_alert_count"`
	// Enriched fields computed after graph construction.
	BlastRadius    int    `json:"blast_radius,omitempty"`
	IsChokepoint   bool   `json:"is_chokepoint,omitempty"`
	PrivLevel      string `json:"priv_level,omitempty"`
	KillChainPhase string `json:"kill_chain_phase,omitempty"`
}

// AttackPathEdge is reachability, not necessarily live traffic direction —
// built from observed connections (agent-to-agent = lateral movement
// opportunity; internet-to-agent = an externally-reachable entry point).
type AttackPathEdge struct {
	Source        string `json:"source"`
	Target        string `json:"target"`
	Kind          string `json:"kind"` // "internet_exposure" | "lateral" | "priv_esc"
	TechniqueID   string `json:"technique_id,omitempty"`
	TechniqueName string `json:"technique_name,omitempty"`
	Description   string `json:"description,omitempty"`
}

// RankedAttackPath is one candidate route an attacker could take from the
// internet to a real asset, ranked by how cheap the path is to traverse
// relative to how valuable (risky/KEV-exposed) the target is.
type RankedAttackPath struct {
	Hops            []string       `json:"hops"` // node IDs, internet -> ... -> target
	TotalCost       float64        `json:"total_cost"`
	TargetHostname  string         `json:"target_hostname"`
	TargetRiskLevel string         `json:"target_risk_level"`
	Score           float64        `json:"score"`
	PathType        string         `json:"path_type,omitempty"`   // "lateral" | "priv_esc"
	KillChainPhases []string       `json:"kill_chain_phases,omitempty"`
	Techniques      []TechniqueRef `json:"techniques,omitempty"`
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

// portFromAddress extracts the port string from an "ip:port" address.
// Returns empty string if no port is present or parsing fails.
func portFromAddress(addr string) string {
	if pct := strings.Index(addr, "%"); pct >= 0 {
		if colon := strings.LastIndex(addr, ":"); colon > pct {
			addr = addr[:pct] + addr[colon:]
		}
	}
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return ""
	}
	return port
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

// edgeTechnique returns the best technique for an edge — port-specific if
// available, otherwise the kind-level fallback.
func edgeTechnique(kind, port string) TechniqueRef {
	if (kind == "lateral" || kind == "priv_esc") && port != "" {
		if t, ok := portTechniques[port]; ok {
			return t
		}
	}
	if t, ok := kindTechniques[kind]; ok {
		return t
	}
	return TechniqueRef{}
}

// inferPrivLevel returns a coarse privilege classification derived from the
// node's exploitability signal. Not a substitute for real AD/identity data,
// but gives the SOC a useful first signal without any new DB queries.
func inferPrivLevel(n *AttackPathNode) string {
	if n.HasKEV && n.RiskScore >= 60 {
		return "admin"
	}
	if n.RiskScore >= 70 {
		return "elevated"
	}
	if n.RiskScore >= 45 {
		return "standard"
	}
	return "user"
}

// inferKillChainPhase maps a node's structural role in the graph to the
// most likely ATT&CK kill-chain phase. Applied after blast_radius and
// is_chokepoint are computed so those fields can inform the assignment.
func inferKillChainPhase(n *AttackPathNode, totalAgents int) string {
	if n.Type == "internet" {
		return "reconnaissance"
	}
	if n.Exposed {
		return "initial_access"
	}
	if n.HasKEV {
		return "exploitation"
	}
	if n.IsChokepoint {
		return "lateral_movement"
	}
	if n.RiskScore >= 70 {
		return "persistence"
	}
	if totalAgents > 0 && n.BlastRadius >= totalAgents/3 {
		return "collection"
	}
	return "execution"
}

// bfsReachable returns the count of nodes reachable from startID in the
// undirected adjacency graph, excluding startID and the internet node itself.
func bfsReachable(startID string, adj map[string][]string) int {
	visited := map[string]bool{startID: true}
	q := []string{startID}
	for len(q) > 0 {
		cur := q[0]
		q = q[1:]
		for _, next := range adj[cur] {
			if !visited[next] {
				visited[next] = true
				q = append(q, next)
			}
		}
	}
	count := 0
	for id := range visited {
		if id != startID && id != internetNodeID {
			count++
		}
	}
	return count
}

// BuildAttackPathGraph composes observed network connections, EPSS/KEV
// exploitability, and risk scores into a graph of how an attacker could
// pivot from the public internet to the tenant's assets — and ranks the
// cheapest paths to the most valuable targets.
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

	openAlerts, err := openAlertCountsByAgent(tenantID)
	if err != nil {
		openAlerts = map[int]int{} // non-fatal
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

	makeNodeID := func(agentID int) string { return fmt.Sprintf("agent-%d", agentID) }

	nodes := make(map[string]*AttackPathNode, len(agents)+1)
	nodes[internetNodeID] = &AttackPathNode{ID: internetNodeID, Type: "internet"}

	for _, a := range agents {
		n := &AttackPathNode{
			ID:        makeNodeID(a.ID),
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
		n.OpenAlertCount = openAlerts[a.ID]

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

	// ── Edge construction ────────────────────────────────────────────────────
	// Dedup by ordered pair (source|target) regardless of kind so each pair
	// of nodes has exactly one edge. priv_esc connections are processed in a
	// second pass, so the first-seen connection wins for port-technique lookup.

	pairSeen := map[string]bool{} // "source|target" or "target|source"
	var edges []AttackPathEdge
	adjacency := map[string][]string{} // undirected; used for Dijkstra + blast_radius

	addEdge := func(source, target, kind, port string) {
		fwd := source + "|" + target
		rev := target + "|" + source
		if pairSeen[fwd] || pairSeen[rev] {
			return
		}
		pairSeen[fwd] = true

		tech := edgeTechnique(kind, port)
		e := AttackPathEdge{
			Source:        source,
			Target:        target,
			Kind:          kind,
			TechniqueID:   tech.ID,
			TechniqueName: tech.Name,
		}
		edges = append(edges, e)

		adjacency[source] = append(adjacency[source], target)
		// lateral and priv_esc are bidirectional reachability for Dijkstra.
		if kind == "lateral" || kind == "priv_esc" {
			adjacency[target] = append(adjacency[target], source)
		}
	}

	for _, c := range conns {
		if c.State != "ESTABLISHED" {
			continue
		}
		host := hostFromAddress(c.RemoteAddress)
		if isListenPlaceholder(host) {
			continue
		}
		srcID := makeNodeID(c.AgentID)
		if _, ok := nodes[srcID]; !ok {
			continue
		}

		port := portFromAddress(c.RemoteAddress)

		if remoteAgent, ok := agentByIP[host]; ok {
			if remoteAgent.ID == c.AgentID {
				continue
			}
			addEdge(srcID, makeNodeID(remoteAgent.ID), "lateral", port)
			continue
		}

		if !isPrivateIP(host) {
			nodes[srcID].Exposed = true
			addEdge(internetNodeID, srcID, "internet_exposure", port)
		}
	}

	// ── Privilege escalation upgrade pass ───────────────────────────────────
	// Re-classify lateral edges where the target is significantly more
	// exploitable than the source and has an actively-exploited (KEV) vuln.
	// This is the best heuristic available without actual AD/privilege data.
	for i, e := range edges {
		if e.Kind != "lateral" {
			continue
		}
		src, sok := nodes[e.Source]
		tgt, tok := nodes[e.Target]
		if !sok || !tok {
			continue
		}
		if tgt.HasKEV && tgt.RiskScore >= 60 && tgt.RiskScore > src.RiskScore+15 {
			edges[i].Kind = "priv_esc"
			t := edgeTechnique("priv_esc", "")
			edges[i].TechniqueID = t.ID
			edges[i].TechniqueName = t.Name
			edges[i].Description = "Target has known-exploited CVE and significantly higher risk score — privilege escalation likely."
		}
	}

	// ── Blast radius ─────────────────────────────────────────────────────────
	// BFS from each agent node through the undirected adjacency map.
	// Tells the SOC: "if this host is compromised, how many others are exposed?"
	for id, n := range nodes {
		if n.Type == "internet" {
			continue
		}
		n.BlastRadius = bfsReachable(id, adjacency)
	}

	// ── Dijkstra + path ranking ──────────────────────────────────────────────
	hasEntryPoint := len(adjacency[internetNodeID]) > 0
	dist, prev := dijkstraFromInternet(nodes, adjacency)
	topPaths := rankAttackPaths(nodes, dist, prev)

	// ── Chokepoint detection ─────────────────────────────────────────────────
	// A node is a chokepoint if it appears in ≥2 of the top paths, or if it
	// is the only path to one or more targets (appears in all ranked paths).
	hopCount := map[string]int{}
	for _, p := range topPaths {
		for _, h := range p.Hops {
			if h != internetNodeID {
				hopCount[h]++
			}
		}
	}
	chokepointThreshold := 2
	if len(topPaths) == 1 {
		chokepointThreshold = 1
	}
	for id, cnt := range hopCount {
		if cnt >= chokepointThreshold {
			if n, ok := nodes[id]; ok {
				n.IsChokepoint = true
			}
		}
	}

	// ── Per-node enrichment ──────────────────────────────────────────────────
	totalAgents := len(agents)
	for _, n := range nodes {
		if n.Type == "internet" {
			n.KillChainPhase = "reconnaissance"
			continue
		}
		n.PrivLevel = inferPrivLevel(n)
		n.KillChainPhase = inferKillChainPhase(n, totalAgents)
	}

	// ── Path-level enrichment ────────────────────────────────────────────────
	// Build a lookup so we can walk path hops → edges → techniques.
	edgeByPair := map[string]AttackPathEdge{}
	for _, e := range edges {
		edgeByPair[e.Source+"|"+e.Target] = e
		edgeByPair[e.Target+"|"+e.Source] = e // bidirectional lookup
	}

	for i, p := range topPaths {
		techSeen := map[string]bool{}
		phaseSeen := map[string]bool{}
		var techs []TechniqueRef
		var phases []string
		hasPrivEsc := false

		for j := 0; j < len(p.Hops)-1; j++ {
			fwd := p.Hops[j] + "|" + p.Hops[j+1]
			if e, ok := edgeByPair[fwd]; ok {
				if e.TechniqueID != "" && !techSeen[e.TechniqueID] {
					techSeen[e.TechniqueID] = true
					techs = append(techs, TechniqueRef{ID: e.TechniqueID, Name: e.TechniqueName})
				}
				if e.Kind == "priv_esc" {
					hasPrivEsc = true
				}
			}
			// Collect kill-chain phases from the destination node of each hop.
			if n, ok := nodes[p.Hops[j+1]]; ok && n.KillChainPhase != "" {
				if !phaseSeen[n.KillChainPhase] {
					phaseSeen[n.KillChainPhase] = true
					phases = append(phases, n.KillChainPhase)
				}
			}
		}

		topPaths[i].Techniques = techs
		topPaths[i].KillChainPhases = phases
		if hasPrivEsc {
			topPaths[i].PathType = "priv_esc"
		} else {
			topPaths[i].PathType = "lateral"
		}
	}

	// ── Serialise nodes ──────────────────────────────────────────────────────
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
// entering a node is that node's CompromiseCost.
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
// top 5 with their full hop sequence reconstructed from the predecessor map.
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
			continue
		}
		pathCost := dist[id]
		if pathCost <= 0 {
			pathCost = 0.001
		}
		candidates = append(candidates, candidate{id: id, score: value / pathCost})
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

// openAlertCountsByAgent returns a map of agent_id → count of open, non-snoozed
// alerts. Used to annotate attack-path nodes with live alert pressure so the
// SOC can see which nodes are actively firing, not just historically risky.
func openAlertCountsByAgent(tenantID int) (map[int]int, error) {
	rows, err := database.DB.Query(`
		SELECT agent_id, COUNT(*) FROM alerts
		WHERE tenant_id = $1
		  AND status = 'open'
		  AND (suppressed_until IS NULL OR suppressed_until < NOW())
		GROUP BY agent_id
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int]int{}
	for rows.Next() {
		var id, cnt int
		if rows.Scan(&id, &cnt) == nil {
			out[id] = cnt
		}
	}
	return out, nil
}
