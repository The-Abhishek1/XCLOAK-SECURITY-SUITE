//go:build !windows

package agent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"time"
)

// StartFirewallStatsCollector runs a background goroutine that parses iptables
// per-rule packet counters every 60 seconds and reports them to the backend.
// It is a no-op if iptables is not installed or if the XCLOAK chain is empty.
func StartFirewallStatsCollector() {
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			collectAndReportFirewallHits()
		}
	}()
}

type firewallHitEntry struct {
	RuleID int   `json:"rule_id"`
	Hits   int64 `json:"hits"`
}

// commentRE matches the xcloak comment added by ruleToIPTables:
//
//	xcloak:<rule_id>:<name>
var commentRE = regexp.MustCompile(`xcloak:(\d+):`)

// lineRE captures the packet count at the start of a verbose iptables line:
//
//	   <pkts>   <bytes>  <target>  ...  /* comment */
var lineRE = regexp.MustCompile(`^\s*(\d+)`)

func collectAndReportFirewallHits() {
	if _, err := exec.LookPath("iptables"); err != nil {
		return // iptables not available
	}

	out, err := exec.Command("iptables", "-L", "XCLOAK", "-v", "-n").Output()
	if err != nil {
		return // XCLOAK chain may not exist yet
	}

	var hits []firewallHitEntry
	seen := map[int]bool{}

	for _, line := range bytes.Split(out, []byte("\n")) {
		m := commentRE.FindSubmatch(line)
		if m == nil {
			continue
		}
		ruleID, err := strconv.Atoi(string(m[1]))
		if err != nil || ruleID == 0 || seen[ruleID] {
			continue
		}

		// Extract packet count from the first field of the line.
		pm := lineRE.FindSubmatch(line)
		if pm == nil {
			continue
		}
		pkts, err := strconv.ParseInt(string(pm[1]), 10, 64)
		if err != nil {
			continue
		}

		hits = append(hits, firewallHitEntry{RuleID: ruleID, Hits: pkts})
		seen[ruleID] = true
	}

	if len(hits) == 0 {
		return
	}

	payload, _ := json.Marshal(map[string]interface{}{"hits": hits})
	resp, err := authPost("/api/agents/firewall-hits", payload)
	if err != nil {
		fmt.Println("firewall stats: POST failed:", err)
		return
	}
	defer resp.Body.Close()
}
