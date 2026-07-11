//go:build linux

package agent

import (
	"encoding/json"
	"fmt"
	"time"

	"xcloak-agent-desktop/agent/ebpf"
	"xcloak-agent-desktop/models"
)

const (
	connectEventBatchSize     = 50
	connectEventFlushInterval = 5 * time.Second
)

// StartConnectEventStream launches the eBPF-backed real-time outbound-connect
// collector. Unlike the other collectors (periodic poll via runCollector),
// this is event-driven: a kprobe on tcp_v4_connect pushes one event per
// connect() call into a ring buffer, which we batch here and flush on a
// timer or once a batch fills up, whichever comes first.
//
// Requires CAP_BPF/CAP_PERFMON (root) plus a BTF-enabled kernel. If either is
// missing this logs once and gives up — the periodic ss-based snapshot
// collector (CollectConnections) still covers the same host, just without
// per-connection pid/uid attribution or sub-poll-interval visibility.
func StartConnectEventStream(agentID int) {
	collector, err := ebpf.NewCollector()
	if err != nil {
		fmt.Printf("[collector] connect_events: eBPF unavailable, skipping (%v)\n", err)
		return
	}

	fmt.Println("[collector] connect_events: attached, streaming")

	// Wrapped in runSafe (same recover used by the autonomous collectors,
	// collector.go) — a panic in either loop used to crash the whole agent
	// process, not just the eBPF pipeline. No restart-after-panic here: a
	// fresh ebpf.NewCollector() would be needed to genuinely recover, a
	// different concern from "don't crash the agent" that this collector
	// doesn't currently need solved.
	events := make(chan models.ConnectEvent, 256)
	go runSafe("connect-events-read", func() { connectEventReadLoop(collector, agentID, events) })
	go runSafe("connect-events-send", func() { connectEventBatchAndSend(events) })
}

func connectEventReadLoop(collector *ebpf.Collector, agentID int, out chan<- models.ConnectEvent) {
	defer collector.Close()
	for {
		ev, err := collector.Read()
		if err != nil {
			fmt.Printf("[collector] connect_events: read loop ended: %v\n", err)
			close(out)
			return
		}
		ce := models.ConnectEvent{
			AgentID:       agentID,
			PID:           int(ev.PID),
			Comm:          ev.Comm,
			UID:           int(ev.UID),
			Protocol:      "tcp",
			LocalAddress:  ev.LocalAddress,
			RemoteAddress: ev.RemoteAddress,
			State:         "connect",
			EventTS:       int64(ev.TimestampNS),
		}
		// Passive DPI: best-effort L7 enrichment (SNI, HTTP headers, TLS version).
		// Runs in a goroutine with a short deadline so slow /proc reads never
		// stall the eBPF ring buffer drain.
		enriched := make(chan models.ConnectEvent, 1)
		go func() { enriched <- EnrichConnectEventDPI(ce) }()
		select {
		case ce = <-enriched:
		case <-time.After(80 * time.Millisecond):
		}
		out <- ce
	}
}

func connectEventBatchAndSend(events <-chan models.ConnectEvent) {
	var buf []models.ConnectEvent
	ticker := time.NewTicker(connectEventFlushInterval)
	defer ticker.Stop()

	flush := func() {
		if len(buf) == 0 {
			return
		}
		sendConnectEvents(buf)
		buf = nil
	}

	for {
		select {
		case ev, ok := <-events:
			if !ok {
				flush()
				return
			}
			buf = append(buf, ev)
			if len(buf) >= connectEventBatchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

func sendConnectEvents(events []models.ConnectEvent) {
	body, _ := json.Marshal(events)
	resp, err := authPost("/api/agents/connect-events", body)
	if err != nil {
		fmt.Printf("[collector] connect_events: send failed: %v\n", err)
		return
	}
	defer resp.Body.Close()
	fmt.Printf("[collector] connect_events: sent %d events\n", len(events))
}
