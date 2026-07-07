package services

import (
	"bufio"
	"log/slog"
	"net"
	"os"
	"time"

	"xcloak-ngfw/models"
	"xcloak-ngfw/repositories"
)

// StartSyslogReceiver starts UDP and TCP syslog listeners.
// Bind addresses are read from SYSLOG_UDP_ADDR / SYSLOG_TCP_ADDR env vars;
// defaults to :514 (requires root) — use :5514 in dev without root.
// A bind failure is logged but non-fatal so the rest of the API still starts.
func StartSyslogReceiver() {
	udpAddr := os.Getenv("SYSLOG_UDP_ADDR")
	if udpAddr == "" {
		udpAddr = ":514"
	}
	tcpAddr := os.Getenv("SYSLOG_TCP_ADDR")
	if tcpAddr == "" {
		tcpAddr = ":514"
	}

	go listenUDP(udpAddr)
	go listenTCP(tcpAddr)
}

// ── UDP receiver ──────────────────────────────────────────────────────────────

func listenUDP(addr string) {
	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		slog.Error("syslog: UDP bind failed (try SYSLOG_UDP_ADDR=:5514 if non-root)", "addr", addr, "err", err)
		return
	}
	defer conn.Close()
	slog.Info("syslog: UDP receiver listening", "addr", addr)

	buf := make([]byte, 65536)
	for {
		n, src, err := conn.ReadFrom(buf)
		if err != nil {
			continue
		}
		srcIP := extractIP(src.String())
		msg := string(buf[:n])
		go dispatchSyslogMessage(msg, srcIP)
	}
}

// ── TCP receiver ──────────────────────────────────────────────────────────────

func listenTCP(addr string) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		slog.Error("syslog: TCP bind failed (try SYSLOG_TCP_ADDR=:5514 if non-root)", "addr", addr, "err", err)
		return
	}
	defer ln.Close()
	slog.Info("syslog: TCP receiver listening", "addr", addr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go handleTCPConn(conn)
	}
}

func handleTCPConn(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Minute)) //nolint:errcheck
	srcIP := extractIP(conn.RemoteAddr().String())

	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 65536), 65536)
	for scanner.Scan() {
		if line := scanner.Text(); line != "" {
			dispatchSyslogMessage(line, srcIP)
		}
	}
}

// ── Dispatch ──────────────────────────────────────────────────────────────────

func dispatchSyslogMessage(raw, srcIP string) {
	src := repositories.GetLogSourceByIP(srcIP)
	if src == nil {
		// Unregistered source — drop silently. Operators must register devices
		// under Settings → Log Sources before traffic is accepted.
		return
	}
	if !src.Enabled {
		return
	}

	agentID := 0
	if src.AgentID != nil {
		agentID = *src.AgentID
	}

	log := models.Log{
		AgentID:     agentID,
		LogSource:   src.Name,
		LogMessage:  raw,
		CollectedAt: time.Now(),
	}

	if err := SaveLogs([]models.Log{log}); err != nil {
		slog.Error("syslog: save error", "source", src.Name, "err", err)
		return
	}

	go repositories.BumpLogSourceEvent(src.ID)
}

// extractIP strips the port from "host:port" strings returned by net.Addr.
func extractIP(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}
