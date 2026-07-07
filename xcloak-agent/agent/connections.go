//go:build !windows

package agent

import (
	"bufio"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"xcloak-agent/models"
)

// CollectConnections uses ss -tunpo which includes process info (PID, process
// name) per socket. Falls back to the simpler ss -tun on error.
func CollectConnections(agentID int) {
	conns := collectConnectionsWithProc(agentID)
	if len(conns) == 0 {
		slog.Warn("connection collection returned 0 entries")
		return
	}
	body, _ := json.Marshal(conns)
	resp, err := authPost("/api/agents/connections", body)
	if err != nil {
		slog.Error("failed sending connections", "err", err)
		return
	}
	defer resp.Body.Close()
	slog.Info("connections sent", "count", len(conns))
}

// collectConnectionsWithProc builds the connection list using /proc/net/{tcp,tcp6,udp,udp6}
// combined with an inode→PID map built from /proc/<pid>/fd/ symlinks.
// This is more reliable than parsing ss -tunpo text output.
func collectConnectionsWithProc(agentID int) []models.Connection {
	inodeMap := buildInodePIDMap()
	pidNames := buildPIDNameMap()

	var conns []models.Connection
	for _, entry := range []struct{ proto, path string }{
		{"tcp", "/proc/net/tcp"},
		{"tcp6", "/proc/net/tcp6"},
		{"udp", "/proc/net/udp"},
		{"udp6", "/proc/net/udp6"},
	} {
		entries, err := parseProcNetFile(entry.path, entry.proto, agentID, inodeMap, pidNames)
		if err != nil {
			slog.Debug("proc net file unavailable", "path", entry.path, "err", err)
			continue
		}
		conns = append(conns, entries...)
	}
	return conns
}

// buildInodePIDMap reads /proc/<pid>/fd/* symlinks (which point at
// socket:[inode]) to build an inode→PID lookup table.
func buildInodePIDMap() map[string]int {
	m := make(map[string]int)
	dirs, err := os.ReadDir("/proc")
	if err != nil {
		return m
	}
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(d.Name())
		if err != nil {
			continue
		}
		fdDir := filepath.Join("/proc", d.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			// links look like "socket:[12345678]"
			if strings.HasPrefix(link, "socket:[") && strings.HasSuffix(link, "]") {
				inode := link[8 : len(link)-1]
				m[inode] = pid
			}
		}
	}
	return m
}

// buildPIDNameMap reads /proc/<pid>/comm for every PID.
func buildPIDNameMap() map[int]string {
	m := make(map[int]string)
	dirs, _ := os.ReadDir("/proc")
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(d.Name())
		if err != nil {
			continue
		}
		data, err := os.ReadFile(filepath.Join("/proc", d.Name(), "comm"))
		if err != nil {
			continue
		}
		m[pid] = strings.TrimSpace(string(data))
	}
	return m
}

// parseProcNetFile reads a /proc/net/{tcp,udp,...} file and returns Connection
// entries. The kernel format is fixed-width hex columns.
func parseProcNetFile(path, proto string, agentID int, inodeMap map[string]int, pidNames map[int]string) ([]models.Connection, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	stateNames := map[string]string{
		"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV",
		"04": "FIN_WAIT1", "05": "FIN_WAIT2", "06": "TIME_WAIT",
		"07": "CLOSE", "08": "CLOSE_WAIT", "09": "LAST_ACK",
		"0A": "LISTEN", "0B": "CLOSING",
	}

	var conns []models.Connection
	sc := bufio.NewScanner(f)
	first := true
	for sc.Scan() {
		if first {
			first = false
			continue
		}
		fields := strings.Fields(sc.Text())
		if len(fields) < 10 {
			continue
		}
		local := hexToAddr(fields[1])
		remote := hexToAddr(fields[2])
		state := stateNames[strings.ToUpper(fields[3])]
		if state == "" {
			state = fields[3]
		}
		inode := fields[9]
		pid := inodeMap[inode]
		name := pidNames[pid]

		// Skip pure loopback ESTABLISHED connections unless process enrichment is useful
		c := models.Connection{
			AgentID:       agentID,
			Protocol:      proto,
			LocalAddress:  local,
			RemoteAddress: remote,
			State:         state,
			PID:           pid,
			ProcessName:   name,
		}
		if pid > 0 {
			if exe, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), "exe")); err == nil {
				c.ProcessPath = exe
			}
		}
		conns = append(conns, c)
	}
	return conns, nil
}

// hexToAddr converts a /proc/net hex address "0100007F:1F90" → "127.0.0.1:8080".
// IPv6 addresses are 32 hex chars in little-endian word order.
func hexToAddr(s string) string {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return s
	}
	addrHex := parts[0]
	portHex := parts[1]

	port, _ := strconv.ParseInt(portHex, 16, 32)

	if len(addrHex) == 8 {
		// IPv4 — little-endian 32-bit word
		n, _ := strconv.ParseUint(addrHex, 16, 32)
		return strconv.Itoa(int(n&0xff)) + "." +
			strconv.Itoa(int((n>>8)&0xff)) + "." +
			strconv.Itoa(int((n>>16)&0xff)) + "." +
			strconv.Itoa(int((n>>24)&0xff)) +
			":" + strconv.Itoa(int(port))
	}
	// IPv6 — return raw hex for now
	return "[" + addrHex + "]:" + strconv.Itoa(int(port))
}
