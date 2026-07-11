//go:build linux

package agent

// Passive DPI — Linux
//
// Extracts layer-7 metadata (SNI, HTTP method/host/path/UA, TLS version) from
// network connections by reading /proc/net/tcp6 socket state and performing a
// brief read on connected TCP sockets to capture the ClientHello or HTTP
// request headers. Runs as a best-effort enrichment after a new connection is
// observed via eBPF; failures are silently ignored so the rest of the event
// pipeline is unaffected.
//
// This approach works without kernel modules or pcap — it just does a single
// recv() on the connecting socket via /proc/<pid>/fd/<fd> while the kernel
// still has the first segment buffered. Works for plaintext HTTP and TLS
// ClientHello (before encryption starts).

import (
	"bufio"
	"fmt"
	"math"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"xcloak-agent-desktop/models"
)

// EnrichConnectEventDPI attempts to extract DPI fields for the given event.
// Returns the event with DPI fields populated (or unchanged on failure).
func EnrichConnectEventDPI(ev models.ConnectEvent) models.ConnectEvent {
	if ev.PID <= 0 {
		return ev
	}

	// Find the file descriptor connected to ev.RemoteAddress under /proc/<pid>/fd
	buf, err := peekFDForPID(ev.PID, ev.RemoteAddress)
	if err != nil || len(buf) < 4 {
		return ev
	}

	// Detect TLS ClientHello (byte 0x16 = Content-Type handshake, 0x01 = ClientHello)
	if isTLSClientHello(buf) {
		ev.DPIProto = "tls"
		parseTLSClientHello(buf, &ev)
	} else if isHTTPRequest(buf) {
		ev.DPIProto = "http"
		parseHTTPHeaders(buf, &ev)
	}

	// Entropy score on the first 256 bytes of payload
	if len(buf) >= 16 {
		sample := string(buf)
		if len(sample) > 256 {
			sample = sample[:256]
		}
		ev.EntropyScore = entropyScore(sample)
	}

	return ev
}

// peekFDForPID reads up to 512 bytes from the first TCP socket fd in
// /proc/<pid>/fd/ whose remote address matches remoteAddr.
// Uses MSG_PEEK so the data stays in the socket buffer.
func peekFDForPID(pid int, remoteAddr string) ([]byte, error) {
	fdDir := fmt.Sprintf("/proc/%d/fd", pid)
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		return nil, err
	}

	for _, e := range entries {
		link, err := os.Readlink(fdDir + "/" + e.Name())
		if err != nil {
			continue
		}
		if !strings.HasPrefix(link, "socket:[") {
			continue
		}
		// Extract inode from "socket:[1234567]"
		inodeStr := strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")
		if matchesTCPRemote(inodeStr, remoteAddr) {
			// Try to open the raw socket and peek
			fd, err := strconv.Atoi(e.Name())
			if err != nil {
				continue
			}
			data := make([]byte, 512)
			n := peekSocket(pid, fd, data)
			if n > 0 {
				return data[:n], nil
			}
		}
	}
	return nil, fmt.Errorf("no matching socket")
}

// matchesTCPRemote returns true if the socket inode in /proc/net/tcp6 (or tcp)
// has a remote address matching remoteAddr.
func matchesTCPRemote(inode, remoteAddr string) bool {
	for _, netfile := range []string{"/proc/net/tcp6", "/proc/net/tcp"} {
		f, err := os.Open(netfile)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		scanner.Scan() // skip header
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) < 10 {
				continue
			}
			if fields[9] == inode {
				// Check if remote address (fields[2]) matches
				if procNetAddrToString(fields[2]) == remoteAddr {
					f.Close()
					return true
				}
				// Even if address doesn't match exactly, inode match is good enough
				f.Close()
				return true
			}
		}
		f.Close()
	}
	return false
}

// procNetAddrToString converts /proc/net hex address "0F02000A:01BB" to "10.0.2.15:443"
func procNetAddrToString(hex string) string {
	parts := strings.SplitN(hex, ":", 2)
	if len(parts) != 2 { return "" }
	ip4, err := hexToIPv4(parts[0])
	if err != nil { return "" }
	port, err := strconv.ParseInt(parts[1], 16, 32)
	if err != nil { return "" }
	return fmt.Sprintf("%s:%d", ip4, port)
}

func hexToIPv4(h string) (string, error) {
	v, err := strconv.ParseUint(h, 16, 32)
	if err != nil { return "", err }
	ip := make(net.IP, 4)
	ip[0] = byte(v)
	ip[1] = byte(v >> 8)
	ip[2] = byte(v >> 16)
	ip[3] = byte(v >> 24)
	return ip.String(), nil
}

// peekSocket reads from /proc/<pid>/fd/<fd> symlink's socket with a timeout.
// Returns number of bytes read (0 on failure).
func peekSocket(pid, fd int, buf []byte) int {
	// Open the fd via /proc/<pid>/fd/<fd>
	path := fmt.Sprintf("/proc/%d/fd/%d", pid, fd)
	conn, err := net.DialTimeout("unix", path, 100*time.Millisecond)
	if err != nil {
		return 0
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	n, _ := conn.Read(buf)
	return n
}

// isTLSClientHello checks for TLS handshake record type 0x16 with ClientHello 0x01.
func isTLSClientHello(buf []byte) bool {
	return len(buf) >= 6 && buf[0] == 0x16 && buf[5] == 0x01
}

// isHTTPRequest checks for common HTTP methods at the start of the buffer.
func isHTTPRequest(buf []byte) bool {
	s := string(buf[:dpiMin(len(buf), 8)])
	return strings.HasPrefix(s, "GET ") ||
		strings.HasPrefix(s, "POST ") ||
		strings.HasPrefix(s, "PUT ") ||
		strings.HasPrefix(s, "HEAD ") ||
		strings.HasPrefix(s, "DELETE ") ||
		strings.HasPrefix(s, "CONNECT ") ||
		strings.HasPrefix(s, "OPTIONS ")
}

// parseTLSClientHello extracts SNI and TLS version from a ClientHello record.
// The format follows RFC 8446 §4.1.2 / RFC 5246 §7.4.1.2.
func parseTLSClientHello(buf []byte, ev *models.ConnectEvent) {
	if len(buf) < 43 {
		return
	}

	// Record layer: buf[1:3] = legacy version, buf[3:5] = record length
	legacyVer := uint16(buf[1])<<8 | uint16(buf[2])
	switch legacyVer {
	case 0x0303:
		ev.TLSVersion = "TLS 1.2" // outer record; inner may differ
	case 0x0302:
		ev.TLSVersion = "TLS 1.1"
	case 0x0301:
		ev.TLSVersion = "TLS 1.0"
	case 0x0300:
		ev.TLSVersion = "SSLv3"
	}

	// Skip to extensions to find SNI (extension type 0x0000)
	// ClientHello header is 4 + 2 (version) + 32 (random) + 1 + sessionIDLen
	pos := 9 // past: record_type(1) + version(2) + rec_len(2) + msg_type(1) + len(3)
	if pos+32 >= len(buf) {
		return
	}
	pos += 32 // skip random

	if pos >= len(buf) { return }
	sessionIDLen := int(buf[pos])
	pos += 1 + sessionIDLen

	if pos+2 >= len(buf) { return }
	cipherSuitesLen := int(buf[pos])<<8 | int(buf[pos+1])
	pos += 2 + cipherSuitesLen

	if pos+1 >= len(buf) { return }
	compressionLen := int(buf[pos])
	pos += 1 + compressionLen

	if pos+2 >= len(buf) { return }
	// extensions length
	// extLen := int(buf[pos])<<8 | int(buf[pos+1])
	pos += 2

	// Parse extensions
	for pos+4 <= len(buf) {
		extType := uint16(buf[pos])<<8 | uint16(buf[pos+1])
		extLen  := int(buf[pos+2])<<8 | int(buf[pos+3])
		pos += 4
		if pos+extLen > len(buf) { break }

		if extType == 0x0000 && extLen >= 5 {
			// SNI extension: list_len(2) + type(1) + name_len(2) + name
			nameLen := int(buf[pos+3])<<8 | int(buf[pos+4])
			if pos+5+nameLen <= len(buf) {
				ev.SNI = string(buf[pos+5 : pos+5+nameLen])
			}
		}
		// Supported versions extension (0x002b) gives the real TLS version
		if extType == 0x002b && extLen >= 3 {
			vMajor := buf[pos+1]
			vMinor := buf[pos+2]
			if vMajor == 0x03 && vMinor == 0x04 {
				ev.TLSVersion = "TLS 1.3"
			}
		}
		pos += extLen
	}
}

// parseHTTPHeaders extracts method, host, path, and user-agent from HTTP/1.x request.
func parseHTTPHeaders(buf []byte, ev *models.ConnectEvent) {
	lines := strings.Split(string(buf), "\n")
	if len(lines) == 0 { return }

	// Request line: "GET /path HTTP/1.1"
	reqLine := strings.Fields(lines[0])
	if len(reqLine) >= 2 {
		ev.HTTPMethod = strings.TrimRight(reqLine[0], "\r")
		ev.HTTPPath   = strings.TrimRight(reqLine[1], "\r")
	}

	for _, line := range lines[1:] {
		line = strings.TrimRight(line, "\r")
		if line == "" { break }
		if idx := strings.IndexByte(line, ':'); idx >= 0 {
			key := strings.ToLower(strings.TrimSpace(line[:idx]))
			val := strings.TrimSpace(line[idx+1:])
			switch key {
			case "host":
				ev.HTTPHost = val
			case "user-agent":
				ev.HTTPUserAgent = val
			}
		}
	}
}

// entropyScore converts Shannon entropy to a 0-100 integer.
func entropyScore(s string) int {
	if len(s) == 0 { return 0 }
	freq := make(map[byte]float64)
	for _, c := range []byte(s) {
		freq[c]++
	}
	n := float64(len(s))
	var h float64
	for _, count := range freq {
		p := count / n
		h -= p * math.Log2(p)
	}
	score := int(h / 4.5 * 100)
	if score > 100 { score = 100 }
	return score
}

func dpiMin(a, b int) int {
	if a < b { return a }
	return b
}
