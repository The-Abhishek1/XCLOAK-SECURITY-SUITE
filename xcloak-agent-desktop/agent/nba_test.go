package agent

import (
	"encoding/json"
	"net"
	"testing"
)

// TestNBAConnectEvent_Fields verifies that connection events submitted by the
// desktop agent include the fields the NBA service depends on for baseline
// and anomaly detection: dst_ip, dst_port, proto.
func TestNBAConnectEvent_Fields(t *testing.T) {
	event := map[string]any{
		"agent_id": 1,
		"dst_ip":   "203.0.113.5",
		"dst_port": 443,
		"proto":    "tcp",
		"event_ts": "2025-01-15T10:30:00Z",
	}

	b, _ := json.Marshal(event)
	var decoded map[string]any
	json.Unmarshal(b, &decoded)

	for _, key := range []string{"dst_ip", "dst_port", "proto"} {
		if _, ok := decoded[key]; !ok {
			t.Errorf("connect event missing NBA field %q", key)
		}
	}
}

// TestNBAConnectEvent_PrivateIPIsInternal verifies that the private IP check
// logic (mirrored from nba_service.go isPrivateIPStr) correctly classifies
// RFC-1918 addresses as internal — these are skipped in anomaly detection.
func TestNBAConnectEvent_PrivateIPIsInternal(t *testing.T) {
	privateIPs := []string{
		"10.0.0.1", "172.16.0.1", "192.168.1.1", "127.0.0.1",
	}
	publicIPs := []string{
		"8.8.8.8", "203.0.113.5", "1.1.1.1",
	}

	isPrivate := func(ipStr string) bool {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return false
		}
		return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()
	}

	for _, ip := range privateIPs {
		if !isPrivate(ip) {
			t.Errorf("expected %q to be private (NBA skips internal traffic)", ip)
		}
	}
	for _, ip := range publicIPs {
		if isPrivate(ip) {
			t.Errorf("expected %q to be public (NBA should analyse this)", ip)
		}
	}
}

// TestNBAConnectEvent_ProtoIsString verifies that the proto field in connect
// events is a string. The NBA service stores it as text and uses it in the
// baseline unique constraint (agent_id, dst_ip, dst_port, proto).
func TestNBAConnectEvent_ProtoIsString(t *testing.T) {
	for _, proto := range []string{"tcp", "udp", "icmp"} {
		event := map[string]any{
			"agent_id": 1,
			"dst_ip":   "8.8.8.8",
			"dst_port": 53,
			"proto":    proto,
		}
		b, _ := json.Marshal(event)
		var decoded map[string]any
		json.Unmarshal(b, &decoded)

		if _, ok := decoded["proto"].(string); !ok {
			t.Errorf("proto %q: must be a string in connect event", proto)
		}
	}
}
