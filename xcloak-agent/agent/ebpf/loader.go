//go:build linux

// Package ebpf wraps the generated bpf2go bindings (bpf_x86_bpfel.go) behind
// a small exported API, since bpf2go's own output (bpfObjects, bpfMaps, ...)
// is unexported and only meant to be consumed from within this package.
package ebpf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// rawEvent mirrors struct event in connect_events.c byte-for-byte.
// Saddr/Daddr/Dport are kept as raw network-byte-order octets (the kernel's
// __be32/__be16 fields are written verbatim by the BPF program — no
// endianness conversion happens there), so they're decoded directly into
// dotted-quad / port form without an intermediate integer reinterpretation.
// Sport (skc_num) is the one field the kernel keeps in host byte order.
type rawEvent struct {
	TsNs  uint64
	Pid   uint32
	Uid   uint32
	Saddr [4]byte
	Daddr [4]byte
	Sport uint16
	Dport [2]byte
	Comm  [16]byte
}

// ConnectEvent is a single attributed outbound TCP connect() call.
type ConnectEvent struct {
	TimestampNS   uint64
	PID           uint32
	UID           uint32
	Comm          string
	LocalAddress  string
	RemoteAddress string
}

// Collector loads the connect_events BPF program, attaches it to
// tcp_v4_connect, and exposes the resulting events one at a time via Read.
type Collector struct {
	objs    bpfObjects
	kprobe  link.Link
	kretprb link.Link
	reader  *ringbuf.Reader
}

// NewCollector loads and attaches the eBPF program. Requires root / CAP_BPF
// + CAP_PERFMON (or equivalent) — the caller should treat failure here as
// "not supported on this host" and fall back to periodic polling.
func NewCollector() (*Collector, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock rlimit: %w", err)
	}

	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load bpf objects: %w", err)
	}

	kp, err := link.Kprobe("tcp_v4_connect", objs.TraceTcpV4Connect, nil)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attach kprobe: %w", err)
	}

	krp, err := link.Kretprobe("tcp_v4_connect", objs.TraceTcpV4ConnectRet, nil)
	if err != nil {
		kp.Close()
		objs.Close()
		return nil, fmt.Errorf("attach kretprobe: %w", err)
	}

	reader, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		krp.Close()
		kp.Close()
		objs.Close()
		return nil, fmt.Errorf("open ringbuf reader: %w", err)
	}

	return &Collector{objs: objs, kprobe: kp, kretprb: krp, reader: reader}, nil
}

// Read blocks until the next connect event is available, or returns an
// error once Close has been called (ringbuf.ErrClosed).
func (c *Collector) Read() (ConnectEvent, error) {
	record, err := c.reader.Read()
	if err != nil {
		if errors.Is(err, ringbuf.ErrClosed) {
			return ConnectEvent{}, err
		}
		return ConnectEvent{}, fmt.Errorf("read ringbuf: %w", err)
	}

	var raw rawEvent
	if err := decodeRawEvent(record.RawSample, &raw); err != nil {
		return ConnectEvent{}, err
	}

	return ConnectEvent{
		TimestampNS:   raw.TsNs,
		PID:           raw.Pid,
		UID:           raw.Uid,
		Comm:          commToString(raw.Comm),
		LocalAddress:  fmt.Sprintf("%s:%d", ipv4String(raw.Saddr), raw.Sport),
		RemoteAddress: fmt.Sprintf("%s:%d", ipv4String(raw.Daddr), binary.BigEndian.Uint16(raw.Dport[:])),
	}, nil
}

// Close detaches the probes and unblocks any in-flight Read call.
func (c *Collector) Close() error {
	c.reader.Close()
	c.kretprb.Close()
	c.kprobe.Close()
	return c.objs.Close()
}

func decodeRawEvent(b []byte, out *rawEvent) error {
	const size = 8 + 4 + 4 + 4 + 4 + 2 + 2 + 16
	if len(b) < size {
		return fmt.Errorf("short ringbuf record: %d bytes", len(b))
	}
	out.TsNs = binary.LittleEndian.Uint64(b[0:8])
	out.Pid = binary.LittleEndian.Uint32(b[8:12])
	out.Uid = binary.LittleEndian.Uint32(b[12:16])
	copy(out.Saddr[:], b[16:20])
	copy(out.Daddr[:], b[20:24])
	out.Sport = binary.LittleEndian.Uint16(b[24:26])
	copy(out.Dport[:], b[26:28])
	copy(out.Comm[:], b[28:44])
	return nil
}

// ipv4String renders the kernel's raw network-byte-order address octets
// as a dotted-quad.
func ipv4String(addr [4]byte) string {
	return net.IP(addr[:]).String()
}

func commToString(comm [16]byte) string {
	n := 0
	for n < len(comm) && comm[n] != 0 {
		n++
	}
	return string(comm[:n])
}
