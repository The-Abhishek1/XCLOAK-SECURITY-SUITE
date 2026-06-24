//go:build ignore

// connect_events.c — eBPF program that captures every outbound IPv4 TCP
// connect() attempt, with the calling process's pid/comm/uid attached.
//
// Approach: kprobe tcp_v4_connect (entry) records sk* keyed by the calling
// thread's pid_tgid; kretprobe tcp_v4_connect (exit) looks that sk* back up,
// and — only on success (ret == 0) — reads the now-populated source/dest
// address+port off the socket and pushes one event into the ring buffer.
// This is the standard technique for attributing TCP connects to a process
// (same idea as bcc/libbpf-tools' tcpconnect): the sock:inet_sock_set_state
// tracepoint alone can fire outside process context for later state
// transitions, so it can't reliably give you the calling task's pid/uid —
// hooking tcp_v4_connect directly can, since connect() runs in the caller's
// process context all the way to the function's return.
#include "headers/vmlinux.h"
#include "headers/bpf_helpers.h"
#include "headers/bpf_core_read.h"
#include "headers/bpf_endian.h"
#include "headers/bpf_tracing.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct event {
	__u64 ts_ns;
	__u32 pid;
	__u32 uid;
	__u32 saddr;
	__u32 daddr;
	__u16 sport;
	__u16 dport;
	char comm[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, __u64);   // pid_tgid
	__type(value, __u64); // struct sock *
} sock_by_thread SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(trace_tcp_v4_connect, struct sock *sk) {
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u64 skp = (__u64)sk;
	bpf_map_update_elem(&sock_by_thread, &pid_tgid, &skp, BPF_ANY);
	return 0;
}

SEC("kretprobe/tcp_v4_connect")
int BPF_KRETPROBE(trace_tcp_v4_connect_ret, int ret) {
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u64 *skp = bpf_map_lookup_elem(&sock_by_thread, &pid_tgid);
	if (!skp) {
		return 0;
	}
	struct sock *sk = (struct sock *)(*skp);
	bpf_map_delete_elem(&sock_by_thread, &pid_tgid);

	if (ret != 0) {
		// connect() failed synchronously (e.g. EINVAL) — nothing to report.
		return 0;
	}

	struct event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
	if (!ev) {
		return 0;
	}

	ev->ts_ns = bpf_ktime_get_ns();
	ev->pid = pid_tgid >> 32;
	ev->uid = (__u32)bpf_get_current_uid_gid();
	ev->saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
	ev->daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
	ev->dport = BPF_CORE_READ(sk, __sk_common.skc_dport); // network byte order
	ev->sport = BPF_CORE_READ(sk, __sk_common.skc_num);   // host byte order
	bpf_get_current_comm(&ev->comm, sizeof(ev->comm));

	bpf_ringbuf_submit(ev, 0);
	return 0;
}
