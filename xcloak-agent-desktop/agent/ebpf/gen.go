//go:build linux

package ebpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang-16 -strip llvm-strip-16 -target amd64 bpf connect_events.c -- -I.
