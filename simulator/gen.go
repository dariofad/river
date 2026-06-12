package simulator

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux probe probe.c -- -DBENCH -O2 -g -Wall -Wno-missing-declarations
