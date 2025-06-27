# eBPF-enabled falsification

This repository demonstrates how to search for counterexamples (i.e.,
falsification) with eBPF.

Follow the prerequisites to reproduce.

## Instructions to reproduce

Platform: Ubuntu 24.04 LTS (kernel newer than v5.7)

### Tools

Install a compatible version of the following tools:

- `GNU  gdb` 15.0.50
- `GNU  objdumb` 2.42
- `GNU  readelf` 2.42
- `GNU Make` 4.3
- `bpftool` v7.4.0 (with `libbpf` v1.4)
- `g++` 13.3.3
- `go` 1.24.3
- `llvm-strip` 18.1.3
- `llvm` 18.1.3

After, install:

- the Cilium eBPF tool with `go get github.com/cilium/ebpf`
- Linux headers files `sudo apt install linux-headers-generic`, `sudo ln -sf /usr/include/asm-generic/ /usr/include/asm`
- eBPF headers `sudo apt install libbpf-dev`

## Test

The directories `monitor ` and `stopper` stores preliminary examples
that demonstrate how to interact with Simulink-generated models via
eBPF. For each example follow the instructions.
