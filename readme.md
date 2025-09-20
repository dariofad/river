# eBPF-enabled falsification

This repository implements a Go TCPIP server capable of running Simulink models with online perturbation.
This supports multiple objectives, including searching for counterexamples (i.e.,
falsification) online, monitoring models, changing model behavior at runtime.

Follow the prerequisites to reproduce.

## Prerequisites

Development platform: Ubuntu 24.04 LTS (kernel newer than v5.7)

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
- clang

After, install:

- Linux headers files `sudo apt install linux-headers-generic`, `sudo ln -sf /usr/include/asm-generic/ /usr/include/asm`
- eBPF headers `sudo apt install libbpf-dev`

## Test

The current version uses the `DualACC` model from this
[repo](https://github.com/dariofad/sim2cpp) (commit: 058d589), and
relies on the Matlab client implemented
[here](https://github.com/shincyou0916/Falsification-for-MPCACC-model-with-eBPF).

Remember to complete the additional setup as described within the
directory `simulator `.

### Run

- Disable ASLR with `make aslr_off` before starting the development session
- Build and run the server with `make`

You can get additional feedback checking the output of the eBPF probes at `/sys/kernel/tracing/trace_pipe`.
