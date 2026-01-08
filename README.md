# eBPF-based model/controller simulation

This repository implements a tool to execute Simulink models enabling
monitoring, falsification (to search for counterexamples), and online
perturbation of input signals and model state.  All the operations are
non-intrusive thanks to eBPF, and can be performed without changing
the model nor its source code.  To reproduce the results and the
demos, check the instructions in the `server`, `simulator` and
`client` folders.

## Prerequisites

Development platform: Ubuntu 24.04 LTS (kernel newer than v5.7)

Developed and tested with the following tools:

- `GNU  gdb` 15.0.50
- `GNU  objdumb` 2.42
- `GNU  readelf` 2.42
- `GNU Make` 4.3
- `bpftool` 7.4.0 (with `libbpf` 1.4)
- `g++` 13.3.3
- `go` 1.24.3
- `llvm-strip` 18.1.3
- `llvm` 18.1.3
- `clang` 18.1.3
- `clang-format` 18.1.3
- `docker ` 28.4.0

After, install:

- Linux headers files `sudo apt install linux-headers-generic`, `sudo ln -sf /usr/include/asm-generic/ /usr/include/asm`
- eBPF headers `sudo apt install libbpf-dev`

### Code style

After cloning the repository run `git config --local core.hooksPath
githooks`. This enables a script to format C source files with clangd
at commit time. Formatted files must be manually re-added to the
staging area.

## Test

The current version uses several models from this
[repo](https://github.com/dariofad/sim2cpp) (commit: c0ce95f). See
this other
[repo](https://github.com/shincyou0916/Falsification-for-MPCACC-model-with-eBPF)
for an example of a Matlab client.

### Run

- Disable ASLR with `make aslr_off` before starting the development session
- Create the redis container with `make redis`
- Build and run the server with `make`

You can get additional feedback checking the output of the eBPF probes at `/sys/kernel/tracing/trace_pipe`.
