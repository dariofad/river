# RIVER: An eBPF-based Runtime Verification Platform for Cyber-Physical Systems

This repository implements a tool to execute Simulink models enabling monitoring, falsification (to search for counterexamples), online perturbation of input signals and model state (adversarial attacks), and runtime enforcement.  All the operations are non-intrusive thanks to eBPF, and can be performed without changing the model nor its source code. To reproduce the results and the demos, check the instructions in the `server`, `simulator` and `client` folders.

## Prerequisites

Development platform: Ubuntu 24.04 LTS, 26.04 LTS (kernel must be newer than v6.1)
Supported architectures: x86, arm64

Developed and tested with the following tools:

- `GNU  gdb` 17.1
- `GNU  objdump` 2.46
- `GNU  readelf` 2.46
- `GNU Make` 4.4.1
- `bpftool` 7.7.0 (with `libbpf` 1.7)
- `g++` 15.2.0
- `go` 1.26.4
- [`uv`](https://github.com/astral-sh/uv)
- `llvm-strip` 21.1.8
- `llvm` 21.1.8
- `clang` 21.1.8
- `clang-format` 21.1.8
- `docker ` 29.5.3

After, install:

- Linux headers files `sudo apt install linux-headers-generic`, `sudo ln -sf /usr/include/asm-generic/ /usr/include/asm`
- eBPF headers `sudo apt install libbpf-dev`

## Python tooling

- Install the workspace dependencies with `uv sync`
- Install the workspace dependencies plus development tools with `uv sync --dev`

## Code style

After cloning the repository run `git config --local core.hooksPath
githooks`. This enables a script to format C source files with clangd
at commit time. Formatted files must be manually re-added to the
staging area.

## Demos

The demos used to test the server use models from The current version
uses several models from [this
repo](https://github.com/dariofad/sim2cpp/tree/e793667428f6bcbce932c1cff87085ebca17d89e). It
is also possible to interact with the server using a Matlab session.

## Build and run the server

- Create the redis container with `make redis` (only the first time)
- Build and run the server with `make`

You can get additional feedback checking the output of the eBPF probes at `/sys/kernel/tracing/trace_pipe`.
