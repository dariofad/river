#!/usr/bin/env bash

set -u

TOOLS=(
  "GNU gdb:gdb"
  "GNU objdump:objdump"
  "GNU readelf:readelf"
  "GNU Make:make"
  "bpftool:bpftool"
  "g++:g++"
  "go:go"
  "uv:uv"
  "llvm-strip:llvm-strip"
  "llvm:llvm-config"
  "clang:clang"
  "clang-format:clang-format"
  "docker:docker"
)

missing_tools=0

for tool_spec in "${TOOLS[@]}"; do
  tool_name="${tool_spec%%:*}"
  command_name="${tool_spec#*:}"
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "Error: required tool '$tool_name' ('$command_name') was not found in PATH." >&2
    missing_tools=1
  fi
done

if [[ "$missing_tools" -ne 0 ]]; then
  exit 1
fi

echo "All required tools were found in PATH."
