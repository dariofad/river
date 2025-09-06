.phony: all build run generate vmlinux aslr_off

EBPF_PROBE = probe
GO_MODULE = ebpf_simulator
SIMULATOR_PATH := simulator

all: run

vmlinux:
	mkdir -p $(SIMULATOR_PATH)/headers
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(SIMULATOR_PATH)/headers/vmlinux.h

generate: vmlinux
	cd $(SIMULATOR_PATH); go generate

build: generate
# with CGO_ENABLED=0 the build doesn't depend on libc
	@CGO_ENABLED=0 GO_ARCH=amd64 go build 

run: build
	@sudo ./$(GO_MODULE)

clean:
	@rm -rf $(SIMULATOR_PATH)/headers
	@rm -rf $(GO_MODULE) $(SIMULATOR_PATH)/$(EBPF_PROBE)_bpf*

aslr_off:
	@echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
