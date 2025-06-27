.phony: all build run mod_init generate vmlinux aslr_off

MODULE = cps_monitor
EBPF_SRC = probe

all: run

generate:
	@go generate

build: generate
# with CGO_ENABLED=0 the build doesn't depend on libc
	@CGO_ENABLED=0 GO_ARCH=amd64 go build 

run: build
	@sudo ./$(MODULE)

mod_init:
	@go mod init $(MODULE)
	@go mod tidy
	@go get github.com/cilium/ebpf/cmd/bpf2go

vmlinux:
	@bpftool btf dump file /sys/kernel/btf/vmlinux format c > headers/vmlinux.h

clean:
	@rm -rf $(MODULE) $(EBPF_SRC)_bpfel.o $(EBPF_SRC)_bpfeb.o

aslr_off:
	@echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
