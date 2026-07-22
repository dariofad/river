.PHONY: all build run generate vmlinux redis start_redis stop_redis bench check-env clean manifest

EBPF_PROBE = probe
GO_MODULE = river
SIMULATOR_PATH := simulator
REDIS_PORT := 6379
ARCH:= $(shell go env GOARCH)
MANIFEST ?=

BPF_CFLAGS  = -DDEBUG -O2 -Wall
BPF_CFLAGS_BENCH  = -O2 -Wall

all: run

check-env:
	bash scripts/check-env.sh

vmlinux:
	mkdir -p $(SIMULATOR_PATH)/headers
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(SIMULATOR_PATH)/headers/vmlinux.h

generate: vmlinux
	cd $(SIMULATOR_PATH); BPF2GO_CFLAGS="$(BPF_CFLAGS)" go generate
generate_bench: vmlinux
	cd $(SIMULATOR_PATH); BPF2GO_CFLAGS="$(BPF_CFLAGS_BENCH)" go generate

build: generate
# with CGO_ENABLED=0 the build doesn't depend on libc
	@CGO_ENABLED=0 GOARCH=$(ARCH) go build
build_bench: generate_bench
	@CGO_ENABLED=0 GOARCH=$(ARCH) go build

redis:
	docker create --name redis -p $(REDIS_PORT):$(REDIS_PORT) redis:latest

start_redis:
	docker start redis

stop_redis:
	docker stop redis

_run: | start_redis
	@if docker ps -a --filter "name=$(CONTAINER_NAME)" --format "{{.ID}}" | grep -q .; then \
		echo "-> container $(CONTAINER_NAME) is already running or exists. Skipping creation."; \
	else \
		echo "-> creating and running container $(CONTAINER_NAME)..."; \
		docker run -d --name $(CONTAINER_NAME) $(IMAGE_NAME); \
		sleep 3; \
	fi

_run_debug: | build _run 
_run_bench: | build_bench _run

run: _run_debug
	@test -n "$(MANIFEST)" || (echo "MANIFEST=/path/to/model.river.yaml is required"; exit 2)
	@sudo ./$(GO_MODULE) -manifest "$(MANIFEST)"
bench: _run_bench
	@test -n "$(MANIFEST)" || (echo "MANIFEST=/path/to/model.river.yaml is required"; exit 2)
	sudo sysctl -w kernel.bpf_stats_enabled=1
	@sudo ./$(GO_MODULE) -b -manifest "$(MANIFEST)"

clean:
	@rm -rf $(SIMULATOR_PATH)/headers
	@rm -rf $(GO_MODULE) $(SIMULATOR_PATH)/$(EBPF_PROBE)_bpf*

manifest:
	@go run ./cmd/river-manifest generate --binary "$(MODEL)" --output "$(OUT)"
