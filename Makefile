.PHONY: all bench build build_bench check-env clean generate generate_bench manifest run start_redis stop_redis vmlinux

SERVER_BINARY = river
MANIFEST_GENERATOR_BINARY = river-manifest
SIMULATOR_PATH := simulator
REDIS_CONTAINER := redis
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
build_bench: generate_bench

build build_bench:
# with CGO_ENABLED=0 the build doesn't depend on libc
	@CGO_ENABLED=0 GOARCH=$(ARCH) go build
	@CGO_ENABLED=0 GOARCH=$(ARCH) go build -o $(MANIFEST_GENERATOR_BINARY) ./cmd/river-manifest

start_redis:
	@if ! docker container inspect $(REDIS_CONTAINER) >/dev/null 2>&1; then \
		docker create --name $(REDIS_CONTAINER) -p $(REDIS_PORT):$(REDIS_PORT) redis:latest >/dev/null; \
	fi
	@if [ "$$(docker container inspect -f '{{.State.Running}}' $(REDIS_CONTAINER))" != "true" ]; then \
		docker start $(REDIS_CONTAINER) >/dev/null; \
	fi

stop_redis:
	@if docker container inspect $(REDIS_CONTAINER) >/dev/null 2>&1 && \
		[ "$$(docker container inspect -f '{{.State.Running}}' $(REDIS_CONTAINER))" = "true" ]; then \
		docker stop $(REDIS_CONTAINER); \
	fi

manifest: build
	@test -n "$(MODEL)" || (echo "MODEL=/path/to/model is required"; exit 2)
	@test -n "$(MANIFEST)" || (echo "MANIFEST=/path/to/model.river.yaml is required"; exit 2)
	@./$(MANIFEST_GENERATOR_BINARY) generate --binary "$(MODEL)" --output "$(MANIFEST)"

run: build start_redis
	@test -n "$(MANIFEST)" || (echo "MANIFEST=/path/to/model.river.yaml is required"; exit 2)
	@sudo ./$(SERVER_BINARY) -manifest "$(MANIFEST)"
bench: build_bench start_redis
	@test -n "$(MANIFEST)" || (echo "MANIFEST=/path/to/model.river.yaml is required"; exit 2)
	sudo sysctl -w kernel.bpf_stats_enabled=1
	@sudo ./$(SERVER_BINARY) -b -manifest "$(MANIFEST)"

clean:
	@rm -rf $(SIMULATOR_PATH)/headers
	@rm -rf $(SERVER_BINARY) $(MANIFEST_GENERATOR_BINARY) $(SIMULATOR_PATH)/probe_*_bpf*.*
