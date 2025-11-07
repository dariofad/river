.phony: all build run generate vmlinux aslr_off

EBPF_PROBE = probe
GO_MODULE = ebpf_simulator
SIMULATOR_PATH := simulator
REDIS_PORT := 6379

all: run

vmlinux:
	mkdir -p $(SIMULATOR_PATH)/headers
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(SIMULATOR_PATH)/headers/vmlinux.h

generate: vmlinux
	cd $(SIMULATOR_PATH); go generate

build: generate
# with CGO_ENABLED=0 the build doesn't depend on libc
	@CGO_ENABLED=0 GO_ARCH=amd64 go build

redis:
	docker create --name redis -p $(REDIS_PORT):$(REDIS_PORT) redis:latest

start_redis:
	docker start redis

run: build start_redis
	@if docker ps -a --filter "name=$(CONTAINER_NAME)" --format "{{.ID}}" | grep -q .; then \
		echo "-> container $(CONTAINER_NAME) is already running or exists. Skipping creation."; \
	else \
		echo "-> creating and running container $(CONTAINER_NAME)..."; \
		docker run -d --name $(CONTAINER_NAME) $(IMAGE_NAME); \
		sleep 3; \
	fi
	@sudo ./$(GO_MODULE)

clean:
	@rm -rf $(SIMULATOR_PATH)/headers
	@rm -rf $(GO_MODULE) $(SIMULATOR_PATH)/$(EBPF_PROBE)_bpf*

aslr_off:
	@echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
