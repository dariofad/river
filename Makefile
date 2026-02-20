.phony: all build run generate vmlinux aslr_off redis start_redis stop_redis bench

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

pert_injector:
	gcc -Wall -O2 -o $(SIMULATOR_PATH)/injector $(SIMULATOR_PATH)/injector.c -lbpf; \
		sudo setcap cap_bpf,cap_perfmon+ep $(SIMULATOR_PATH)/injector

state_pert_injector:
	gcc -Wall -O2 -o $(SIMULATOR_PATH)/state_injector $(SIMULATOR_PATH)/state_injector.c -lbpf; \
		sudo setcap cap_bpf,cap_perfmon+ep $(SIMULATOR_PATH)/state_injector

build: generate pert_injector state_pert_injector
# with CGO_ENABLED=0 the build doesn't depend on libc
	@CGO_ENABLED=0 GO_ARCH=amd64 go build

redis:
	docker create --name redis -p $(REDIS_PORT):$(REDIS_PORT) redis:latest

start_redis:
	docker start redis

stop_redis:
	docker stop redis

aslr_off:
	echo 0 | sudo tee /proc/sys/kernel/randomize_va_space

_run: | aslr_off build start_redis
	sudo su -c 'rm -rf /sys/fs/bpf/inner*'
	sudo su -c 'rm -rf /sys/fs/bpf/pertbuf*'
	sudo su -c 'rm -rf /sys/fs/bpf/state_pertbuf*'
	@if docker ps -a --filter "name=$(CONTAINER_NAME)" --format "{{.ID}}" | grep -q .; then \
		echo "-> container $(CONTAINER_NAME) is already running or exists. Skipping creation."; \
	else \
		echo "-> creating and running container $(CONTAINER_NAME)..."; \
		docker run -d --name $(CONTAINER_NAME) $(IMAGE_NAME); \
		sleep 3; \
	fi

run: _run
	@sudo ./$(GO_MODULE)

bench: _run
	sudo sysctl -w kernel.bpf_stats_enabled=1
	@sudo ./$(GO_MODULE) -b

clean:
	@rm -rf $(SIMULATOR_PATH)/headers
	@rm -rf $(GO_MODULE) $(SIMULATOR_PATH)/$(EBPF_PROBE)_bpf* $(SIMULATOR_PATH)/injector $(SIMULATOR_PATH)/state_injector
