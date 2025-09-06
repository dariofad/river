// go:build ignore

#include "headers/vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// hardcoded input addresses
volatile const __u64 ADDR_BASE;
volatile const __u64 ADDR_OBJ;
volatile const __u64 ADDR_DREL;

SEC("uretprobe/drel_probe")
int uprobe_drel_probe() {

	// overwriting a memory location of a process executing a simulink model
        __s64 val_to_write = 0;
	int err = bpf_probe_write_user((void *)(ADDR_BASE+ADDR_OBJ+ADDR_DREL), &val_to_write, sizeof(val_to_write));
	if (err != 0) {
		bpf_printk("UWRITE FAILED: %ld\n", err);
		return 0;
        } else {
		bpf_printk("d_rel overwritten\n");
        }
	
	return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";
