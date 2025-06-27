// go:build ignore

#include "headers/vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// user space memory address
volatile const __u64 ADDR_BASE;
volatile const __u64 ADDR_OBJ;
volatile const __u64 ADDR_X;
volatile const __u64 ADDR_Y;

SEC("uretprobe/step_tracker")
int uretprobe_step_monitor() {

	// reading an input of a simulink model
        __u32 key = 0;
        __u32 val_read = 0.0;
        long err = bpf_probe_read_user(&val_read, sizeof(val_read), (void *)(ADDR_BASE+ADDR_OBJ+ADDR_X));
	if (err != 0) {
		bpf_printk("UREAD ERROR: %ld\n", err);		          
		return 0;
        } else {
		bpf_printk("Value: %d\n", val_read);
        }
	
	// overwriting a value input to a simulink module
        __u32 val_to_write = 10;
	err = bpf_probe_write_user((void *)(ADDR_BASE+ADDR_OBJ+ADDR_Y), &val_to_write, sizeof(val_to_write));
	if (err != 0) {
		bpf_printk("UWRITE FAILED: %ld\n", err);
		return 0;
        }

	return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";
