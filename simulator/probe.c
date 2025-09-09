// go:build ignore

#include "headers/vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// spec values
volatile const __u64 ADDR_BASE;
volatile const __u64 ADDR_OBJ;
volatile const __u64 ADDR_DREL;
volatile const __u64 OFFSET_MAJORT;

// timing
volatile const __u32 MINOR_TO_MAJOR_RATIO;
__u32 minor_step = 0;
__u32 cycle = 0;
volatile const __u32 MAX_CYCLES;

// signals
const __u16 SIGKILL = 9;

// d_rel map
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u64); // use a u64 to store a double value
} d_rel_map SEC(".maps");

SEC("uretprobe/drel_probe")
int uprobe_drel_probe() {

	// determine if the call is part of a major cycle
	bool isMajor = 0;
	if (minor_step % MINOR_TO_MAJOR_RATIO == 0){
		isMajor = 1;
		cycle++;		
	}
	minor_step++;	
	if (cycle > MAX_CYCLES) {
		bpf_printk("SIGKILL sent to process");
		bpf_send_signal(SIGKILL);
		return 0;
	}
        if (isMajor) {
		__u32 d_rel_key = cycle - 1;
		// read d_rel from input trace
		__u64 *d_rel = bpf_map_lookup_elem(&d_rel_map, &d_rel_key);
		if (!d_rel){
			bpf_printk("Error reading d_rel");
			return 0;
		}
		bpf_printk("d_rel at idx %d: %llu", d_rel_key, *d_rel);
		// overwrite d_rel in userspace memory
		long err = bpf_probe_write_user((void *)(ADDR_BASE+ADDR_OBJ+ADDR_DREL), d_rel, 8);
		if (err != 0) {
			bpf_printk("UWRITE FAILED (d_rel_i): %ld\n", err);
			return 0;
		}	
		__u64 buf = 0;
		// check value written in userspace
		if (bpf_probe_read_user(&buf, sizeof(buf), (void *)(ADDR_BASE+ADDR_OBJ+ADDR_DREL)) == 0) {
			bpf_printk("Read after write: %llu\n", buf);
		} else {
			bpf_printk("Failed to read");
		}	
	}

	return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";
