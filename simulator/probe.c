// go:build ignore

#include "headers/vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// interactivity
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u16);
} interactive_map SEC(".maps");
static __u16 get_interactive(void) {
    u32 key = 0;
    __u16 *val = bpf_map_lookup_elem(&interactive_map, &key);
    return val ? *val : 0;
}

volatile const __u32 NOF_WISIGNALS;
volatile const __u32 NOF_RISIGNALS;
volatile const __u32 NOF_ROSIGNALS;

const __u32 MAX_NOF_SIGNALS = 16;

// timing
volatile const __u32 MINOR_TO_MAJOR_RATIO;
__u32 minor_step = 0;
__u32 IS_MAJOR = 0;
__u32 time = 0;
__u32 log_counter = 0;
volatile const __u32 MAX_CYCLES;

// -----------------------------------------------------------------------
// MAPS TO STORE SIGNALS
// single trace
struct m_signal {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);        // use __u64 to store an ieee754 value
    __uint(max_entries, 4096);      // NB adjust before simulating the model
};
// traces by signal key
struct m_signals {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __type(key, __u32);
    __type(value, __u32);  // FD
    __uint(max_entries, 4096);
    __array(values, struct m_signal);
} tracee_map SEC(".maps");
// addresses by signal key
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 4096);	  // NB adjust before simulating the model
} address_map SEC(".maps");
// types by signal key (0 write_i, 1 read_i, 2 read_o)
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 4096);	  // NB adjust before simulating the model
} type_map SEC(".maps");

// -----------------------------------------------------------------------
// 
// signals
const __u16 SIGKILL = 9;

struct out_record {
	__u32 time;
	__u32 filler;
        __u64 values[];
};
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 128 * 4096); // must be a power of 2 and a multiple of 4096 (memory page size)
} out_rb SEC(".maps");

static __always_inline int count_leading_left_zeroes(__u64 n) {

	int count = 0;
	if (n == 0) {
		return 64;
	}
	if ((n >> 32) == 0) {
		count += 32;
		n <<= 32;
	}
	if ((n >> 48) == 0) {
		count += 16;
		n <<= 16;
	}
	if ((n >> 56) == 0) {
		count += 8;
		n <<= 8;
	}
	if ((n >> 60) == 0) {
		count += 4;
		n <<= 4;
	}
	if ((n >> 62) == 0) {
		count += 2;
		n <<= 2;
	}
	if ((n >> 63) == 0) {
		count += 1;
	}
	return count;
}

// Returns always 0 in case of overflow, also prints a message to trace_pipe
static __u64 ieee754_add(__u64 a, __u64 b) {
	
	__u64 s_a = (a >> 63) & 1;
	__u64 s_b = (b >> 63) & 1;
    
	__u64 e_a = (a >> 52) & 0x7ff;
	__u64 m_a = a & 0x000fffffffffffffULL;
	if (e_a != 0) {
		m_a |= (1ULL << 52); // non-zero value, explicitly add the first "mantissa bit"
	}

	__u64 e_b = (b >> 52) & 0x7ff;
	__u64 m_b = b & 0x000fffffffffffffULL;
	if (e_b != 0) {
		m_b |= (1ULL << 52);
	}

	bool same_sign = (s_a == s_b);

	// determine the large and small number
	bool a_l = (e_a > e_b) || ((e_a == e_b) && (m_a > m_b));
	__u64 e_l, e_s, m_l, m_s;
	__u64 s_l, s_s;
	if (a_l) {
		e_l = e_a;
		m_l = m_a;
		s_l = s_a;
		e_s = e_b;
		m_s = m_b;
		s_s = s_b;
	} else {
		e_l = e_b;
		m_l = m_b;
		s_l = s_b;
		e_s = e_a;
		m_s = m_a;
		s_s = s_a;
	}

	// align the two mantissa to perform the operation
	__s32 delta = (__s32)e_l - (__s32)e_s;
	if (delta > 63) {
		delta = 63;  // undefined behavior
	}
	m_s >>= delta;

	__u64 m_res;
        __u64 s_res = s_l;
        if (same_sign) {
                m_res = m_l + m_s;
        } else {
                m_res = m_l - m_s;
        }
        if (m_res == 0) {
                return 0ULL;
        }

        // normalize the representation of the result (A + B)
        // A. fix the exponent
        int left_zeros = count_leading_left_zeroes(m_res);
        int msb_pos = 63 - left_zeros;
        int shift = msb_pos - 52;
        __s32 e_res = (__s32)e_l + shift;

        // overflow occurred
	if (e_res > 2046 || e_res < 0) {
		bpf_printk("OP RESULTED IN OVERFLOW");
		return 0ULL;
	}
	
        // B. shift mantissa accordingly
        if (shift > 0) {
                if (shift > 63)
                  shift = 63;
                m_res >>= shift;
        } else if (shift < 0) {
                int left_shift = -shift;
                if (left_shift > 63)
                  left_shift = 63;
                m_res <<= left_shift;
        }

        // mask mantissa
        __u64 mant = m_res & ((1ULL << 52) - 1ULL);

        // assemble the result
        __u64 result = (s_res << 63) | ((__u64)e_res << 52) | mant;
	
        return result;
}

static __u64 ieee754_sub(__u64 a, __u64 b) {

	// flip sign and do an addition
	b ^= (1ULL << 63);
	return ieee754_add(a, b);
}

SEC("uretprobe/timer")
int uprobe_timer() {

	// determine if the current cyclic is a major step
	if (minor_step % MINOR_TO_MAJOR_RATIO == 0){
		IS_MAJOR = 1;
		time++;		
	} else {
		IS_MAJOR = 0;
	}
	minor_step++;	
	if (time > MAX_CYCLES) {
		bpf_printk("Logged %d records", log_counter-1);
		bpf_printk("SIGKILL sent to process");
		bpf_send_signal(SIGKILL);
		return 0;
	}
	return 0;
}

static inline int read_signals(__u32 nof_signals, __u32 key_offset) {

	if (nof_signals > MAX_NOF_SIGNALS){
		bpf_printk("Too many signals to read");
		return -1;
	}

	// determine the correct simulation time
       __u32 actual_time = time - 1;
       bpf_printk("Actual time %d:", actual_time);
       __u64 values[16];

       for (__u32 k = 0; k < nof_signals; k++){
	       __u32 key = k + key_offset;
	       // get the signal address
	       __u64 *address = bpf_map_lookup_elem(&address_map, &key);
	       if (!address){
		       bpf_printk("ERR retrieving address from address_map");
		       return -1;
	       }
	       // read the signal from user space
	       __u64 signal = 0;
	       if (bpf_probe_read_user(&signal, sizeof(signal), (void *)(*address)) == 0) {
		       bpf_printk("Signal %d from user space: %llu", key, signal);
	       } else {
		       bpf_printk("Failed to read signal");
		       return -1;
	       }
	       // get the signal trace
	       bpf_printk("Retrieving trace for signal %d", key);
	       struct m_signal *sign_trace = (struct m_signal *)bpf_map_lookup_elem(&tracee_map, &key);
	       if (sign_trace == NULL){
		       bpf_printk("ERR retrieving sign_trace map");			
		       return -1;
	       }
	       // update the signal trace
	       int err = bpf_map_update_elem(sign_trace, &actual_time, &signal, BPF_ANY);
	       if (err != 0) {
		       bpf_printk("Cannot write signal %d to trace", key);
		       return -1;
	       } else {
		       bpf_printk("Signal %d written to trace, value: %llu", key, signal);
	       }
	       values[k] = signal;
       }

       __u16 INTERACTIVE = get_interactive();
       struct out_record *r;
       if (INTERACTIVE == 1){
	       // reserve memory in the ring buffer
	       r = bpf_ringbuf_reserve(&out_rb, sizeof(struct out_record) + nof_signals * sizeof(__u64), 0);
	       if (r == NULL) {
		       bpf_printk("Failed to reserve rb memory");
		       return -1;
	       }
	       r->time = actual_time;
	       r->filler = 0;
	       // it is implemented this way since it avoids automatic
	       // rewriting and consequent program rejection by the
	       // verifier
	       for (__u32 k = 0; k < MAX_NOF_SIGNALS; k++){
		       if (k < nof_signals)
			       r->values[k] = values[k];
	       }
	       // commit to the rb
	       bpf_ringbuf_submit(r, BPF_RB_NO_WAKEUP);
	       bpf_printk("Record committed to the ring buffer");
      }
      return 0;	
}

SEC("uretprobe/read_i")
int uprobe_read_i() {

        if (!IS_MAJOR){ // skip the rest of the program if not major step
		return 0;
	} else {
		return read_signals(NOF_RISIGNALS, NOF_WISIGNALS);
	}
}

SEC("uretprobe/read_o")
int uprobe_read_o() {

        if (!IS_MAJOR){ // skip the rest of the program if not major step
		return 0;
	} else {
		log_counter += 1;
		return read_signals(NOF_ROSIGNALS, NOF_WISIGNALS + NOF_RISIGNALS);
	}
}

SEC("uretprobe/write_i")
int uprobe_write_i() {

        if (!IS_MAJOR) // skip the rest of the program if not major step
		return 0;

	if (NOF_WISIGNALS > MAX_NOF_SIGNALS){
		bpf_printk("Too many signals to write");
		return -1;
	}

	for (__u32 s = 0; s < NOF_WISIGNALS; s++){
		// get the signal trace
		__u32 key = s;
		bpf_printk("Retrieving perturbation trace for signal %d", key);
		void *sign_trace = bpf_map_lookup_elem(&tracee_map, &key);
		if (!sign_trace){
			bpf_printk("ERR retrieving sign_trace map");
			return -1;
		}
		
		// read the perturbation from the input trace
		__u32 actual_time = time - 1;
		__u64 *pert = bpf_map_lookup_elem(sign_trace, &actual_time);
		if (!pert){
			bpf_printk("Error reading signal %d pert", key);
			return -1;
		} else {
			bpf_printk("Signal %d perturbation: %llu", key, *pert);
		}

		// get the signal address
		__u64 *address = bpf_map_lookup_elem(&address_map, &key);
		if (!address){
			bpf_printk("ERR retrieving address from address_map");
			return -1;
		}
		
		// read the signal from the user space
		__u64 sign = 0;
		if (bpf_probe_read_user(&sign, sizeof(sign), (void *)(*address)) == 0) {
			bpf_printk("Signal %d from user space: %llu", key, sign);
		} else {
			bpf_printk("Failed to read signal %d from user space", key);
			return -1;
		}

		// add perturbation to signal
		sign = ieee754_add(sign, *pert);
		bpf_printk("New value after perturbation: %llu", sign);

		// overwrite signal in user space
		long err = bpf_probe_write_user((void *)(address), &sign, 8);
		if (err != 0) {
			bpf_printk("Failed to overwrite signal %k, err: %ld", key, err);
			return -1;
		}
	}
	return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";
