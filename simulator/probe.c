// go:build ignore

#include "headers/vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define DRAIN_SINGLE_POINT 1

const __u32 MAX_NOF_SIGNALS = 16;

// interactivity
struct {
        __uint(type, BPF_MAP_TYPE_ARRAY);
        __uint(max_entries, 1);
        __type(key, u32);
        __type(value, u16);
} interactive_map SEC(".maps");
static __u16 get_interactive(void) {
        u32 key    = 0;
        __u16 *val = bpf_map_lookup_elem(&interactive_map, &key);
        return val ? *val : 0;
}

volatile const __u32 NOF_WISIGNALS;
volatile const __u32 NOF_RISIGNALS;
volatile const __u32 NOF_ROSIGNALS;

// timing
volatile const __u32 MINOR_TO_MAJOR_RATIO;
__u32 minor_step  = 0;
__u32 IS_MAJOR    = 0;
__u32 time        = 0;
__u32 log_counter = 0;
volatile const __u32 MAX_CYCLES;

__u64 stash[16]; // hardcoded

// -----------------------------------------------------------------------
// MAPS TO STORE SIGNALS
// single trace
struct m_signal {
        __uint(type, BPF_MAP_TYPE_ARRAY);
        __type(key, __u32);
        __type(value, __u64);      // use __u64 to store an ieee754 value
        __uint(max_entries, 4096); // NB adjust before simulating the model
};
// traces by signal key
struct m_signals {
        __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
        __type(key, __u32);
        __type(value, __u32); // FD
        __uint(max_entries, 4096);
        __array(values, struct m_signal);
} tracee_map SEC(".maps");
// addresses by signal key
struct {
        __uint(type, BPF_MAP_TYPE_ARRAY);
        __type(key, __u32);
        __type(value, __u64);
        __uint(max_entries, 4096); // NB adjust before simulating the model
} address_map SEC(".maps");
// types by signal key (0 write_i, 1 read_i, 2 read_o)
struct {
        __uint(type, BPF_MAP_TYPE_ARRAY);
        __type(key, __u32);
        __type(value, __u32);
        __uint(max_entries, 4096); // NB adjust before simulating the model
} type_map SEC(".maps");

// -----------------------------------------------------------------------
//
// signals
const __u16 SIGKILL = 9;

// kernel -> user space ring buffer
struct model_record {
        __u32 time;
        __u32 filler;
        __u64 values[];
};
struct {
        __uint(type, BPF_MAP_TYPE_RINGBUF);
        __uint(max_entries,
               128 * 4096); // must be a power of 2 and a multiple of 4096 (memory page size)
} out_rb SEC(".maps");

// user -> kernel space ring buffer for noise injection
struct pert_record { // todo: use a structure with dynamic len
        __u32 time;
        __u32 filler;
        __u64 values[8]; // hardcoded
};
struct {
        __uint(type, BPF_MAP_TYPE_USER_RINGBUF);
        __uint(max_entries, 128 * 4096); // see note above
} inj_rb SEC(".maps");

// user -> kernel space ring buffer to dynamically change the state
struct state_record {
        __u32 time;
        __u32 value_size;
        __u64 addr;
        __u64 value;
};
struct state_record_trimmed {
        __u64 addr;
        __u64 value;
};
struct {
        __uint(type, BPF_MAP_TYPE_USER_RINGBUF);
        __uint(max_entries, 4096);
} state_rb SEC(".maps");
// state array map
struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 4096);
        __type(key, __u32);
        __type(value, struct state_record_trimmed);
} state_trace SEC(".maps");

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
                delta = 63; // undefined behavior
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
        int msb_pos    = 63 - left_zeros;
        int shift      = msb_pos - 52;
        __s32 e_res    = (__s32)e_l + shift;

        // overflow occurred
        if (e_res > 2046 || e_res < 0) {
                bpf_printk("\tERR: OP RESULTED IN OVERFLOW");
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

struct i_loop_ctx {
        __u32 time;
        __u64 inj_pert;
};

static long inj_signals(u64 index, void *_ctx) {

        struct i_loop_ctx *ctx = _ctx;
        __u32 skey             = (__u32)index;

        void *sign_trace = bpf_map_lookup_elem(&tracee_map, &skey);
        if (!sign_trace) {
                bpf_printk("\tERR retrieving sign_trace map");
                return 1;
        }

        // get the perturbation value
        __u64 *pert = bpf_map_lookup_elem(sign_trace, &(ctx->time));
        if (!pert) {
                bpf_printk("\tERR retrieving the signal trace (urb draining)");
                return 1;
        } else {
                // add injected value to initial perturbation
                bpf_printk("\tsign_key %d, initial: %llu, added: %llu", skey, *pert, ctx->inj_pert);
                ctx->inj_pert = ieee754_add(ctx->inj_pert, *pert);
                int err = bpf_map_update_elem(sign_trace, &(ctx->time), &(ctx->inj_pert), BPF_ANY);
                if (err != 0) {
                        bpf_printk("\t\t-> failed injection, ERR: %d", err);
                        return 1;
                } else {
                        bpf_printk("\t\t-> successful injection");
                }
        }

        return 0;
}

static long extract_injected_pert(struct bpf_dynptr *dynptr, __u32 *_nof_pert_signals) {

        struct pert_record *DRAINED_RECORD;
        DRAINED_RECORD = bpf_dynptr_data(dynptr, 0, 8 + 8 * 8);
        if (!DRAINED_RECORD) {
                return 0;
        }
        __u32 thr = *_nof_pert_signals;

        struct i_loop_ctx ctx = {
            .time = DRAINED_RECORD->time,
        };

        __u32 actual_time = time - 1;
        if (actual_time > DRAINED_RECORD->time) {
                bpf_printk("LIVE PERTURBATION, time: %d [late]", actual_time);
                return DRAIN_SINGLE_POINT;
        } else {
                bpf_printk("LIVE PERTURBATION, time: %d [on time] (affects time: %d)", actual_time,
                           DRAINED_RECORD->time);
        }

#pragma unroll
        for (int i = 0; i < 8; ++i) { // hardcoded
                if (i >= NOF_WISIGNALS)
                        break;
                ctx.inj_pert = DRAINED_RECORD->values[i];
                inj_signals(i, &ctx);
        }

        return DRAIN_SINGLE_POINT;
}

static long extract_injected_state_pert(struct bpf_dynptr *dynptr, __u32 placeholder) {

        struct state_record *DRAINED_RECORD;
        DRAINED_RECORD = bpf_dynptr_data(dynptr, 0, 8 + 2 * 8);
        if (!DRAINED_RECORD) {
                return 0;
        }

        __u32 actual_time = time - 1;
        if (actual_time > DRAINED_RECORD->time) {
                bpf_printk("LIVE STATE PERTURBATION, time: %d [late]", actual_time);
                return DRAIN_SINGLE_POINT;
        } else {
                bpf_printk("LIVE STATE PERTURBATION, time: %d [on time] (affects time: %d)",
                           actual_time, DRAINED_RECORD->time);
        }

        struct state_record_trimmed srt = {
            .addr  = DRAINED_RECORD->addr,
            .value = DRAINED_RECORD->value,
        };
        // transfer the state record to a map
        int err = bpf_map_update_elem(&state_trace, &DRAINED_RECORD->time, &srt, BPF_ANY);
        if (err != 0) {
                bpf_printk("\tERR: cannot save the state perturbation at time %d",
                           DRAINED_RECORD->time);
        } else {
                bpf_printk("\t-> saved value: %llu (address: %llu)", srt.value, srt.addr);
        }

        return DRAIN_SINGLE_POINT;
}

SEC("uretprobe/timer")
int uprobe_timer() {

        // determine if the current cyclic is a major step
        if (minor_step % MINOR_TO_MAJOR_RATIO == 0) {
                IS_MAJOR = 1;
                time++;
        } else {
                IS_MAJOR = 0;
        }
        minor_step++;
        if (time > MAX_CYCLES) {
                bpf_printk("\tLOGGED %d RECORDS", log_counter - 1);
                bpf_printk("\tSIGKILL SENT TO PROCESS");
                bpf_send_signal(SIGKILL);
                return 0;
        }
        return 0;
}

static inline int copy_user_space_value_to_map(__u32 actual_time, __u32 key, __u64 signal) {

        struct m_signal *sign_trace = (struct m_signal *)bpf_map_lookup_elem(&tracee_map, &key);
        if (sign_trace == NULL) {
                bpf_printk("\tERR retrieving sign_trace map");
                return -1;
        }
        // update the signal trace
        int err = bpf_map_update_elem(sign_trace, &actual_time, &signal, BPF_ANY);
        if (err != 0) {
                bpf_printk("\tERR, cannot copy value of sign_key %d to trace", key);
                return -1;
        } else {
                bpf_printk("\t\t-> value copied to trace");
        }
        return 0;
}

static inline int read_signals(__u32 nof_signals, __u32 key_offset, __u16 IS_OUTPUT) {

        if (nof_signals > MAX_NOF_SIGNALS) {
                bpf_printk("\tERR, too many signals to read");
                return -1;
        }

        // determine the correct simulation time
        __u32 actual_time = time - 1;
        // check interactivity
        __u16 INTERACTIVE = get_interactive();
        // clean stash (hardcoded)
        stash[0]  = 0;
        stash[1]  = 0;
        stash[2]  = 0;
        stash[3]  = 0;
        stash[4]  = 0;
        stash[5]  = 0;
        stash[6]  = 0;
        stash[7]  = 0;
        stash[8]  = 0;
        stash[9]  = 0;
        stash[10] = 0;
        stash[11] = 0;
        stash[12] = 0;
        stash[13] = 0;
        stash[14] = 0;
        stash[15] = 0;

        bpf_printk("\tnof signals to read: %d", nof_signals);
        for (__u32 k = 0; k < MAX_NOF_SIGNALS; k++) {
                if (k >= nof_signals)
                        break;
                __u32 key = k + key_offset;
                // get the signal address
                __u64 *address = bpf_map_lookup_elem(&address_map, &key);
                if (!address) {
                        bpf_printk("\tERR retrieving address from address_map");
                        return -1;
                }
                // read the signal from user space
                __u64 signal = 0;
                if (bpf_probe_read_user(&signal, sizeof(signal), (void *)(*address)) == 0) {
                        bpf_printk("\tsign_key %d from user space: %llu (address: %llu)", key,
                                   signal, *address);
                } else {
                        bpf_printk("\tERR, failed to read signal");
                        return -1;
                }
                if (INTERACTIVE == 0 || IS_OUTPUT == 0) {
                        copy_user_space_value_to_map(actual_time, key, signal);
                }
                stash[k] = signal;
        }

        struct model_record *r;
        if (INTERACTIVE == 1 && IS_OUTPUT == 1) {
                // reserve memory in the ring buffer
                r = bpf_ringbuf_reserve(
                    &out_rb, sizeof(struct model_record) + nof_signals * sizeof(__u64), 0);
                if (r == NULL) {
                        bpf_printk("\tERR, failed to reserve rb memory");
                        return -1;
                }
                r->time   = actual_time;
                r->filler = 0;
                // it is implemented this way since it avoids automatic
                // rewriting and consequent program rejection by the
                // verifier
                for (__u32 k = 0; k < MAX_NOF_SIGNALS; k++) {
                        if (k < nof_signals)
                                r->values[k] = stash[k];
                }
                // commit to the rb
                bpf_ringbuf_submit(r, BPF_RB_NO_WAKEUP);
                bpf_printk("\t\t-> output record committed to the ring buffer");
        }
        return 0;
}

SEC("uretprobe/read_i")
int uprobe_read_i() {

        if (!IS_MAJOR) { // skip the rest of the program if not major step
                return 0;
        } else {
                __u32 actual_time = time - 1;
                bpf_printk("READ_INPUT, time: %d", actual_time);
                return read_signals(NOF_RISIGNALS, NOF_WISIGNALS, 0);
        }
}

SEC("uretprobe/read_o")
int uprobe_read_o() {

        if (!IS_MAJOR) { // skip the rest of the program if not major step
                return 0;
        } else {
                __u32 actual_time = time - 1;
                bpf_printk("READ_OUTPUT, time: %d", actual_time);
                log_counter += 1;
                return read_signals(NOF_ROSIGNALS, NOF_WISIGNALS + NOF_RISIGNALS, 1);
        }
}

struct w_loop_ctx {
        __u32 actual_time;
};

static long write_signals(u64 index, void *_ctx) {

        struct w_loop_ctx *ctx = _ctx;
        __u32 skey             = (__u32)index;

        // get the signal trace
        void *sign_trace = bpf_map_lookup_elem(&tracee_map, &skey);
        if (!sign_trace) {
                bpf_printk("\tERR retrieving sign_trace map");
                return 1;
        }
        // get the perturbation value
        __u64 *pert = bpf_map_lookup_elem(sign_trace, &(ctx->actual_time));
        if (!pert) {
                bpf_printk("\tERR reading sign_key %d pert", skey);
                return 1;
        } else {
                bpf_printk("\tsign_key %d pert: %llu", skey, *pert);
        }

        // get the signal address
        __u64 *address = bpf_map_lookup_elem(&address_map, &skey);
        if (!address) {
                bpf_printk("\tERR retrieving address from address_map");
                return 1;
        }

        // read the signal from user space
        __u64 sign = 0;
        if (bpf_probe_read_user(&sign, sizeof(sign), (void *)(*address)) == 0) {
                bpf_printk("\tsign_key %d from user space: %llu", skey, sign);
        } else {
                bpf_printk("\tERR, failed to read sign_key %d from user space", skey);
                return 1;
        }

        // add perturbation to signal
        sign = ieee754_add(sign, *pert);

        // overwrite signal in user space
        long err = bpf_probe_write_user((void *)(*address), &sign, 8);
        if (err != 0) {
                bpf_printk("\tERR, failed to overwrite signal %k in user space, err: %ld", skey,
                           err);
                return 1;
        } else {
                bpf_printk("\t\t-> new user space value set to: %llu", sign);
        }

        return 0;
}

SEC("uretprobe/write_i")
int uprobe_write_i() {

        if (!IS_MAJOR) { // skip the rest of the program if not major step
                return 0;
        } else {
                if (NOF_WISIGNALS > 8) { // hardcoded
                        bpf_printk("\tERR, too many signals to write");
                        return -1;
                }

                __u32 actual_time = time - 1;

                // check runtime state injection available (STATE DRAIN)
                __u32 placeholder = 0;
                bpf_user_ringbuf_drain(&state_rb, extract_injected_state_pert, &placeholder, 0);

                // check runtime injection available (DRAIN)
                __u32 _nof_pert_signals = NOF_WISIGNALS;
                bpf_user_ringbuf_drain(&inj_rb, extract_injected_pert, &_nof_pert_signals, 0);

                // write perturbations to user space
                bpf_printk("WRITE, time: %d, nof signals to perturbate: %d", actual_time,
                           NOF_WISIGNALS);
                // write state perturbation to user space
                // state
                struct state_record_trimmed *srt = bpf_map_lookup_elem(&state_trace, &actual_time);
                if (srt == 0) {
                        bpf_printk("-> no state perturbation applicable");
                } else {
                        // write state perturbation to user space
                        long err = bpf_probe_write_user((void *)(srt->addr), &(srt->value), 8);
                        if (err != 0) {
                                bpf_printk("\tERR, failed to write state perturbation to user "
                                           "space, err: %d",
                                           err);
                        } else {
                                bpf_printk("-> used state perturbation, "
                                           "value: %llu (address: %llu)",
                                           srt->value, srt->addr);
                        }
                }
                // signals
                struct w_loop_ctx ctx = {
                    .actual_time = actual_time,
                };
#pragma unroll
                for (int i = 0; i < 8; ++i) { // hardcoded
                        if (i >= NOF_WISIGNALS)
                                break;
                        write_signals(i, &ctx);
                }
        }
        return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";
