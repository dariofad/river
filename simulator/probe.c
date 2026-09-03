// go:build ignore

#include "headers/vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define DRAIN_SINGLE_POINT 1

#ifdef DEBUG
#define DEBUG_P(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)
#else
#define DEBUG_P(...)                                                                               \
        do {                                                                                       \
        } while (0)
#endif

#define MAX_NOF_SIGNALS 16
volatile const __u32 NOF_SIGNALS_READ;
volatile const __u32 NOF_SIGNALS_WRITTEN;

// timing
volatile const __u32 MINOR_TO_MAJOR_RATIO;
__u32 minor_step  = 0;
__u32 IS_MAJOR    = 0;
__u32 time        = 0;
__u32 log_counter = 0;
volatile const __u32 MAX_CYCLES;

__u64 stash[MAX_NOF_SIGNALS];

// -----------------------------------------------------------------------
// SIGNAL DATA
// Discrete time signal values
struct sequence {
        __uint(type, BPF_MAP_TYPE_ARRAY);
        __type(key, __u32);        // time
        __type(value, __u64);      // ieee754-formatted  value stored in a __u64
        __uint(max_entries, 4096); // NB adjust before simulating the model
};
// Discrete model trajectory
struct trajectory {
        __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
        __type(key, __u32);
        __type(value, __u32); // FD
        __uint(max_entries, 4096);
        __array(values, struct sequence);
} trajectory_map SEC(".maps");
// Addresses by signal key
struct {
        __uint(type, BPF_MAP_TYPE_ARRAY);
        __type(key, __u32);
        __type(value, __u64);
        __uint(max_entries, 4096); // NB adjust before simulating the model
} address_map SEC(".maps");

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
struct live_record {
        __u32 time;
        __u32 filler;
        __u64 values[MAX_NOF_SIGNALS];
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
        __u64 s_l; // , s_s;
        if (a_l) {
                e_l = e_a;
                m_l = m_a;
                s_l = s_a;
                e_s = e_b;
                m_s = m_b;
                //                s_s = s_b;
        } else {
                e_l = e_b;
                m_l = m_b;
                s_l = s_b;
                e_s = e_a;
                m_s = m_a;
                //                s_s = s_a;
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
                DEBUG_P("\tERR: OP RESULTED IN OVERFLOW");
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

/* static __u64 ieee754_sub(__u64 a, __u64 b) { */

/*         // flip sign and do an addition */
/*         b ^= (1ULL << 63); */
/*         return ieee754_add(a, b); */
/* } */

struct i_loop_ctx {
        __u32 time;
        __u64 inj_pert;
};

static long inject_values(u64 index, void *_ctx) {

        struct i_loop_ctx *ctx = _ctx;
        __u32 skey             = (__u32)index;

        void *sequence = bpf_map_lookup_elem(&trajectory_map, &skey);
        if (!sequence) {
                DEBUG_P("\tERR retrieving sequence map");
                return 1;
        }

        // get the value injected from userspace
        __u64 *pert = bpf_map_lookup_elem(sequence, &(ctx->time));
        if (!pert) {
                DEBUG_P("\tERR retrieving the sequence value (urb draining)");
                return 1;
        } else {
                // add injected value to the desired trajectory sequence
                DEBUG_P("\ttime_key %d, initial: %llu, added: %llu", skey, *pert, ctx->inj_pert);
                ctx->inj_pert = ieee754_add(ctx->inj_pert, *pert);
                int err = bpf_map_update_elem(sequence, &(ctx->time), &(ctx->inj_pert), BPF_ANY);
                if (err != 0) {
                        DEBUG_P("\t\t-> failed injection, ERR: %d", err);
                        return 1;
                } else {
                        DEBUG_P("\t\t-> successful injection");
                }
        }

        return 0;
}

static long get_injected_point_from_usp(struct bpf_dynptr *dynptr, __u32 *placeholder) {

        struct live_record *R;
        R = bpf_dynptr_data(dynptr, 0, sizeof(struct live_record));
        if (!R) {
                return 0;
        }

        struct i_loop_ctx ctx = {
            .time = R->time,
        };

        __u32 actual_time = time - 1;
        if (actual_time > R->time) {
                bpf_printk("LIVE INJECTION, time: %d [late] -->> %d", actual_time, R->time);
                return DRAIN_SINGLE_POINT;
        } else {
                bpf_printk("LIVE INJECTION, time: %d [on time] (affects time: %d)", actual_time,
                           R->time);
        }

#pragma unroll
        for (int i = 0; i < 8; ++i) {
                if (i >= NOF_SIGNALS_WRITTEN)
                        break;
                ctx.inj_pert = R->values[i];
                // Write trajectories follow all read trajectories in the map.
                inject_values(i + NOF_SIGNALS_READ, &ctx);
        }
#pragma unroll
        for (int i = 8; i < MAX_NOF_SIGNALS; ++i) {
                if (i >= NOF_SIGNALS_WRITTEN)
                        break;
                ctx.inj_pert = R->values[i];
                inject_values(i + NOF_SIGNALS_READ, &ctx);
        }

        return DRAIN_SINGLE_POINT;
}

static long get_injected_stateval_from_usp(struct bpf_dynptr *dynptr, __u32 placeholder) {

        struct state_record *SR;
        SR = bpf_dynptr_data(dynptr, 0, 8 + 2 * 8);
        if (!SR) {
                return 0;
        }

        __u32 actual_time = time - 1;
        if (actual_time > SR->time) {
                bpf_printk("LIVE STATE INJECTION, time: %d [late]", actual_time);
                return DRAIN_SINGLE_POINT;
        } else {
                bpf_printk("LIVE STATE INJECTION, time: %d [on time] (affects time: %d)",
                           actual_time, SR->time);
        }

        struct state_record_trimmed SRT = {
            .addr  = SR->addr,
            .value = SR->value,
        };
        // transfer the state record to a map
        int err = bpf_map_update_elem(&state_trace, &SR->time, &SRT, BPF_ANY);
        if (err != 0) {
                DEBUG_P("\tERR: cannot save the state perturbation at time %d", SR->time);
        } else {
                DEBUG_P("\t-> saved value: %llu (address: %llu)", SRT.value, SRT.addr);
        }

        return DRAIN_SINGLE_POINT;
}

static inline int flush() {

        DEBUG_P("Start flushing...");
        // flush the stash to the cache
        struct model_record *r;
        // reserve memory in the ring buffer
        r = bpf_ringbuf_reserve(&out_rb,
                                sizeof(struct model_record) + NOF_SIGNALS_READ * sizeof(__u64), 0);
        if (r == NULL) {
                DEBUG_P("\tERR, failed to reserve rb memory");
                return -1;
        }
        r->time   = time - 1; // actual time
        r->filler = 0;
        // it is implemented this way since it avoids automatic
        // rewriting and consequent program rejection by the
        // verifier
        for (__u32 k = 0; k < MAX_NOF_SIGNALS; k++) {
                if (k < NOF_SIGNALS_READ)
                        r->values[k] = stash[k];
        }
        // commit to the rb
        bpf_ringbuf_submit(r, BPF_RB_NO_WAKEUP);
        log_counter++;
        DEBUG_P("\t\t-> output record committed to the ring buffer");

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

        // send SIGKILL after last flush
        if (time == MAX_CYCLES) {
                DEBUG_P("\tLOGGED %d RECORDS", log_counter);
                DEBUG_P("\tSIGKILL SENT TO PROCESS");
                bpf_send_signal(SIGKILL);
                return 0;
        }

        return 0;
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

        return 0;
}

static inline int copy_user_space_value_to_map(__u32 actual_time, __u32 key, __u64 value) {

        struct sequence *seq = (struct sequence *)bpf_map_lookup_elem(&trajectory_map, &key);
        if (seq == NULL) {
                DEBUG_P("\tERR retrieving sequence map");
                return -1;
        }
        // update the sequence
        int err = bpf_map_update_elem(seq, &actual_time, &value, BPF_ANY);
        if (err != 0) {
                DEBUG_P("\tERR, cannot copy value to sequence at time %d", key);
                return -1;
        } else {
                DEBUG_P("\t\t-> value copied to trace");
        }
        return 0;
}

static inline int read_signals(__u64 cookie) {

        // determine the correct simulation time
        __u32 actual_time = time - 1;
        // extract signals within the current group
        __u32 group_base = (__u32)cookie >> 4;
        __u32 group_size = ((__u32)cookie & 0b1111) + 1;
        DEBUG_P("\tgroup %d, there are %d signals to read", group_base, group_size);

        for (__u32 k = 0; k < MAX_NOF_SIGNALS; k++) {
                if (k >= group_size)
                        break;
                __u32 key = k + group_base;
                // get the signal address
                __u64 *address = bpf_map_lookup_elem(&address_map, &key);
                if (!address) {
                        DEBUG_P("\tERR retrieving address from address_map");
                        return -1;
                }
                // read the signal from user space
                __u64 signal = 0;
                if (bpf_probe_read_user(&signal, sizeof(signal), (void *)*address) == 0) {
                        DEBUG_P("\tsign_key %d from user space: %llu (address: %llu)", key, signal,
                                *address);
                } else {
                        DEBUG_P("\tERR, failed to read signal");
                        return -1;
                }
                // copy the current value in the correct trajectory sequence
                copy_user_space_value_to_map(actual_time, key, signal);
                // prepare a copy of the value read to flush at the end of the cycle
                if (key < MAX_NOF_SIGNALS)
                        stash[key] = signal;
        }

        // flush records for persistence
        if ((group_base + group_size) == NOF_SIGNALS_READ) {
                flush();
        }
        return 0;
}

SEC("uretprobe/read")
int uprobe_read(struct pt_regs *ctx) {

        if (!IS_MAJOR) { // skip the rest of the program if not major step
                return 0;
        } else {
                if (NOF_SIGNALS_READ > MAX_NOF_SIGNALS) {
                        DEBUG_P("\tERR, too many signals to read");
                        return -1;
                }
                DEBUG_P("READ_INPUT, time: %d", time - 1);
                __u64 cookie = bpf_get_attach_cookie(ctx);
                DEBUG_P("Cookie: %d", cookie);
                return read_signals(cookie);
        }
}

struct w_loop_ctx {
        __u32 actual_time;
};

static long write_signal(u64 index, void *_ctx) {

        struct w_loop_ctx *ctx = _ctx;
        __u32 skey             = (__u32)index;

        // get the sequence
        bpf_printk("skey: %d", skey);
        void *sequence = bpf_map_lookup_elem(&trajectory_map, &skey);
        if (!sequence) {
                DEBUG_P("\tERR retrieving the signal sequence");
                return 1;
        }
        // get the desired value for the signal
        __u64 *value = bpf_map_lookup_elem(sequence, &(ctx->actual_time));
        if (!value) {
                DEBUG_P("\tERR reading the desired value for signal %d", skey);
                return 1;
        } else {
                DEBUG_P("\ttime key %d pert: %llu", skey, *value);
        }

        // get the signal address
        __u64 *address = bpf_map_lookup_elem(&address_map, &skey);
        if (!address) {
                DEBUG_P("\tERR retrieving address from address_map");
                return 1;
        }

        // read the signal from user space
        __u64 sign = 0;
        if (bpf_probe_read_user(&sign, sizeof(sign), (void *)*address) == 0) {
                DEBUG_P("\ttime key %d from user space: %llu", skey, sign);
        } else {
                DEBUG_P("\tERR, failed to read time key %d from user space", skey);
                return 1;
        }

        // add perturbation to signal
        sign = ieee754_add(sign, *value);

        // overwrite signal in user space
        long err = bpf_probe_write_user((void *)*address, &sign, 8);
        if (err != 0) {
                DEBUG_P("\tERR, failed to overwrite signal %k in user space, err: %ld", skey, err);
                return 1;
        } else {
                DEBUG_P("\t\t-> new user space value set to: %llu", sign);
        }

        return 0;
}

SEC("uretprobe/write")
int uprobe_write(struct pt_regs *ctx) {

        if (!IS_MAJOR) { // skip the rest of the program if not major step
                return 0;
        } else {
                if (NOF_SIGNALS_WRITTEN > MAX_NOF_SIGNALS) {
                        DEBUG_P("\tERR, too many signals to write");
                        return -1;
                }

                __u32 actual_time = time - 1;
                __u64 cookie = bpf_get_attach_cookie(ctx);
                __u32 group_base = (__u32)cookie >> 4;

                // check runtime state injection available (STATE DRAIN)
                // todo: apply multiple state value at the same time
                __u32 placeholder = 0;
                bpf_user_ringbuf_drain(&state_rb, get_injected_stateval_from_usp, &placeholder, 0);
                // check live injection available (DRAIN)
                bpf_user_ringbuf_drain(&inj_rb, get_injected_point_from_usp, &placeholder, 0);

                // write live injection to user space
                // state
                struct state_record_trimmed *SRT = bpf_map_lookup_elem(&state_trace, &actual_time);
                if (SRT == 0) {
                        DEBUG_P("-> no state perturbation applicable");
                } else {
                        // write state injection to user space
                        long err = bpf_probe_write_user((void *)(SRT->addr), &(SRT->value), 8);
                        if (err != 0) {
                                DEBUG_P("\tERR, failed to write state perturbation to user "
                                        "space, err: %d",
                                        err);
                        } else {
                                DEBUG_P("-> used state perturbation, "
                                        "value: %llu (address: %llu)",
                                        SRT->value, SRT->addr);
                        }
                }
                // signals
                struct w_loop_ctx wl_ctx = {
                    .actual_time = actual_time,
                };

                // extract signals within the current group
                __u32 group_size = ((__u32)cookie & 0b1111) + 1;
                DEBUG_P("\tgroup %d, there are %d signals to write", group_base, group_size);
#pragma unroll
                for (int i = 0; i < 8; ++i) {
                        if (i >= group_size)
                                break;
                        write_signal(i + group_base, &wl_ctx);
                }
#pragma unroll
                for (int i = 8; i < MAX_NOF_SIGNALS; ++i) {
                        if (i >= group_size)
                                break;
                        write_signal(i + group_base, &wl_ctx);
                }
        }
        return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";
