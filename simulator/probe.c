//go:build ignore

#include "headers/vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_VALUES_PER_MODEL 256

struct runtime_data_desc {
        __u64 offset;
        __u32 model_id;
        __u32 size;
        __u32 type;
        __u32 category;
        __u32 flags;
        __u32 base_kind;
};
struct {
        __uint(type, BPF_MAP_TYPE_ARRAY);
        __uint(max_entries, 4096);
        __type(key, __u32);
        __type(value, struct runtime_data_desc);
} runtime_data_map SEC(".maps");

struct runtime_model_desc {
        __u32 input_start;
        __u32 input_count;
        __u32 sample_start;
        __u32 sample_count;
        __u32 state_start;
        __u32 state_count;
        __u32 sample_every;
        __u32 max_cycles;
};
struct {
        __uint(type, BPF_MAP_TYPE_ARRAY);
        __uint(max_entries, 64);
        __type(key, __u32);
        __type(value, struct runtime_model_desc);
} runtime_model_map SEC(".maps");

struct runtime_key {
        __u64 pid_tgid;
        __u32 model_id;
        __u32 padding;
};
struct runtime_state {
        __u64 base;
        __u64 instruction;
        __u32 invocation;
        __u32 cycle;
        __u32 sampled;
        __u32 padding;
};
struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 1024);
        __type(key, struct runtime_key);
        __type(value, struct runtime_state);
} runtime_state_map SEC(".maps");

struct named_state_key {
        __u32 model_id;
        __u32 cycle;
        __u32 data_id;
};
struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 4096);
        __type(key, struct named_state_key);
        __type(value, __u64);
} runtime_state_write_map SEC(".maps");

struct runtime_value_key {
        __u32 data_id;
        __u32 cycle;
};
struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 65536);
        __type(key, struct runtime_value_key);
        __type(value, __u64);
} runtime_trajectory_map SEC(".maps");

struct runtime_model_record {
        __u32 time;
        __u32 model_id;
        __u32 count;
        __u32 filler;
        // Ring-buffer reservations must have a verifier-known constant size.
        // count determines how many values are meaningful in this record.
        __u64 values[MAX_VALUES_PER_MODEL];
};
struct {
        __uint(type, BPF_MAP_TYPE_RINGBUF);
        __uint(max_entries, 128 * 4096);
} out_rb SEC(".maps");

static __always_inline int runtime_read(void *address, __u32 size, __u64 *value) {
        *value = 0;
        if (size == 1) {
                __u8 v = 0;
                int err = bpf_probe_read_user(&v, sizeof(v), address);
                *value = v;
                return err;
        }
        if (size == 2) {
                __u16 v = 0;
                int err = bpf_probe_read_user(&v, sizeof(v), address);
                *value = v;
                return err;
        }
        if (size == 4) {
                __u32 v = 0;
                int err = bpf_probe_read_user(&v, sizeof(v), address);
                *value = v;
                return err;
        }
        if (size == 8) {
                __u64 v = 0;
                int err = bpf_probe_read_user(&v, sizeof(v), address);
                *value = v;
                return err;
        }
        return -1;
}

static __always_inline int runtime_write(void *address, __u32 size, __u64 *value) {
        if (size == 1) {
                __u8 v = (__u8)*value;
                return bpf_probe_write_user(address, &v, sizeof(v));
        }
        if (size == 2) {
                __u16 v = (__u16)*value;
                return bpf_probe_write_user(address, &v, sizeof(v));
        }
        if (size == 4) {
                __u32 v = (__u32)*value;
                return bpf_probe_write_user(address, &v, sizeof(v));
        }
        if (size == 8) {
                __u64 v = *value;
                return bpf_probe_write_user(address, &v, sizeof(v));
        }
        return -1;
}

SEC("uprobe/model_entry")
int uprobe_model_entry(struct pt_regs *ctx) {
        __u64 cookie = bpf_get_attach_cookie(ctx);
        if (cookie == 0)
                return 0;
        __u32 model_id = (__u32)(cookie - 1);
        struct runtime_model_desc *model = bpf_map_lookup_elem(&runtime_model_map, &model_id);
        if (!model || model->sample_every == 0)
                return 0;

        struct runtime_key key = {
            .pid_tgid = bpf_get_current_pid_tgid(),
            .model_id = model_id,
        };
        struct runtime_state initial = {};
        struct runtime_state *state = bpf_map_lookup_elem(&runtime_state_map, &key);
        if (!state) {
                bpf_map_update_elem(&runtime_state_map, &key, &initial, BPF_NOEXIST);
                state = bpf_map_lookup_elem(&runtime_state_map, &key);
                if (!state)
                        return 0;
        }
        state->base = PT_REGS_PARM1(ctx);
        state->instruction = bpf_get_func_ip(ctx);
        state->sampled = (state->invocation % model->sample_every) == 0;
        state->invocation++;
        if (!state->sampled)
                return 0;

        __u32 cycle = state->cycle++;
        for (__u32 i = 0; i < MAX_VALUES_PER_MODEL; i++) {
                if (i >= model->input_count)
                        break;
                __u32 data_id = model->input_start + i;
                struct runtime_data_desc *data = bpf_map_lookup_elem(&runtime_data_map, &data_id);
                struct runtime_value_key value_key = {
                    .data_id = data_id,
                    .cycle = cycle,
                };
                __u64 *value = bpf_map_lookup_elem(&runtime_trajectory_map, &value_key);
                if (data && (data->flags & 1) && value)
                        runtime_write((void *)(state->base + data->offset), data->size, value);
        }
        for (__u32 i = 0; i < MAX_VALUES_PER_MODEL; i++) {
                if (i >= model->state_count)
                        break;
                __u32 data_id = model->state_start + i;
                struct named_state_key state_key = {
                    .model_id = model_id,
                    .cycle = cycle,
                    .data_id = data_id,
                };
                __u64 *value = bpf_map_lookup_elem(&runtime_state_write_map, &state_key);
                struct runtime_data_desc *data = bpf_map_lookup_elem(&runtime_data_map, &data_id);
                if (data && value) {
                        __u64 base = data->base_kind == 2 ? state->instruction : state->base;
                        runtime_write((void *)(base + data->offset), data->size, value);
                        bpf_map_delete_elem(&runtime_state_write_map, &state_key);
                }
        }
        return 0;
}

SEC("uretprobe/model_return")
int uprobe_model_return(struct pt_regs *ctx) {
        __u64 cookie = bpf_get_attach_cookie(ctx);
        if (cookie == 0)
                return 0;
        __u32 model_id = (__u32)(cookie - 1);
        struct runtime_model_desc *model = bpf_map_lookup_elem(&runtime_model_map, &model_id);
        struct runtime_key key = {
            .pid_tgid = bpf_get_current_pid_tgid(),
            .model_id = model_id,
        };
        struct runtime_state *state = bpf_map_lookup_elem(&runtime_state_map, &key);
        if (!model || !state || !state->sampled)
                return 0;
        __u32 cycle = state->cycle - 1;
        if (model->max_cycles > 0 && cycle >= model->max_cycles) {
                bpf_send_signal(9);
                return 0;
        }
        if (model->sample_count > MAX_VALUES_PER_MODEL)
                return -1;

        struct runtime_model_record *record = bpf_ringbuf_reserve(&out_rb, sizeof(*record), 0);
        if (!record)
                return -1;
        record->time = cycle;
        record->model_id = model_id;
        record->count = model->sample_count;
        record->filler = 0;
        for (__u32 i = 0; i < MAX_VALUES_PER_MODEL; i++) {
                if (i >= model->sample_count)
                        break;
                __u32 data_id = model->sample_start + i;
                struct runtime_data_desc *data = bpf_map_lookup_elem(&runtime_data_map, &data_id);
                __u64 value = 0;
                if (data) {
                        __u64 base = data->base_kind == 2 ? state->instruction : state->base;
                        runtime_read((void *)(base + data->offset), data->size, &value);
                }
                record->values[i] = value;
        }
        bpf_ringbuf_submit(record, BPF_RB_NO_WAKEUP);
        return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";
