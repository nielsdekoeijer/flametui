#include "profile.bpf.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"
#include "bpf_tracing.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define MAX_STACK_DEPTH 127
#define MAX_ENTRIES 10240

// map for stack traces
struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, MAX_STACK_DEPTH * sizeof(__u64));
    __uint(max_entries, MAX_ENTRIES);
} stack_traces SEC(".maps");

// hash map for results
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct key_t));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, MAX_ENTRIES);
} counts SEC(".maps");

SEC("perf_event")
int do_sample(struct bpf_perf_event_data *ctx) {
    struct key_t key = {};
    __u64 id = bpf_get_current_pid_tgid();
    key.tgid = id >> 32;
    key.pid = id; 
    key.user_stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_USER_STACK);
    key.kernel_stack_id = bpf_get_stackid(ctx, &stack_traces, 0);
    bpf_get_current_comm(&key.comm, sizeof(key.comm));

    __u64 *val = bpf_map_lookup_elem(&counts, &key);
    if (val) {
        __sync_fetch_and_add(val, 1);
    } else {
        __u64 initial_count = 1;
        bpf_map_update_elem(&counts, &key, &initial_count, BPF_NOEXIST);
    }

    return 0;
}
