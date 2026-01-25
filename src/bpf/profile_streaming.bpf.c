#include "profile_streaming.bpf.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 8 * 1024 * 1024); // 8MB buffer
} events SEC(".maps");

__u64 dropped_events = 0;

SEC("perf_event")
int do_sample(struct bpf_perf_event_data *ctx) {
    struct sample_event *e;
    
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        __sync_fetch_and_add(&dropped_events, 1);
        return 0;
    }

    __u64 id = bpf_get_current_pid_tgid();
    e->pid = id;
    e->tgid = id >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    long k_res = bpf_get_stack(ctx, e->kips, sizeof(e->kips), 0);
    if (k_res > 0) {
        e->kstack_sz = k_res;
    } else {
        e->kstack_sz = 0;
    }

    long u_res = bpf_get_stack(ctx, e->uips, sizeof(e->uips), BPF_F_USER_STACK);
    if (u_res > 0) {
        e->ustack_sz = u_res;
    } else {
        e->ustack_sz = 0;
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}
