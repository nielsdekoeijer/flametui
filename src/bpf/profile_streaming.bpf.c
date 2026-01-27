#include "profile_streaming.bpf.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 8 * 1024 * 1024); // 8MB buffer
} events SEC(".maps");

__u64 dropped_events = 0;

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __uint(key_size, sizeof(__u32));
  __uint(value_size, MAX_STACK_DEPTH * sizeof(__u64));
} scratch_kstack SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __uint(key_size, sizeof(__u32));
  __uint(value_size, MAX_STACK_DEPTH * sizeof(__u64));
} scratch_ustack SEC(".maps");

SEC("perf_event")
int do_sample(struct bpf_perf_event_data *ctx) {
  // dynamic pointer
  struct bpf_dynptr ptr;
  __u32 key;

  // get scratch space
  key = 0;
  __u64 *kscratch = bpf_map_lookup_elem(&scratch_kstack, &key);
  if (!kscratch) {
    __sync_fetch_and_add(&dropped_events, 1);
    return 0;
  }
  
  key = 0;
  __u64 *uscratch = bpf_map_lookup_elem(&scratch_ustack, &key);
  if (!uscratch) {
    __sync_fetch_and_add(&dropped_events, 1);
    return 0;
  }

  // get pid
  __u64 pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;

  // populate kernel scratch
  long kres = bpf_get_stack(ctx, kscratch, MAX_STACK_DEPTH * sizeof(__u64), 0);
  __u64 kstack_size = 0;
  if (kres > 0) {
    kstack_size = kres;
  }
  
  // // populate user scratch
  long ures = bpf_get_stack(ctx, uscratch, MAX_STACK_DEPTH * sizeof(__u64), BPF_F_USER_STACK);
  __u64 ustack_size = 0;
  if (ures > 0) {
    ustack_size = ures;
  }

  long err;
  err = bpf_ringbuf_reserve_dynptr(&events, sizeof(__u64) * 3 + ustack_size + kstack_size , 0, &ptr);
  if (err < 0) {
      __sync_fetch_and_add(&dropped_events, 1);
      bpf_ringbuf_discard_dynptr(&ptr, 0);
      return 0;
  }

  __u64 offset;

  // add our pid
  offset = 0;
  err = bpf_dynptr_write(&ptr, offset, &pid, sizeof(pid), 0);
  offset = offset + sizeof(pid);
  if (err < 0) {
      __sync_fetch_and_add(&dropped_events, 1);
      bpf_ringbuf_discard_dynptr(&ptr, 0);
      return 0;
  }

  // share the size of our ustack
  err = bpf_dynptr_write(&ptr, offset, &ustack_size, sizeof(ustack_size), 0);
  offset = offset + sizeof(ustack_size);
  if (err < 0) {
      __sync_fetch_and_add(&dropped_events, 1);
      bpf_ringbuf_discard_dynptr(&ptr, 0);
      return 0;
  }

  // share the size of our kstack
  err = bpf_dynptr_write(&ptr, offset, &kstack_size, sizeof(kstack_size), 0);
  offset = offset + sizeof(kstack_size);
  if (err < 0) {
      __sync_fetch_and_add(&dropped_events, 1);
      bpf_ringbuf_discard_dynptr(&ptr, 0);
      return 0;
  }

  // bang on the ustack
  err = bpf_dynptr_write(&ptr, offset, uscratch, ustack_size, 0);
  offset = offset + ustack_size;
  if (err < 0) {
      __sync_fetch_and_add(&dropped_events, 1);
      bpf_ringbuf_discard_dynptr(&ptr, 0);
      return 0;
  }

  // bang on the kstack
  err = bpf_dynptr_write(&ptr, offset, kscratch, kstack_size, 0);
  offset = offset + kstack_size;
  if (err < 0) {
      __sync_fetch_and_add(&dropped_events, 1);
      bpf_ringbuf_discard_dynptr(&ptr, 0);
      return 0;
  }

  bpf_ringbuf_submit_dynptr(&ptr, 0);

  return 0;
}
