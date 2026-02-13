#include "profile_streaming.bpf.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 8 * 1024 * 1024); // 8MB buffer
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct globals_t);
    __uint(map_flags, BPF_F_MMAPABLE);
} globals_map SEC(".maps");

static __always_inline struct globals_t* get_globals() {
    __u32 key = 0;
    return bpf_map_lookup_elem(&globals_map, &key);
}

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
  // grab timestamp
  __u64 timestamp = bpf_ktime_get_ns();

  // dynamic pointer
  struct bpf_dynptr ptr;
  __u32 key;

  // get pid
  __u64 tgid = bpf_get_current_pid_tgid();
  __u64 pid = tgid >> 32;

  // get globals
  struct globals_t* globals = get_globals();
  if (!globals) {
      return 0;
  }

  // if its pid 0, thats the kernel generating kernel events like scheduling, skip 
  if (pid == 0 && globals->enable_idle == 0) {
      return 0;
  }

  // pid filtering
  __u64 pids_len = globals->pids_len;
  if (pids_len > 32) {
      return 0;
  }

  if (pids_len > 0 && pid != 0) {
      bool found = false;
      for (__u64 i = 0; i < pids_len; i++) {
          if (pid == globals->pids[i]) {
              found = true;
          }
      }

      if (!found) {
          return 0;
      }
  }

  // get scratch space
  key = 0;
  __u64 *kscratch = bpf_map_lookup_elem(&scratch_kstack, &key);
  if (!kscratch) {
    __sync_fetch_and_add(&globals->dropped_events, 1);
    return 0;
  }

  key = 0;
  __u64 *uscratch = bpf_map_lookup_elem(&scratch_ustack, &key);
  if (!uscratch) {
    __sync_fetch_and_add(&globals->dropped_events, 1);
    return 0;
  }

  // populate kernel scratch
  long kres = bpf_get_stack(ctx, kscratch, MAX_STACK_DEPTH * sizeof(__u64), 0);
  __u64 kstack_size = 0;
  if (kres > 0) {
    kstack_size = kres;
    if (kstack_size >= MAX_STACK_DEPTH * sizeof(__u64)) {
        kstack_size = MAX_STACK_DEPTH * sizeof(__u64) - 1;
    }
  }

  // // populate user scratch
  long ures = bpf_get_stack(ctx, uscratch, MAX_STACK_DEPTH * sizeof(__u64), BPF_F_USER_STACK);
  __u64 ustack_size = 0;
  if (ures > 0) {
    ustack_size = ures;
    if (ustack_size >= MAX_STACK_DEPTH * sizeof(__u64)) {
        ustack_size = MAX_STACK_DEPTH * sizeof(__u64) - 1;
    }
  }

  long err;
  __u64 ringbufferSize = sizeof(__u64) * 4 + ustack_size + kstack_size;
  err = bpf_ringbuf_reserve_dynptr(&events,  ringbufferSize, 0, &ptr);
  if (err < 0) {
      __sync_fetch_and_add(&globals->dropped_events, 1);
      bpf_ringbuf_discard_dynptr(&ptr, 0);
      return 0;
  }

  __u64 offset = 0;

  // add our tgid
  err = bpf_dynptr_write(&ptr, offset, &tgid, sizeof(tgid), 0);
  offset = offset + sizeof(tgid);
  if (err < 0) {
      __sync_fetch_and_add(&globals->dropped_events, 1);
      bpf_ringbuf_discard_dynptr(&ptr, 0);
      return 0;
  }

  // add our timestamp
  err = bpf_dynptr_write(&ptr, offset, &timestamp, sizeof(timestamp), 0);
  offset = offset + sizeof(timestamp);
  if (err < 0) {
      __sync_fetch_and_add(&globals->dropped_events, 1);
      bpf_ringbuf_discard_dynptr(&ptr, 0);
      return 0;
  }
  
  // share the size of our ustack
  err = bpf_dynptr_write(&ptr, offset, &ustack_size, sizeof(ustack_size), 0);
  offset = offset + sizeof(ustack_size);
  if (err < 0) {
      __sync_fetch_and_add(&globals->dropped_events, 1);
      bpf_ringbuf_discard_dynptr(&ptr, 0);
      return 0;
  }

  // share the size of our kstack
  err = bpf_dynptr_write(&ptr, offset, &kstack_size, sizeof(kstack_size), 0);
  offset = offset + sizeof(kstack_size);
  if (err < 0) {
      __sync_fetch_and_add(&globals->dropped_events, 1);
      bpf_ringbuf_discard_dynptr(&ptr, 0);
      return 0;
  }

  // show the verifier
  if (ustack_size > MAX_STACK_DEPTH * sizeof(__u64)) {
      ustack_size = MAX_STACK_DEPTH * sizeof(__u64);
  }

  // bang on the ustack
  err = bpf_dynptr_write(&ptr, offset, uscratch, ustack_size, 0);
  offset = offset + ustack_size;
  if (err < 0) {
      __sync_fetch_and_add(&globals->dropped_events, 1);
      bpf_ringbuf_discard_dynptr(&ptr, 0);
      return 0;
  }

  // show the verifier
  if (kstack_size > MAX_STACK_DEPTH * sizeof(__u64)) {
      kstack_size = MAX_STACK_DEPTH * sizeof(__u64);
  }
  
  // // bang on the kstack
  err = bpf_dynptr_write(&ptr, offset, kscratch, kstack_size, 0);
  offset = offset + kstack_size;
  if (err < 0) {
      __sync_fetch_and_add(&globals->dropped_events, 1);
      bpf_ringbuf_discard_dynptr(&ptr, 0);
      return 0;
  }

  bpf_ringbuf_submit_dynptr(&ptr, 0);

  return 0;
}
