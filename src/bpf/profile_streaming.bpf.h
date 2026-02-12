#include "vmlinux.h"

#define MAX_STACK_DEPTH 128

struct globals {
    __u64 dropped_events;
    __u64 enable_idle; 
    __u64 pids[32];
    __u64 pids_len;
};
