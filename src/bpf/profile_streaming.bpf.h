#include "vmlinux.h"

#define MAX_STACK_DEPTH 128

// We use dynamic stacks!
struct sample_event {
    __u64 pid;
    __u64 usize; 
    __u64 ksize; 
    __u64 data[];
    // __u64 kips[MAX_STACK_DEPTH];
    // __u64 uips[MAX_STACK_DEPTH];
};
