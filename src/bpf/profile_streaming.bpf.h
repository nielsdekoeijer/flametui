#include "vmlinux.h"

#define MAX_STACK_DEPTH 128

// We use dynamic stacks!
struct sample_event {
    __u32 pid;
    __u32 kstack_sz; 
    __u32 ustack_sz; 
    __u64 kips[MAX_STACK_DEPTH];
    __u64 uips[MAX_STACK_DEPTH];
};
