#include "vmlinux.h"

#define MAX_STACK_DEPTH 128

struct sample_event {
    __u32 pid;
    __u32 tgid;
    __u32 kstack_sz; 
    __u32 ustack_sz; 
    char comm[16];
    __u64 kips[MAX_STACK_DEPTH];
    __u64 uips[MAX_STACK_DEPTH];
};

