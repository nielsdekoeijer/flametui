#include "vmlinux.h"

struct key_t {
    __u32 pid;
    __u32 tgid; 
    __s32 user_stack_id;
    __s32 kernel_stack_id;
    char comm[16]; 
};
