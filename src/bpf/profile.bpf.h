#include "vmlinux.h"

struct key_t {
    __u32 pid;
    __s32 user_stack_id;
    __s32 kernel_stack_id;
    __u32 tgid; 
    char comm[16]; 
};
