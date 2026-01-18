#ifndef DEFINITIONS_H
#define DEFINITIONS_H
#include "vmlinux.h"

struct event {
    u32 pid;
    u8 comm[16]; 
};

#endif
