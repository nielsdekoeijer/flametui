#ifndef UPROBE_HELPER_H
#define UPROBE_HELPER_H
#include <libbpf.h>
struct bpf_link *attach_uprobe_helper(struct bpf_program *prog,
                                      const char *binary, const char *func_name,
                                      bool retprobe);
#endif
