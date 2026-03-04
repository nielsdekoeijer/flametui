#include "uprobe_helper.h"

struct bpf_link *attach_uprobe_helper(struct bpf_program *prog,
                                      const char *binary, const char *func_name,
                                      bool retprobe) {
  LIBBPF_OPTS(bpf_uprobe_opts, opts, .func_name = func_name,
              .retprobe = retprobe);
  return bpf_program__attach_uprobe_opts(prog, -1, binary, 0, &opts);
}
