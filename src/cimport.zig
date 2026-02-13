/// Import all our c dependencies, except for bpf specific things
pub const c = @cImport({
    @cInclude("libbpf.h");
    @cInclude("stdio.h");
    @cInclude("bpf.h");
    @cInclude("linux/perf_event.h");
    @cInclude("stdlib.h");
});

