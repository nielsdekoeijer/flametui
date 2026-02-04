const std = @import("std");
const c = @import("cimport.zig").c;

pub fn setupLoggerBackend(mode: enum { zig, none }) !void {
    _ = switch (mode) {
        .none => c.libbpf_set_print(null),
        // .zig => c.libbpf_set_print(log),
        .zig => c.libbpf_set_print(log),
    };
}

pub fn loadProgramAligned(allocator: std.mem.Allocator, data: anytype) ![]align(8) const u8 {
    const code = try allocator.alignedAlloc(u8, .@"8", data.len);
    @memcpy(code, data);

    return code;
}

// ------------------------
// Represents a BPF Object
// ------------------------
pub const Object = struct {
    internal: *c.struct_bpf_object,

    fn getMapByName(self: Object, name: [*c]const u8) !*c.struct_bpf_map {
        return c.bpf_object__find_map_by_name(self.internal, name) orelse error.MapNotFound;
    }

    pub fn getGlobals(self: Object, comptime T: type) !*T {
        const map = try self.getMapByName(".bss");
        var size: usize = 0;
        const ptr = c.bpf_map__initial_value(map, &size);
        if (ptr == null) return error.MapNotMmapped;
        if (size < @sizeOf(T)) return error.MapSizeMismatch;
        return @as(*T, @ptrCast(@alignCast(ptr)));
    }

    pub fn load(mem: []const u8) anyerror!Object {
        const obj = c.bpf_object__open_mem(@ptrCast(mem), mem.len, null) orelse return error.OpenFailure;
        errdefer c.bpf_object__close(obj);

        if (c.bpf_object__load(obj) != 0) {
            return error.LoadFailure;
        }

        return Object{
            .internal = obj,
        };
    }

    pub fn attachProgramByName(self: Object, name: [*c]const u8) !Link {
        const prog: *c.bpf_program = c.bpf_object__find_program_by_name(self.internal, name) orelse return error.ProgramNotFound;
        // _ = c.bpf_program__attach(prog) orelse return error.AttachFailure;
        const link = c.bpf_program__attach(prog) orelse return error.AttachFailure;
        return Link{ .internal = link };
    }

    pub fn attachProgramPerfEventByName(
        object: Object,
        name: [*c]const u8,
        cpu: usize,
        perfEventAttributes: *std.os.linux.perf_event_attr,
    ) anyerror!Link {
        const prog: ?*c.bpf_program = c.bpf_object__find_program_by_name(object.internal, name) orelse return error.ProgramNotFound;

        const pfd = blk: {
            const pfd = std.os.linux.perf_event_open(perfEventAttributes, -1, @intCast(cpu), -1, 0);
            if (pfd == 0) {
                return error.PerfEventOpenFailure;
            }

            break :blk pfd;
        };

        errdefer {
            _ = std.os.linux.close(@intCast(pfd));
        }
        const link = c.bpf_program__attach_perf_event(prog, @intCast(pfd)) orelse return error.AttachFailure;
        return Link{ .internal = link };
    }

    pub fn free(self: Object) void {
        c.bpf_object__close(self.internal);
    }

    // ------------------------
    // Link
    // ------------------------
    pub const Link = struct {
        internal: ?*c.struct_bpf_link,

        pub fn free(link: *Link) void {
            if (link.internal != null) {
                if (c.bpf_link__destroy(link.internal) != 0) {
                    @panic("ebpf link destruction failure");
                }

                link.internal = null;
            }
        }
    };

    // ------------------------
    // RingBufferMaps
    // ------------------------
    pub const RingBufferMap = struct {
        rb: *c.struct_ring_buffer,
        pub fn createCallback(
            comptime ContextType: type,
            comptime EventType: type,
            comptime handler: *const fn (*ContextType, *const EventType) void,
        ) type {
            return struct {
                pub fn handlerWrapper(ctx: ?*anyopaque, data: ?*anyopaque, size: usize) callconv(.c) c_int {
                    _ = size;
                    const event = @as(*const EventType, @ptrCast(@alignCast(data orelse @panic("event is null"))));
                    const context = @as(*ContextType, @ptrCast(@alignCast(ctx orelse @panic("context is null"))));
                    handler(context, event);
                    return 0;
                }
            };
        }

        pub fn poll(self: RingBufferMap, ms: i64) !void {
            if (c.ring_buffer__poll(self.rb, @intCast(ms)) < 0) {
                return error.PollFailure;
            }
        }

        pub fn consume(self: RingBufferMap) !usize {
            const ret = c.ring_buffer__consume(self.rb) ;
            if (ret < 0) {
                return error.ConsumeFailure;
            }

            return @intCast(ret);
        }

        pub fn free(self: RingBufferMap) void {
            c.ring_buffer__free(self.rb);
        }
    };

    pub fn attachRingBufferMapCallback(
        object: Object,
        comptime ContextType: type,
        comptime EventType: type,
        comptime handler: *const fn (*ContextType, *const EventType) void,
        context: *ContextType,
        name: [*c]const u8,
    ) anyerror!RingBufferMap {
        const fd = blk: {
            const fd = c.bpf_object__find_map_fd_by_name(object.internal, name);
            if (fd < 0) {
                return error.RingBufferMapNotFound;
            }

            break :blk fd;
        };

        const cb = RingBufferMap.createCallback(ContextType, EventType, handler).handlerWrapper;
        const rb = c.ring_buffer__new(fd, cb, context, null) orelse return error.OpenFailure;
        errdefer c.ring_buffer__free(rb);

        return RingBufferMap{
            .rb = rb,
        };
    }
};

const VAListType = blk: switch (@import("builtin").cpu.arch) {
    .aarch64 => break :blk c.struct___va_list_1,
    else => break :blk [*c]c.struct___va_list_tag_1,
};

fn log(level: c.enum_libbpf_print_level, fmt: [*c]const u8, ap: VAListType) callconv(.c) c_int {
    var buf: [512]u8 = undefined;
    const len_c = c.vsnprintf(&buf, buf.len, fmt, ap);
    if (len_c == 0) {
        return 0;
    }

    const len = @max(0, @min(@as(usize, @intCast(len_c)), buf.len) - 2);
    if (len > 0) {
        const slice = buf[0..len];
        switch (level) {
            c.LIBBPF_WARN => {
                std.log.warn("{s}", .{slice});
            },
            c.LIBBPF_INFO => {
                std.log.info("{s}", .{slice});
            },
            c.LIBBPF_DEBUG => {
                std.log.debug("{s}", .{slice});
            },
            else => {
                unreachable;
            },
        }
    }

    return len_c;
}
