const std = @import("std");
const c = @import("cimport.zig").c;

// --------------------------------------------------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------------------------------------------------
/// BPF programs need to be aligned, this function reallocs given data to be in a way that libbpf can load it.
/// Necessary as @embed-ing the file will not yield correct alignment
pub fn dupeProgramAligned(allocator: std.mem.Allocator, data: []const u8) error{OutOfMemory}![]align(8) const u8 {
    const code = try allocator.alignedAlloc(u8, .@"8", data.len);

    @memcpy(code, data);

    return code;
}

test "bpf.dupeProgramAligned returns 8-byte aligned copy" {
    const input = "hello BPF";
    const result = try dupeProgramAligned(std.testing.allocator, input);
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualSlices(u8, input, result);
    try std.testing.expect(@intFromPtr(result.ptr) % 8 == 0);
}

test "bpf.dupeProgramAligned handles empty slice" {
    const result = try dupeProgramAligned(std.testing.allocator, "");
    defer std.testing.allocator.free(result);
    try std.testing.expectEqual(0, result.len);
    try std.testing.expect(@intFromPtr(result.ptr) % 8 == 0);
}

// --------------------------------------------------------------------------------------------------------------------
// Libbpf object wrapping
// --------------------------------------------------------------------------------------------------------------------
/// Wrapper around a libbpf object, which is a loaded elf file. This can contain multiple programs, maps etc.
pub const Object = struct {
    /// libbpf underlying object type
    internal: *c.struct_bpf_object,

    /// Initialize the object from bytecode array
    pub fn init(mem: []align(8) const u8) error{ AlignFailure, OpenFailure, LoadFailure }!Object {
        // Critical for the memory to be 8 byte aligned
        if (@intFromPtr(mem.ptr) % 8 != 0) {
            return error.AlignFailure;
        }

        // Load the elf file
        const internal = c.bpf_object__open_mem(@ptrCast(mem), mem.len, null) orelse return error.OpenFailure;
        errdefer c.bpf_object__close(internal);

        // Load it into the kernel
        if (c.bpf_object__load(internal) < 0) {
            return error.LoadFailure;
        }

        return .{ .internal = internal };
    }

    /// Cleanup and invalidate libbpf object
    pub fn deinit(self: *Object) void {
        c.bpf_object__close(self.internal);
        self.* = undefined;
    }

    test "bpf.Object.init rejects invalid ELF" {
        const program = try dupeProgramAligned(std.testing.allocator, "not a valid elf");
        defer std.testing.allocator.free(program);
        setupLoggerBackend(.none);
        try std.testing.expectError(error.OpenFailure, Object.init(program));
    }

    test "bpf.Object.init rejects empty input" {
        const program = try dupeProgramAligned(std.testing.allocator, "");
        defer std.testing.allocator.free(program);
        setupLoggerBackend(.none);
        try std.testing.expectError(error.OpenFailure, Object.init(program));
    }

    /// Returns a reference to an mmapped eBPF map
    pub fn findMemoryMappedMap(self: Object, name: [:0]const u8, comptime T: type) !MemoryMappedMap(T) {
        const map = c.bpf_object__find_map_by_name(self.internal, name) orelse return error.MapNotFound;

        const value_size = c.bpf_map__value_size(map);
        if (value_size != @sizeOf(T)) {
            return error.MapSizeMismatch;
        }

        const fd = c.bpf_map__fd(map);
        if (fd < 0) return error.MapNotMapped;

        return try MemoryMappedMap(T).init(fd);
    }

    /// Helper type wrapping an eBPF map that is shared through mmapping the underlying map. This is useful for
    /// quicker access, in contrast to using syscalls to interact with the eBPF maps.
    ///
    /// This object owns the underlying mmap'd shared memory and is responsible for cleaning it up
    pub fn MemoryMappedMap(T: type) type {
        return struct {
            map: []align(std.heap.page_size_min) u8,

            /// Initialize from the file descriptor of the underlying map
            pub fn init(fd: std.posix.fd_t) !@This() {
                const ptr = try std.posix.mmap(
                    null,
                    @sizeOf(T),
                    std.posix.PROT.READ | std.posix.PROT.WRITE,
                    .{ .TYPE = .SHARED },
                    fd,
                    0,
                );

                return .{
                    .map = ptr,
                };
            }

            /// Unmaps underlying memory and invalidates self
            pub fn deinit(self: *@This()) void {
                std.posix.munmap(self.map);
                self.* = undefined;
            }

            /// Atomically read a field
            pub fn readAtomic(self: @This(), comptime field_name: []const u8) @FieldType(T, field_name) {
                const ptr = &@field(self.ptrUnsafe().*, field_name);
                return @atomicLoad(@FieldType(T, field_name), ptr, .acquire);
            }

            /// Atomically write a field
            pub fn writeAtomic(self: *@This(), comptime field_name: []const u8, value: @FieldType(T, field_name)) void {
                const ptr = &@field(self.ptrUnsafe().*, field_name);
                @atomicStore(@FieldType(T, field_name), ptr, value, .release);
            }

            /// Helper function get a thread unsafe handle to the underlying memory as a pointer to the underlying type
            pub fn ptrUnsafe(self: @This()) *align(std.heap.page_size_min) volatile T {
                return @as(*align(std.heap.page_size_min) volatile T, @ptrCast(@alignCast(self.map)));
            }
        };
    }

    /// Get a program contained within the object
    pub fn findProgram(self: Object, name: [:0]const u8) error{ProgramNotFound}!Program {
        const program: *c.bpf_program = c.bpf_object__find_program_by_name(self.internal, name.ptr) orelse return error.ProgramNotFound;
        return .{ .program = program };
    }

    /// View over a program stored inside an object.
    ///
    /// Note that the bpf object used when creating the program owns it, and thus will clean it up.
    pub const Program = struct {
        program: *c.bpf_program,

        /// View over a link to a program
        pub const Link = struct {
            link: *c.struct_bpf_link,

            pub fn deinit(self: *Link) void {
                if (c.bpf_link__destroy(self.link) != 0) {
                    @panic("ebpf link destruction failure");
                }

                self.* = undefined;
            }
        };

        /// Generic attachment
        pub fn attach(self: Program) error{AttachFailure}!Link {
            const link = c.bpf_program__attach(self.program) orelse return error.AttachFailure;
            return .{ .link = link };
        }

        /// Attachment with perf event file descriptor
        ///
        /// On success, libbpf takes ownership of fd. On failure, caller must close fd.
        pub fn attachPerfEvent(self: Program, fd: std.posix.fd_t) error{AttachFailure}!Link {
            const link = c.bpf_program__attach_perf_event(self.program, fd) orelse return error.AttachFailure;
            return .{ .link = link };
        }

        /// Attachment with tracepoint
        ///
        /// On success, libbpf takes ownership of fd. On failure, caller must close fd.
        pub fn attachTracepoint(self: Program, category: [:0]const u8, name: [:0]const u8) error{AttachFailure}!Link {
            const link = c.bpf_program__attach_tracepoint(self.program, category, name) orelse return error.AttachFailure;
            return .{ .link = link };
        }

        /// Attachment with kprobe
        ///
        /// On success, libbpf takes ownership of fd. On failure, caller must close fd.
        pub fn attachKProbe(self: Program, retprobe: bool, name: [:0]const u8) error{AttachFailure}!Link {
            const link = c.bpf_program__attach_kprobe(self.program, retprobe, name) orelse return error.AttachFailure;
            return .{ .link = link };
        }

        /// Attachment with uprobe
        ///
        /// On success, libbpf takes ownership of fd. On failure, caller must close fd.
        pub fn attachUProbe(self: Program, retprobe: bool, binary: [:0]const u8, symbol: [:0]const u8) error{AttachFailure}!Link {
            const link = c.attach_uprobe_helper(
                self.program,
                binary.ptr,
                symbol.ptr,
                retprobe,
            ) orelse return error.AttachFailure;

            return .{ .link = link };
        }
    };

    /// Finds ring buffer, instantiate with a callback
    pub fn findRingBuffer(
        self: Object,
        comptime ContextType: type,
        comptime EventType: type,
        comptime handler: *const fn (*ContextType, *const EventType) void,
        context: *ContextType,
        name: [:0]const u8,
    ) error{ RingBufferNotFound, OpenFailure }!RingBuffer {
        const fd = blk: {
            const fd = c.bpf_object__find_map_fd_by_name(self.internal, name);
            if (fd < 0) {
                return error.RingBufferNotFound;
            }

            break :blk fd;
        };

        const cb = RingBuffer.callback(ContextType, EventType, handler);
        const rb = c.ring_buffer__new(fd, cb, context, null) orelse return error.OpenFailure;
        errdefer c.ring_buffer__free(rb);

        return RingBuffer{
            .ringbuffer = rb,
        };
    }

    /// View over a ringbuffer with an associated callback
    ///
    /// Note that the bpf object used when creating the ringbuffer owns it, and thus will clean it up.
    pub const RingBuffer = struct {
        ringbuffer: *c.struct_ring_buffer,

        pub fn deinit(self: *RingBuffer) void {
            c.ring_buffer__free(self.ringbuffer);
            self.* = undefined;
        }

        pub fn callback(
            comptime ContextType: type,
            comptime EventType: type,
            comptime handler: *const fn (*ContextType, *const EventType) void,
        ) fn (?*anyopaque, ?*anyopaque, usize) callconv(.c) c_int {
            return struct {
                // TODO: this is quite unsafe, we are also throwing away the size. There's a more elegant solution 
                // possible here I think...
                pub fn handlerWrapper(ctx: ?*anyopaque, data: ?*anyopaque, size: usize) callconv(.c) c_int {
                    _ = size;
                    const event = @as(*const EventType, @ptrCast(@alignCast(data orelse @panic("event is null"))));
                    const context = @as(*ContextType, @ptrCast(@alignCast(ctx orelse @panic("context is null"))));
                    handler(context, event);
                    return 0;
                }
            }.handlerWrapper;
        }

        /// Check the ringbuffer for items and invoke the callback
        pub fn poll(self: RingBuffer, ms: i64) error{PollFailure}!void {
            if (c.ring_buffer__poll(self.ringbuffer, @intCast(ms)) < 0) {
                return error.PollFailure;
            }
        }

        /// Consume one entry from the ring buffer and return 
        pub fn consume(self: RingBuffer) error{ConsumeFailure}!usize {
            const ret = c.ring_buffer__consume(self.ringbuffer);
            if (ret < 0) {
                return error.ConsumeFailure;
            }

            return @intCast(ret);
        }

    };
};

// --------------------------------------------------------------------------------------------------------------------
// Libbpf logging forwarding
// --------------------------------------------------------------------------------------------------------------------
/// Unfortunately, the underlying C structure generated seems to change per platform, perhaps because of various
/// defines. Thus, we infer it using compiletime reflection.
pub fn DetermineFunctionArgumentType(comptime func: anytype, comptime index: usize) type {
    return @typeInfo(@typeInfo(@typeInfo(func).optional.child).pointer.child).@"fn".params[index].type.?;
}

/// Logger that can be passed to libbpf, which forwards logs to zig logger
fn log(
    level: c.enum_libbpf_print_level,
    fmt: [*c]const u8,
    ap: DetermineFunctionArgumentType(c.libbpf_print_fn_t, 2),
) callconv(.c) c_int {
    // Format print into buf from libc
    var buf: [1024]u8 = undefined;
    const len_c = c.vsnprintf(&buf, buf.len, fmt, ap);

    // On error log + return
    if (len_c < 0) {
        const errno = std.posix.errno(std.math.lossyCast(usize, len_c));
        std.log.err("vsnprintf failed: {s}", .{@tagName(errno)});
        return 0;
    }

    // Extract slice sans buffer len and newline + nullterm
    const raw_len = @min(@as(usize, @intCast(len_c)), buf.len);
    const slice = std.mem.trimRight(u8, buf[0..raw_len], "\n\x00");

    // If we have for whatever reason an empty log line, we just return len_c
    if (slice.len == 0) {
        return len_c;
    }

    // Map to zig logger
    switch (level) {
        c.LIBBPF_WARN => {
            std.log.warn("libbpf: {s}", .{slice});
        },
        c.LIBBPF_INFO => {
            std.log.info("libbpf: {s}", .{slice});
        },
        c.LIBBPF_DEBUG => {
            std.log.debug("libbpf: {s}", .{slice});
        },
        else => {
            std.log.warn("libbpf (unknown log level): {s}", .{slice});
        },
    }

    return len_c;
}

/// Helper to configure the logging backend
pub fn setupLoggerBackend(mode: enum { zig, none }) void {
    // Setting a logging function pointer to previous logging function, which we choose to discard
    _ = c.libbpf_set_print(switch (mode) {
        .none => null,
        .zig => log,
    });
}
