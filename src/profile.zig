const std = @import("std");
const bpf = @import("bpf.zig");
const c = @import("cimport.zig").c;

pub const Program = @import("profile_streaming");
pub const Definitions = @cImport(@cInclude("profile_streaming.bpf.h"));

/// Alias for the kernel type
pub const InstructionPointer = u64;

/// Alias for the kernel type
pub const PID = u64;
pub const TID = u64;

/// ===================================================================================================================
/// Helpers
/// ===================================================================================================================
/// The event type from bpf
pub const EventTypeRaw = u64;

/// Our parsed view over the raw data, note we dont clone for efficiencies sake
/// Wire layout (all fields are `u64`):
/// ```
///   [0]  pid | tid
///   [1]  timestamp
///   [2]  us
///   [3]  ks
///   [4]  user IPs ... kernel IPs
/// ```
pub const EventType = struct {
    pid: u64,
    tid: u64,
    timestamp: u64,
    kips: []const u64,
    uips: []const u64,

    // We parse from a raw pointer
    pub fn init(raw: *const EventTypeRaw) EventType {
        const ev = @as([*]const u64, @ptrCast(raw));

        // Sizes are given in bytes
        const us = ev[2] / 8;
        const ks = ev[3] / 8;

        const event = EventType{
            .pid = ev[0] >> 32,
            .tid = ev[0] & 0xFFFFFFFF,
            .timestamp = ev[1],
            .uips = ev[4 .. 4 + us],
            .kips = ev[4 + us .. 4 + us + ks],
        };

        return event;
    }

    test "profile.EventType.init parses mixed user and kernel stacks correctly" {
        const raw = [_]u64{
            (@as(u64, 32) << 32) | 100, // [0] pid (32) | tid (100) -> (32 << 32) | 100
            123456789, // [1] timestamp -> 123456789
            16, // [2] user_stack_size_bytes -> 16 (2 * 8 bytes)
            24, // [3] kernel_stack_size_bytes -> 24 (3 * 8 bytes)
            0xAAAA, // [4] uip[0] -> 0xAAAA
            0xBBBB, // [5] uip[1] -> 0xBBBB
            0x1111, // [6] kip[0] -> 0x1111
            0x2222, // [7] kip[1] -> 0x2222
            0x3333, // [8] kip[2] -> 0x3333
        };

        // Cast the pointer to the type expected by init
        const event = EventType.init(@ptrCast(&raw[0]));

        try std.testing.expectEqual(32, event.pid);
        try std.testing.expectEqual(100, event.tid);
        try std.testing.expectEqual(123456789, event.timestamp);

        // Verify User Stack
        try std.testing.expectEqual(2, event.uips.len);
        try std.testing.expectEqual(0xAAAA, event.uips[0]);
        try std.testing.expectEqual(0xBBBB, event.uips[1]);

        // Verify Kernel Stack
        try std.testing.expectEqual(3, event.kips.len);
        try std.testing.expectEqual(0x1111, event.kips[0]);
        try std.testing.expectEqual(0x2222, event.kips[1]);
        try std.testing.expectEqual(0x3333, event.kips[2]);
    }

    test "profile.EventType.init parses minimal event with empty stacks" {
        const raw = [_]u64{ @as(u64, 42) << 32, 0, 0, 0 };

        const event = EventType.init(@ptrCast(&raw[0]));

        try std.testing.expectEqual(42, event.pid);
        try std.testing.expectEqual(0, event.uips.len);
        try std.testing.expectEqual(0, event.kips.len);
    }

    test "profile.EventType.init parses kernel-only stacks" {
        const raw = [_]u64{ @as(u64, 99) << 32, 0, 0, 16, 0x1111, 0x2222 };

        const event = EventType.init(@ptrCast(&raw[0]));

        try std.testing.expectEqual(99, event.pid);
        try std.testing.expectEqual(0, event.uips.len);
        try std.testing.expectEqual(2, event.kips.len);
    }
};

/// Name of the function in our bpf program
const ProfileFunctionNamePerf = "sample_perf";
const ProfileFunctionNameKProbe = "sample_kprobe";
const ProfileFunctionNameTracePoint = "sample_tracepoint";
const TriggerFunctionNamePerf = "trigger_perf";
const TriggerFunctionNameKProbe = "trigger_kprobe";
const TriggerFunctionNameTracePoint = "trigger_tracepoint";

// --------------------------------------------------------------------------------------------------------------------
// Libbpf attachment types
// --------------------------------------------------------------------------------------------------------------------
pub const Attachment = union(enum) {
    perf: struct {
        hz: usize = 49,

        pub fn parse(subcommand: []const u8) !@This() {
            return @This(){
                .hz = try std.fmt.parseInt(usize, subcommand, 10),
            };
        }
    },
    kprobe: struct {
        name: [:0]const u8,

        pub fn parse(allocator: std.mem.Allocator, subcommand: []const u8) !@This() {
            return @This(){
                .name = try allocator.dupeZ(u8, subcommand),
            };
        }
    },
    tracepoint: struct {
        name: [:0]const u8,
        category: [:0]const u8,

        pub fn parse(allocator: std.mem.Allocator, subcommand: []const u8) !@This() {
            var tokens = std.mem.tokenizeScalar(u8, subcommand, ':');
            return @This(){
                .category = try allocator.dupeZ(u8, tokens.next() orelse return error.ParseError),
                .name = try allocator.dupeZ(u8, tokens.next() orelse return error.ParseError),
            };
        }
    },

    pub fn parse(allocator: std.mem.Allocator, command: []const u8) !Attachment {
        var commandTokenized = std.mem.tokenizeScalar(u8, command, '=');
        const subcommand = commandTokenized.next() orelse return error.ParseError;
        const argument = commandTokenized.next() orelse return error.ParseError;

        if (std.mem.eql(u8, subcommand, "perf")) {
            return .{
                .perf = try .parse(argument),
            };
        }

        if (std.mem.eql(u8, subcommand, "kprobe")) {
            return .{
                .kprobe = try .parse(allocator, argument),
            };
        }

        if (std.mem.eql(u8, subcommand, "tracepoint")) {
            return .{
                .tracepoint = try .parse(allocator, argument),
            };
        }

        return error.ParseError;
    }

    pub fn deinit(self: *Attachment, allocator: std.mem.Allocator) void {
        switch (self.*) {
            inline .kprobe => |s| {
                allocator.free(s.name);
            },
            inline .tracepoint => |s| {
                allocator.free(s.name);
                allocator.free(s.category);
            },
            else => return,
        }

        self.* = undefined;
    }
};

/// ===================================================================================================================
/// Wrappers
/// ===================================================================================================================
/// Wrapper around our profiling ebpf program
pub const ProfilerUnmanaged = struct {
    /// Owned copy of our bpf code
    bytecode: []align(8) const u8,

    /// Wrapper around a bpf object
    object: bpf.Object,

    /// Connections of our bpf object, stays alive
    links: ?[]bpf.Object.Link,

    /// Ringbuffer inside our ebpf program
    ring: bpf.Object.RingBuffer,

    /// Global values for our bpf object
    globals: bpf.Object.Map(Definitions.globals_t),

    pub fn init(
        comptime ContextType: type,
        comptime handler: *const fn (*ContextType, *const EventTypeRaw) void,
        allocator: std.mem.Allocator,
        context: *ContextType,
    ) !ProfilerUnmanaged {
        // Configure logging
        bpf.setupLoggerBackend(.zig);

        // Load our embedded code into an byte array with 8 byte alignment
        const code = try bpf.dupeProgramAligned(allocator, Program.bytecode);
        errdefer allocator.free(code);

        // Use my bpf "library" to wrap the Object
        var object = try bpf.Object.init(code);
        errdefer object.deinit();

        // Create ringbuffer
        var ring = try object.findRingBuffer(ContextType, EventTypeRaw, handler, context, "events");
        errdefer ring.deinit();

        // Global from the program
        var globals = try object.getMapPointer("globals_map", Definitions.globals_t);
        errdefer globals.deinit();

        return ProfilerUnmanaged{
            .bytecode = code,
            .object = object,
            .links = null,
            .ring = ring,
            .globals = globals,
        };
    }

    pub fn deinit(self: *ProfilerUnmanaged, allocator: std.mem.Allocator) void {
        // Frees the links, servering the connection
        self.stop(allocator);

        // Destroy links
        self.globals.deinit();
        self.ring.deinit();
        self.object.deinit();

        allocator.free(self.bytecode);
    }

    /// Opens events and attaches them. We store the links in order to keep them alive. Freeing them closes
    /// the connection.
    pub fn start(self: *ProfilerUnmanaged, allocator: std.mem.Allocator, attachments: []const Attachment) !void {
        if (self.links) |_| {
            return error.ProfilerUnmanagedStartingWhileStarted;
        }

        // Use a dynamic list to gather all links safely
        var link_list: std.ArrayListUnmanaged(bpf.Object.Link) = .{};

        // If anything fails midway, destroy all previously successful attachments
        errdefer {
            for (link_list.items) |*l| l.deinit();
            link_list.deinit(allocator);
        }

        for (attachments) |attachment| {
            switch (attachment) {
                .perf => |config| {
                    const cpuCount = try std.Thread.getCpuCount();
                    std.log.info("Attaching perf_event at {} Hz across {} CPUs", .{ config.hz, cpuCount });

                    var attributes = std.os.linux.perf_event_attr{
                        .type = .SOFTWARE,
                        .sample_period_or_freq = config.hz,
                        .config = c.PERF_COUNT_SW_CPU_CLOCK,
                        .flags = .{ .freq = true, .mmap = true },
                    };

                    const program = try self.object.findProgram("sample_perf");

                    for (0..cpuCount) |i| {
                        const pfd: i64 = @bitCast(std.os.linux.perf_event_open(&attributes, -1, @intCast(i), -1, 0));
                        if (pfd == -1) return error.PerfEventOpenFailure;

                        const fd = @as(i32, @intCast(pfd));
                        errdefer std.posix.close(fd);

                        try link_list.append(allocator, try program.attachPerfEvent(fd));
                    }
                },
                .kprobe => |config| {
                    std.log.info("Attaching kprobe to '{s}'", .{config.name});
                    const program = try self.object.findProgram("sample_kprobe");
                    try link_list.append(allocator, try program.attachKProbe(false, config.name));
                },
                .tracepoint => |config| {
                    std.log.info("Attaching tracepoint to '{s}:{s}'", .{ config.category, config.name });
                    const program = try self.object.findProgram("sample_tracepoint");
                    try link_list.append(allocator, try program.attachTracepoint(config.category, config.name));
                },
            }
        }

        self.links = try link_list.toOwnedSlice(allocator);
    }

    /// Stop running by detaching the link
    pub fn stop(self: *ProfilerUnmanaged, allocator: std.mem.Allocator) void {
        if (self.links) |links| {
            for (links) |*link| {
                link.deinit();
            }

            allocator.free(links);
            self.links = null;
        }
    }
};
