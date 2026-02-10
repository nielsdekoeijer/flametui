const std = @import("std");
const bpf = @import("bpf.zig");
const c = @import("cimport.zig").c;

pub const Program = @import("profile_streaming");

/// ===================================================================================================================
/// Helpers
/// ===================================================================================================================
/// The event type from bpf
pub const EventTypeRaw = u64;

/// Our parsed view over the raw data, note we dont clone for efficiencies sake
pub const EventType = struct {
    pid: u64,
    kips: []const u64,
    uips: []const u64,

    // We parse from a raw pointer
    pub fn init(raw: *const EventTypeRaw) EventType {
        const ev = @as([*]const u64, @ptrCast(raw));
        const us = ev[1] / 8;
        const ks = ev[2] / 8;

        const event = EventType{
            .pid = ev[0],
            .uips = ev[3 .. 3 + us],
            .kips = ev[3 + us .. 3 + us + ks],
        };

        return event;
    }
};

/// Name of the function in our bpf program
const ProfileFunctionName = "do_sample";

/// ===================================================================================================================
/// Wrappers
/// ===================================================================================================================
/// Wrapper around our profiling ebpf program
pub const Profiler = struct {
    allocator: std.mem.Allocator,
    bytecode: []align(8) const u8,
    object: bpf.Object,
    links: []bpf.Object.Link,
    ring: bpf.Object.RingBuffer,
    missed: *u64,

    pub fn init(
        comptime ContextType: type,
        comptime handler: *const fn (*ContextType, *const EventTypeRaw) void,
        allocator: std.mem.Allocator,
        context: *ContextType,
    ) anyerror!Profiler {

        // Configure logging
        bpf.setupLoggerBackend(.zig);

        // Load our embedded code into an byte array with 8 byte alignment
        const code = try bpf.loadProgramAligned(allocator, Program.bytecode);
        errdefer allocator.free(code);

        // Use my bpf "library" to wrap the Object
        var object = try bpf.Object.init(code);
        errdefer object.free();

        // Create links
        const cpuCount = try std.Thread.getCpuCount();
        const links = try allocator.alloc(bpf.Object.Link, cpuCount);
        errdefer {
            for (links) |*link| {
                link.free();
            }
        }

        // Create ringbuffer
        const ring = try object.findRingBuffer(
            ContextType,
            EventTypeRaw,
            handler,
            context,
            "events",
        );

        // Global from the program
        const missed = try object.getGlobalSectionPointer(u64);

        return Profiler{
            .allocator = allocator,
            .bytecode = code,
            .object = object,
            .links = links,
            .ring = ring,
            .missed = missed,
        };
    }

    pub fn start(self: Profiler, rate: usize) !void {
        var attributes = std.os.linux.perf_event_attr{
            .type = .SOFTWARE,
            .sample_period_or_freq = rate,
            .config = c.PERF_COUNT_SW_CPU_CLOCK,
            .flags = .{
                .freq = true,
                .mmap = true,
            },
        };

        const program = try self.object.findProgram(ProfileFunctionName);

        // Attach programs to each cpu
        for (0..self.links.len) |i| {
            const fd = blk: {
                const pfd: i64 = @bitCast(std.os.linux.perf_event_open(
                    &attributes,
                    -1,
                    @intCast(i),
                    -1,
                    0,
                ));

                if (pfd == -1) {
                    return error.PerfEventOpenFailure;
                }

                break :blk @as(i32, @intCast(pfd));
            };

            self.links[i] = try program.attachPerfEvent(fd);
        }
    }

    pub fn stop(self: Profiler) void {
        defer {
            for (self.links) |*link| {
                link.free();
            }
        }
    }

    pub fn run(self: Profiler, rate: usize, nanoseconds: u64) anyerror!void {
        try self.start(rate);

        // Run
        var timer = try std.time.Timer.start();

        while (timer.read() < nanoseconds) {
            const count = try self.ring.consume();

            if (count == 0) {
                try self.ring.poll(10);
            }
        }
    }

    pub fn free(self: *Profiler) void {
        self.allocator.free(self.bytecode);
        self.object.free();
        for (self.links) |*link| {
            link.free();
        }

        self.ring.free();
    }
};
