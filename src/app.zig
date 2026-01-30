// Main logic for our application
const std = @import("std");
const vaxis = @import("vaxis");
const c = @import("cimport.zig").c;
const bpf = @import("bpf.zig");

const InstructionPointer = @import("typesystem.zig").InstructionPointer;
const PID = @import("typesystem.zig").PID;
const UMapEntry = @import("umap.zig").UMapEntry;
const UMapCache = @import("umap.zig").UMapCache;
const UMapUnmanaged = @import("umap.zig").UMapUnmanaged;
const KMapUnmanaged = @import("kmap.zig").KMapUnmanaged;
const SymbolTrie = @import("symboltrie.zig").SymbolTrie;
const StackTrie = @import("stacktrie.zig").StackTrie;
const EventType = @import("profile.zig").EventType;
const EventTypeRaw = @import("profile.zig").EventTypeRaw;
const Program = @import("profile.zig").Program;
const Interface = @import("tui.zig").Interface;

/// ===================================================================================================================
/// App
/// ===================================================================================================================
pub const App = struct {
    allocator: std.mem.Allocator,
    code: []const u8,
    object: bpf.Object,
    links: []bpf.Object.Link,
    ring: bpf.Object.RingBufferMap,
    missed: *u64,
    iptrie: *StackTrie,

    // Invoked on polling our ebpf stack ringbuffer
    pub fn stackRingCallback(iptrie: *StackTrie, event: *const EventTypeRaw) void {
        const parsed = EventType.init(event);
        iptrie.add(parsed) catch @panic("failure to add to iptrie in callback");
    }

    pub fn init(allocator: std.mem.Allocator) anyerror!App {
        // disable logging
        try bpf.setupLoggerBackend(.zig);

        // load our embedded code into an byte array with 8 byte alignment
        const code = try bpf.loadProgramAligned(allocator, Program.bytecode);
        errdefer allocator.free(code);
        const object = try bpf.Object.load(code);
        errdefer object.free();

        // create links structure
        const cpuCount = try std.Thread.getCpuCount();
        const links = try allocator.alloc(bpf.Object.Link, cpuCount);
        for (links) |*link| link.internal = null;
        errdefer {
            for (links) |*link| {
                link.free();
            }
        }

        // StackTrie
        const iptrie = try allocator.create(StackTrie);
        iptrie.* = try StackTrie.init(allocator);

        // create event ring buffer
        const ring = try object.attachRingBufferMapCallback(StackTrie, EventTypeRaw, stackRingCallback, iptrie, "events");

        // grab global counters
        const missed = try object.getGlobals(u64);

        // store
        return App{
            .allocator = allocator,
            .code = code,
            .object = object,
            .links = links,
            .ring = ring,
            .missed = missed,
            .iptrie = iptrie,
        };
    }

    pub fn free(self: *App) void {
        self.allocator.free(self.code);
        self.object.free();
        for (self.links) |*link| {
            link.free();
        }

        self.iptrie.free();
        self.allocator.destroy(self.iptrie);
    }

    pub fn run(self: App, rate: usize, nanoseconds: u64) anyerror!void {
        // Specify our perf events
        var attributes = std.os.linux.perf_event_attr{
            .type = .SOFTWARE,
            .sample_period_or_freq = rate,
            .config = c.PERF_COUNT_SW_CPU_CLOCK,
            .flags = .{
                .freq = true,
                .mmap = true,
            },
        };

        // Attach programs to each cpu
        for (0..self.links.len) |i| {
            self.links[i] = try self.object.attachProgramPerfEventByName("do_sample", i, &attributes);
        }
        defer {
            for (self.links) |*link| {
                link.free();
            }
        }

        // Run
        var timer = try std.time.Timer.start();
        while (timer.read() < nanoseconds) {
            try self.ring.poll(1);
            std.atomic.spinLoopHint();
        }

        var symboltrie = try SymbolTrie.init(self.allocator);
        try symboltrie.add(self.iptrie.*);
        try symboltrie.add(self.iptrie.*);

        // Report how many we missed, reset it
        self.missed.* = 0;

        var interface = try Interface.init(self.allocator);
        interface.populate(&symboltrie);
        try interface.start();
    }
};
