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
    context: *Context,

    const Context = struct { iptrie: *StackTrie, umapCache: *UMapCache };

    // Invoked on polling our ebpf stack ringbuffer
    pub fn stackRingCallback(context: *Context, event: *const EventTypeRaw) void {
        const parsed = EventType.init(event);
        context.iptrie.add(
            parsed,
            context.umapCache,
        ) catch @panic("failure to add to iptrie in callback");
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

        const umapCache = try allocator.create(UMapCache);
        umapCache.* = try UMapCache.init(allocator);

        const context = try allocator.create(Context);
        context.iptrie = iptrie;
        context.umapCache = umapCache;

        // create event ring buffer
        const ring = try object.attachRingBufferMapCallback(
            Context,
            EventTypeRaw,
            stackRingCallback,
            context,
            "events",
        );

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
            .context = context,
        };
    }

    pub fn free(self: *App) void {
        self.allocator.free(self.code);
        self.object.free();
        for (self.links) |*link| {
            link.free();
        }

        self.context.iptrie.free();
        self.allocator.destroy(self.context.iptrie);

        self.context.umapCache.deinit();
        self.allocator.destroy(self.context.umapCache);
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
            const count = try self.ring.consume();

            if (count == 0) {
                try self.ring.poll(10);
            }
        }

        var symboltrie = try SymbolTrie.init(self.allocator);
        try symboltrie.add(self.context.iptrie.*);

        // Report how many we missed, reset it
        self.missed.* = 0;

        var interface = try Interface.init(self.allocator);
        interface.populate(&symboltrie);
        try interface.start();
    }
};
