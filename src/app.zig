// Main logic for our application
const std = @import("std");
const vaxis = @import("vaxis");
const c = @import("cimport.zig").c;
const bpf = @import("bpf.zig");

const InstructionPointer = @import("profile.zig").InstructionPointer;
const PID = @import("profile.zig").PID;
const UMapEntryUnmanaged = @import("umap.zig").UMapEntryUnmanaged;
const UMapCacheUnmanaged = @import("umap.zig").UMapCacheUnmanaged;
const UMapUnmanaged = @import("umap.zig").UMapUnmanaged;
const KMap = @import("kmap.zig").KMap;
const SymbolTrie = @import("symboltrie.zig").SymbolTrie;
const StackTrie = @import("stacktrie.zig").StackTrie;
const EventType = @import("profile.zig").EventType;
const EventTypeRaw = @import("profile.zig").EventTypeRaw;
const Program = @import("profile.zig").Program;
const ProfilerUnmanaged = @import("profile.zig").ProfilerUnmanaged;
const Interface = @import("tui.zig").Interface;
const ThreadSafe = @import("lock.zig").ThreadSafe;

/// ===================================================================================================================
/// Callback Contexts
/// ===================================================================================================================
const RingProfilerContext = struct {
    /// The starting timestamp of the current bin in nanoseconds
    binStartNanoseconds: ?u64,

    /// The duration of a bin in nanoseconds
    binDurationNanoseconds: u64,

    /// A reference to a ringbuffer containing stacktries, not owned by us
    ring: *StackTrieRing,

    /// The currently selected iptrie from the ring
    iptrieCurrent: *StackTrie,

    /// A cache to loaded umaps, to be shared between iptries to accelerate searches
    umapCache: UMapCacheUnmanaged,

    /// Initialize with a reference to an existing stack trie ring
    pub fn init(allocator: std.mem.Allocator, ring: *StackTrieRing) !RingProfilerContext {
        return .{
            .ring = ring,
            .iptrieCurrent = &ring.stacktries[0],
            .umapCache = try UMapCacheUnmanaged.init(allocator),
            .binStartNanoseconds = null,
            .binDurationNanoseconds = 100 * std.time.ns_per_ms,
        };
    }

    /// Clear and invalidate
    pub fn deinit(self: *RingProfilerContext, allocator: std.mem.Allocator) void {
        self.umapCache.deinit(allocator);

        // invalidate
        defer self.* = undefined;
    }

    pub fn callback(context: *RingProfilerContext, event: *const EventTypeRaw) void {
        const parsed = EventType.init(event);

        if (context.binStartNanoseconds) |*binStartNanoseconds| {
            while (parsed.timestamp >= binStartNanoseconds.* +| context.binDurationNanoseconds) {
                binStartNanoseconds.* += context.binDurationNanoseconds;

                if (context.ring.progressWriterHead()) |new| {
                    context.iptrieCurrent = new;
                    context.iptrieCurrent.reset();
                } else {
                    break;
                }
            }
        } else {
            // Populate if not yet defined
            context.binStartNanoseconds = parsed.timestamp;
        }

        // Cannot throw, so panic on error
        context.iptrieCurrent.add(parsed, &context.umapCache) catch {
            @panic("Could not add to stacktrie");
        };
    }
};

/// ===================================================================================================================
/// StackRingBuffer
/// ===================================================================================================================
/// Thread-Safe Ring Buffer, inefficient perhaps but easy to understand.
pub const StackTrieRing = struct {
    allocator: std.mem.Allocator,
    stacktries: []StackTrie,
    mutex: std.Thread.Mutex,

    // Currently written by ebpf program
    writerHead: usize,

    // Newest sample, eventually writerHead - 1, should be merged in symboltrie
    readerHead: usize,

    // Oldest sample, writerHead + 1, should be evicted from symboltrie
    readerTail: usize,

    /// Initialize the ring with an empty StackTrie list
    pub fn init(allocator: std.mem.Allocator, n: usize) !StackTrieRing {
        const stacktries = try allocator.alloc(StackTrie, n);
        errdefer allocator.free(stacktries);

        for (stacktries, 0..) |*stacktrie, i| {
            errdefer for (0..i) |j| stacktries[j].deinit();
            stacktrie.* = try StackTrie.init(allocator);
        }

        return StackTrieRing{
            .allocator = allocator,
            .stacktries = stacktries,
            .mutex = .{},
            .writerHead = 0,
            .readerHead = n - 1,
            .readerTail = 1,
        };
    }

    /// Atomic deinit + invalidate
    pub fn deinit(self: *StackTrieRing, allocator: std.mem.Allocator) void {
        self.mutex.lock();

        for (self.stacktries) |*stacktrie| {
            stacktrie.deinit();
        }

        allocator.free(self.stacktries);

        self.mutex.unlock();
        self.* = undefined;
    }

    // Returns the next head, or null if it would exceed the readerTail. If null, the eBPF program simply keeps
    // writing to the same "bucket", i.e. stacktrace.
    pub fn progressWriterHead(self: *StackTrieRing) ?*StackTrie {
        self.mutex.lock();
        defer self.mutex.unlock();

        const nextSlot = (self.writerHead + 1) % self.stacktries.len;

        // Always as close to readerTail as possible, but never overtake
        if (nextSlot == self.readerTail) {
            return null;
        }

        self.writerHead = nextSlot;
        return &self.stacktries[self.writerHead];
    }

    // Returns the next reader head, aka the newest stacktrie. Nominally, this should be 1 behind the writer head.
    // Merges to the symboltrie until null, in which case do nothing.
    pub fn peekReaderHead(self: *StackTrieRing) ?*StackTrie {
        self.mutex.lock();
        defer self.mutex.unlock();

        const nextSlot = (self.readerHead + 1) % self.stacktries.len;

        // Always as close to writerHead as possible, but never overtage
        if (nextSlot == self.writerHead) {
            return null;
        }

        return &self.stacktries[nextSlot];
    }

    // Pushes reader head one forward
    pub fn advanceReaderHead(self: *StackTrieRing) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const nextSlot = (self.readerHead + 1) % self.stacktries.len;
        self.readerHead = nextSlot;
    }

    // Returns the next tail,
    pub fn peekReaderTail(self: *StackTrieRing) ?*StackTrie {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Should be always 1 ahead of writer (thats the oldest), so if next is the slot beyond that null
        if (self.readerTail == (self.writerHead + 1) % self.stacktries.len) {
            return &self.stacktries[self.readerTail];
        }

        return null;
    }

    // Pushes reader tail one forward
    pub fn advanceReaderTail(self: *StackTrieRing) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const nextSlot = (self.readerTail + 1) % self.stacktries.len;
        self.readerTail = nextSlot;
    }
};

/// ===================================================================================================================
/// SymbolTrieList
/// ===================================================================================================================
pub const SymbolTrieList = struct {
    list: ThreadSafe([]*SymbolTrie),
    kmap: ?*KMap,

    pub fn init(allocator: std.mem.Allocator, kmap: ?*KMap, size: usize) !SymbolTrieList {
        const symboltrieSlice = try allocator.alloc(*SymbolTrie, size);
        errdefer allocator.free(symboltrieSlice);

        for (0..size) |i| {
            errdefer {
                for (0..i) |j| {
                    symboltrieSlice[j].deinit();
                    allocator.destroy(symboltrieSlice[j]);
                }
            }

            symboltrieSlice[i] = try allocator.create(SymbolTrie);
            errdefer allocator.destroy(symboltrieSlice[i]);

            symboltrieSlice[i].* = try SymbolTrie.init(allocator, kmap);
            errdefer symboltrieSlice[i].*.deinit();
        }

        const list = try allocator.create([]*SymbolTrie);
        errdefer allocator.destroy(list);
        list.* = symboltrieSlice;

        return .{
            .list = ThreadSafe([]*SymbolTrie).init(list),
            .kmap = kmap,
        };
    }

    pub fn deinit(self: *SymbolTrieList, allocator: std.mem.Allocator) void {
        {
            const list = self.list.lock();
            defer self.list.unlock();

            for (list.*) |symboltrie| {
                symboltrie.deinit();
                allocator.destroy(symboltrie);
            }

            allocator.free(list.*);
            allocator.destroy(list);
        }

        self.* = undefined;
    }
};

/// ===================================================================================================================
/// App
/// ===================================================================================================================
pub const RingProfiler = struct {
    allocator: std.mem.Allocator,

    /// Ringbuffer that contains stack tries
    ring: *StackTrieRing,

    /// Context for running our profiler
    context: *RingProfilerContext,

    /// eBPF profiler program
    profiler: ProfilerUnmanaged,

    /// Thread for handling eBPF callbacks
    bpfThread: ?std.Thread,

    /// Thread for handling tui interactions
    tuiThread: ?std.Thread,

    /// KMap for symboltries
    kmap: *KMap,

    /// SymbolTries we make available for drawing
    symbols: *SymbolTrieList,

    /// Should stop our threads
    shouldQuit: std.atomic.Value(bool),

    /// Our TUI
    interface: Interface,

    pub fn init(allocator: std.mem.Allocator, bins: usize) !RingProfiler {
        // init ringbuffer pointer
        const ring = try allocator.create(StackTrieRing);
        ring.* = try StackTrieRing.init(allocator, 16);
        errdefer ring.deinit(allocator);

        // init profiler context pointer
        const context = try allocator.create(RingProfilerContext);
        context.* = try RingProfilerContext.init(allocator, ring);
        errdefer context.deinit(allocator);

        // init profiler
        var profiler = try ProfilerUnmanaged.init(RingProfilerContext, RingProfilerContext.callback, allocator, context);
        errdefer profiler.deinit(allocator);

        // init kmap
        const kmap = try allocator.create(KMap);
        kmap.* = try KMap.init(allocator);
        errdefer kmap.deinit();

        // init symbol list
        const symbols = try allocator.create(SymbolTrieList);
        symbols.* = try SymbolTrieList.init(allocator, kmap, bins);
        errdefer symbols.deinit();

        // init tui
        var interface = try Interface.init(allocator, symbols);
        interface.missed = &profiler.globals.map.dropped_events;
        errdefer interface.deinit();

        return RingProfiler{
            .allocator = allocator,
            .ring = ring,
            .context = context,
            .profiler = profiler,
            .kmap = kmap,
            .symbols = symbols,
            .interface = interface,
            .bpfThread = null,
            .tuiThread = null,
            .shouldQuit = std.atomic.Value(bool).init(false),
        };
    }

    pub fn deinit(self: *RingProfiler) void {
        self.stop();

        self.symbols.deinit(self.allocator);
        self.allocator.destroy(self.symbols);

        self.kmap.deinit();
        self.allocator.destroy(self.kmap);

        self.profiler.deinit(self.allocator);

        self.context.deinit(self.allocator);
        self.allocator.destroy(self.context);

        self.ring.deinit(self.allocator);
        self.allocator.destroy(self.ring);
    }

    /// Start running the application
    fn start(self: *RingProfiler, rate: usize) !void {
        self.shouldQuit.store(false, .release);
        errdefer self.stop();

        if (self.bpfThread != null) return error.ThreadAlreadyRunning;
        self.bpfThread = try std.Thread.spawn(.{}, bpfWorker, .{ self, rate });

        if (self.tuiThread != null) return error.ThreadAlreadyRunning;
        self.tuiThread = try std.Thread.spawn(.{}, tuiWorker, .{self});
    }

    /// Stop the application from running by joining threads
    fn stop(self: *RingProfiler) void {
        self.shouldQuit.store(true, .release);

        if (self.bpfThread) |t| t.join();
        self.bpfThread = null;

        if (self.tuiThread) |t| t.join();
        self.tuiThread = null;
    }

    /// Worker thread, draining bpf events
    fn bpfWorker(self: *RingProfiler, rate: usize) void {
        self.profiler.start(self.allocator, rate) catch {
            @panic("Could not start profiler");
        };

        while (!self.shouldQuit.load(.acquire)) {
            while (true) {
                const count = self.profiler.ring.consume() catch break;
                if (count == 0) break;
            }

            std.Thread.sleep(5 * std.time.ns_per_ms);
        }

        self.profiler.stop(self.allocator);
    }

    /// Manages the tui
    fn tuiWorker(self: *RingProfiler) void {
        self.interface.start() catch {
            @panic("Could not start TUI");
        };

        self.shouldQuit.store(true, .release);
    }
};

/// ===================================================================================================================
/// Ring (--ring)
/// ===================================================================================================================
/// Sliding window. Streams results to TUI, evicts oldest slot when ring is full.
pub const RingApp = struct {
    app: RingProfiler,

    pub fn init(allocator: std.mem.Allocator) !RingApp {
        return .{
            .app = try RingProfiler.init(allocator, 1),
        };
    }

    pub fn deinit(self: *RingApp) void {
        self.app.deinit();
    }

    pub fn run(self: *RingApp, rate: usize, slot_ns: u64, ring_slots: usize) !void {
        // Reinitialize ring with requested size
        self.app.ring.deinit(self.app.allocator);
        self.app.ring.* = try StackTrieRing.init(self.app.allocator, ring_slots);
        self.app.context.ring = self.app.ring;
        self.app.context.iptrieCurrent = &self.app.ring.stacktries[0];

        self.app.context.binDurationNanoseconds = slot_ns;

        try self.app.start(rate);

        const merge_interval = 16 * std.time.ns_per_ms;

        while (!self.app.shouldQuit.load(.acquire)) {
            var shouldRedraw = false;
            if (self.app.ring.peekReaderTail()) |stack_trie| {
                const symbols = (self.app.symbols.list.lock().*)[0];
                defer self.app.symbols.list.unlock();

                try symbols.map(stack_trie.*, .evict);
                stack_trie.reset();

                self.app.ring.advanceReaderTail();

                shouldRedraw = true;
            }

            while (self.app.ring.peekReaderHead()) |stack_trie| {
                const symbols = self.app.symbols.list.lock().*[0];
                defer self.app.symbols.list.unlock();

                try symbols.map(stack_trie.*, .merge);

                self.app.ring.advanceReaderHead();

                shouldRedraw = true;
            }

            if (self.app.interface.loop) |*loop| {
                if (shouldRedraw) {
                    loop.postEvent(.{ .redraw = {} });
                }
            }

            std.Thread.sleep(merge_interval);
        }
    }
};

/// ===================================================================================================================
/// Aggregate (--aggregate)
/// ===================================================================================================================
/// Aggregate indefinitely. Streams results to TUI, never evicts.
pub const AggregateApp = struct {
    app: RingProfiler,

    pub fn init(allocator: std.mem.Allocator) !AggregateApp {
        return .{
            .app = try RingProfiler.init(allocator, 1),
        };
    }

    pub fn deinit(self: *AggregateApp) void {
        self.app.deinit();
    }

    pub fn run(self: *AggregateApp, rate: usize) !void {
        // Rotate the ring, but never evict old data
        self.app.context.binDurationNanoseconds = 50 * std.time.ns_per_ms;

        try self.app.start(rate);

        const merge_interval = 16 * std.time.ns_per_ms;

        while (!self.app.shouldQuit.load(.acquire)) {
            var shouldRedraw = false;

            while (self.app.ring.peekReaderHead()) |stack_trie| {
                const symbols = self.app.symbols.list.lock().*[0];
                defer self.app.symbols.list.unlock();

                try symbols.map(stack_trie.*, .merge);

                self.app.ring.advanceReaderHead();
                shouldRedraw = true;
            }

            while (self.app.ring.peekReaderTail()) |stack_trie| {
                stack_trie.reset();
                self.app.ring.advanceReaderTail();
            }

            if (self.app.interface.loop) |*loop| {
                if (shouldRedraw) {
                    loop.postEvent(.{ .redraw = {} });
                }
            }

            std.Thread.sleep(merge_interval);
        }
    }
};

/// ===================================================================================================================
/// Fixed (--fixed)
/// ===================================================================================================================
/// Fixed duration measurement. Profile, then display the result. No streaming.
pub const FixedApp = struct {
    app: RingProfiler,

    pub fn init(allocator: std.mem.Allocator, bins: usize) !FixedApp {
        return .{
            .app = try RingProfiler.init(allocator, bins),
        };
    }

    pub fn deinit(self: *FixedApp) void {
        self.app.deinit();
    }

    pub fn run(self: *FixedApp, rate: usize, timeout_ns: u64) !void {
        const binCount = blk: {
            const symbols = self.app.symbols.list.lock();
            defer self.app.symbols.list.unlock();
            break :blk symbols.len;
        };

        if (binCount > 1) {
            const bin_ns = timeout_ns / binCount;

            self.app.ring.deinit(self.app.allocator);
            self.app.ring.* = try StackTrieRing.init(self.app.allocator, binCount);
            self.app.context.ring = self.app.ring;
            self.app.context.iptrieCurrent = &self.app.ring.stacktries[0];
            self.app.context.binDurationNanoseconds = bin_ns;

            // Neuter the ring protocol so progressWriterHead never blocks.
            // TODO: probably make a thing that just uses a list rather than the existing ring
            self.app.ring.writerHead = 0;
            self.app.ring.readerHead = 0;
            self.app.ring.readerTail = 0;

            try self.app.profiler.start(self.app.allocator, rate);
            defer self.app.profiler.stop(self.app.allocator);

            var timer = try std.time.Timer.start();

            while (timer.read() < timeout_ns) {
                const count = try self.app.profiler.ring.consume();

                if (count == 0) {
                    try self.app.profiler.ring.poll(10);
                }
            }

            // Map ring slot i -> symbol trie i
            for (0..binCount) |i| {
                const symbols = self.app.symbols.list.lock();
                defer self.app.symbols.list.unlock();
                if (self.app.ring.stacktries[i].nodes.items[StackTrie.RootId].hitCount > 0) {
                    try (symbols.*)[i].map(self.app.ring.stacktries[i], .merge);
                }
            }
        } else {
            self.app.context.binDurationNanoseconds = std.math.maxInt(u64);

            try self.app.profiler.start(self.app.allocator, rate);
            defer self.app.profiler.stop(self.app.allocator);

            var timer = try std.time.Timer.start();
            while (timer.read() < timeout_ns) {
                const count = try self.app.profiler.ring.consume();
                if (count == 0) {
                    try self.app.profiler.ring.poll(10);
                }
            }

            {
                const symbols = self.app.symbols.list.lock().*[0];
                defer self.app.symbols.list.unlock();
                try symbols.map(self.app.ring.stacktries[0], .merge);
            }
        }

        try self.app.interface.start();
    }
};

/// ===================================================================================================================
/// File (--file)
/// ===================================================================================================================
/// From a collapsed file
pub const FileApp = struct {
    pub fn run(allocator: std.mem.Allocator, reader: *std.Io.Reader) !void {
        const symbols = try allocator.create(SymbolTrieList);
        defer allocator.destroy(symbols);

        // Create a symboltrie with 1 slot and no kmap (no kernel symbols need be resolved)
        symbols.* = try SymbolTrieList.init(allocator, null, 1);
        defer symbols.deinit(allocator);

        const list = symbols.list.lock();
        list.*[0].deinit();
        list.*[0].* = try SymbolTrie.initCollapsed(allocator, reader);
        symbols.list.unlock();

        var interface = try Interface.init(allocator, symbols);
        defer interface.deinit();
        try interface.start();
    }
};

/// ===================================================================================================================
/// Stdin (-)
/// ===================================================================================================================
/// From a perf script
pub const StdinApp = struct {
    pub fn run(allocator: std.mem.Allocator, reader: *std.Io.Reader) !void {
        const symbols = try allocator.create(SymbolTrieList);
        defer allocator.destroy(symbols);
        symbols.* = try SymbolTrieList.init(allocator, null, 1);
        defer symbols.deinit(allocator);

        const list = symbols.list.lock();
        list.*[0].deinit();
        list.*[0].* = try SymbolTrie.initPerfScript(allocator, reader);
        symbols.list.unlock();

        var interface = try Interface.init(allocator, symbols);
        defer interface.deinit();
        try interface.start();
    }
};
