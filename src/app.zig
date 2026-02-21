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
const KMapUnmanaged = @import("kmap.zig").KMapUnmanaged;
const SymbolTrie = @import("symboltrie.zig").SymbolTrie;
const StackTrieUnmanaged = @import("stacktrie.zig").StackTrieUnmanaged;
const EventType = @import("profile.zig").EventType;
const EventTypeRaw = @import("profile.zig").EventTypeRaw;
const Program = @import("profile.zig").Program;
const ProfilerUnmanaged = @import("profile.zig").ProfilerUnmanaged;
const Interface = @import("tui.zig").Interface;
const ThreadSafe = @import("lock.zig").ThreadSafe;

/// ===================================================================================================================
/// Callback Contexts
/// ===================================================================================================================
/// A profiler backed by a ringbuffer of stack tries. The ringbuffer implementation effectively generalizes a
/// triple buffer useful for drawing while measuring.
const RingProfilerContext = struct {
    /// The starting timestamp of the current bin in nanoseconds
    binStartNanoseconds: ?u64,

    /// The duration of a bin in nanoseconds
    binDurationNanoseconds: u64,

    /// A reference to a ringbuffer containing stacktries
    stacktries: *StackTrieRing,

    /// The currently selected iptrie from the ring
    iptrieCurrent: *StackTrieUnmanaged,

    /// A cache to loaded umaps, to be shared between iptries to accelerate searches
    umapCache: UMapCacheUnmanaged,

    /// We manage an allocator due to the callback
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, bins: usize) !RingProfilerContext {
        // init ringbuffer pointer
        const stacktries = try allocator.create(StackTrieRing);
        stacktries.* = try StackTrieRing.init(allocator, bins);
        errdefer stacktries.deinit(allocator);

        return .{
            .stacktries = stacktries,
            .iptrieCurrent = &stacktries.stacktries[0],
            .umapCache = try UMapCacheUnmanaged.init(allocator),
            .binStartNanoseconds = null,
            .binDurationNanoseconds = 100 * std.time.ns_per_ms,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *RingProfilerContext) void {
        self.umapCache.deinit(self.allocator);

        self.stacktries.deinit(self.allocator);
        self.allocator.destroy(self.stacktries);

        // invalidate
        defer self.* = undefined;
    }

    pub fn callback(context: *RingProfilerContext, event: *const EventTypeRaw) void {
        const parsed = EventType.init(event);

        if (context.binStartNanoseconds) |*binStartNanoseconds| {
            while (parsed.timestamp >= binStartNanoseconds.* +| context.binDurationNanoseconds) {
                binStartNanoseconds.* += context.binDurationNanoseconds;

                if (context.stacktries.progressWriterHead()) |new| {
                    context.iptrieCurrent = new;
                    context.iptrieCurrent.reset(context.allocator);
                } else {
                    break;
                }
            }
        } else {
            // Populate if not yet defined, aka the first measurement
            context.binStartNanoseconds = parsed.timestamp;
        }

        // Cannot throw, so panic on error
        context.iptrieCurrent.add(context.allocator, parsed, &context.umapCache) catch {
            @panic("Could not add to stacktrie");
        };
    }
};

/// A context for a fixed measurement. In the case of the fixed measurement, we may precompute the number of
/// stacktries required.
const FixedContext = struct {
    /// The starting timestamp of the current bin in nanoseconds
    binStartNanoseconds: ?u64,

    /// The duration of a bin in nanoseconds
    binDurationNanoseconds: u64,

    /// A list of stacktries
    stacktries: []StackTrieUnmanaged,

    /// The index of the current stacktrie
    binCurrent: usize,

    /// A cache to loaded umaps, to be shared between iptries to accelerate searches
    umapCache: UMapCacheUnmanaged,

    /// We manage an allocator due to the callback, doesn't play nice with unmanaged design
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, bins: usize) !FixedContext {
        const stacktries = try allocator.alloc(StackTrieUnmanaged, bins);
        errdefer allocator.free(stacktries);

        for (stacktries, 0..) |*st, i| {
            errdefer for (0..i) |j| stacktries[j].deinit(allocator);
            st.* = try StackTrieUnmanaged.init(allocator);
        }

        return .{
            .stacktries = stacktries,
            .binCurrent = 0,
            .binStartNanoseconds = null,
            .binDurationNanoseconds = std.math.maxInt(u64),
            .umapCache = try UMapCacheUnmanaged.init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *FixedContext) void {
        self.umapCache.deinit(self.allocator);
        for (self.stacktries) |*st| st.deinit(self.allocator);
        self.allocator.free(self.stacktries);

        // invalidate
        self.* = undefined;
    }

    pub fn callback(self: *FixedContext, event: *const EventTypeRaw) void {
        const parsed = EventType.init(event);

        if (self.binStartNanoseconds) |*start| {
            while (parsed.timestamp >= start.* +| self.binDurationNanoseconds) {
                start.* += self.binDurationNanoseconds;
                if (self.binCurrent + 1 < self.stacktries.len) {
                    self.binCurrent += 1;
                } else break;
            }
        } else {
            self.binStartNanoseconds = parsed.timestamp;
        }

        // Cannot throw, so panic on error
        self.stacktries[self.binCurrent].add(self.allocator, parsed, &self.umapCache) catch {
            @panic("Could not add to stacktrie");
        };
    }
};

/// ===================================================================================================================
/// StackRingBuffer
/// ===================================================================================================================
/// Thread-Safe Ring Buffer, inefficient perhaps but easy to understand.
pub const StackTrieRing = struct {
    stacktries: []StackTrieUnmanaged,
    mutex: std.Thread.Mutex,

    // Currently written by ebpf program
    writerHead: usize,

    // Newest sample, eventually writerHead - 1, should be merged in symboltrie
    readerHead: usize,

    // Oldest sample, writerHead + 1, should be evicted from symboltrie
    readerTail: usize,

    /// Initialize the ring with an empty StackTrieUnmanaged list
    pub fn init(allocator: std.mem.Allocator, n: usize) !StackTrieRing {
        const stacktries = try allocator.alloc(StackTrieUnmanaged, n);
        errdefer allocator.free(stacktries);

        for (stacktries, 0..) |*stacktrie, i| {
            errdefer for (0..i) |j| stacktries[j].deinit(allocator);
            stacktrie.* = try StackTrieUnmanaged.init(allocator);
        }

        return StackTrieRing{
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
            stacktrie.deinit(allocator);
        }

        allocator.free(self.stacktries);

        self.mutex.unlock();
        self.* = undefined;
    }

    // Returns the next head, or null if it would exceed the readerTail. If null, the eBPF program simply keeps
    // writing to the same "bucket", i.e. stacktrace.
    pub fn progressWriterHead(self: *StackTrieRing) ?*StackTrieUnmanaged {
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
    pub fn peekReaderHead(self: *StackTrieRing) ?*StackTrieUnmanaged {
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
    pub fn peekReaderTail(self: *StackTrieRing) ?*StackTrieUnmanaged {
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
    kmap: ?*KMapUnmanaged,

    pub fn init(allocator: std.mem.Allocator, kmap: ?*KMapUnmanaged, size: usize) !SymbolTrieList {
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

    pub fn mapAtomic(self: *SymbolTrieList, stacktrie: StackTrieUnmanaged, mode: SymbolTrie.MapMode) !void {
        const symbols = (self.list.lock().*)[0];
        defer self.list.unlock();
        try symbols.map(stacktrie, mode);
    }

    pub fn lock(self: *SymbolTrieList) !void {
        _ = self.list.lock();
    }

    pub fn mapUnsafe(self: *SymbolTrieList, stacktrie: StackTrieUnmanaged, mode: SymbolTrie.MapMode) !void {
        try (self.list.data.*)[0].map(stacktrie, mode);
    }

    pub fn unlock(self: *SymbolTrieList) void {
        defer self.list.unlock();
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
/// Profiler backed by generic context
pub fn ProfilerApp(ContextType: type) type {
    return struct {
        allocator: std.mem.Allocator,

        /// eBPF profiler program
        profiler: ProfilerUnmanaged,

        /// Thread for handling eBPF callbacks
        bpfThread: ?std.Thread,

        /// Thread for handling tui interactions
        tuiThread: ?std.Thread,

        /// KMap for symboltries
        kmap: *KMapUnmanaged,

        /// KMap allocator, using an arena allocator means way faster deinit and init
        kmapArena: std.heap.ArenaAllocator,

        /// SymbolTries we make available for drawing
        symbols: *SymbolTrieList,

        /// Should stop our threads
        shouldQuit: std.atomic.Value(bool),

        /// Our TUI
        interface: Interface,

        /// Context
        context: *ContextType,

        pub fn init(allocator: std.mem.Allocator, context: *ContextType, binsSymbolTrie: usize) !@This() {
            // init profiler
            var profiler = try ProfilerUnmanaged.init(ContextType, ContextType.callback, allocator, context);
            errdefer profiler.deinit(allocator);

            // init kmapArena
            var kmapArena = std.heap.ArenaAllocator.init(allocator);
            errdefer kmapArena.deinit();

            // init kmap
            const kmap = try allocator.create(KMapUnmanaged);
            kmap.* = try KMapUnmanaged.init(kmapArena.allocator());
            errdefer kmap.deinit(kmapArena.allocator());

            // init symbol list
            const symbols = try allocator.create(SymbolTrieList);
            symbols.* = try SymbolTrieList.init(allocator, kmap, binsSymbolTrie);
            errdefer symbols.deinit();

            // init tui with the symbols
            var interface = try Interface.init(allocator, symbols);
            interface.missed = &profiler.globals.map.dropped_events;
            errdefer interface.deinit();

            return .{
                .allocator = allocator,
                .context = context,
                .profiler = profiler,
                .kmap = kmap,
                .kmapArena = kmapArena,
                .symbols = symbols,
                .interface = interface,
                .bpfThread = null,
                .tuiThread = null,
                .shouldQuit = std.atomic.Value(bool).init(false),
            };
        }

        pub fn deinit(self: *@This()) void {
            self.stop();

            self.symbols.deinit(self.allocator);
            self.allocator.destroy(self.symbols);

            self.kmap.deinit(self.kmapArena.allocator());
            self.allocator.destroy(self.kmap);

            self.kmapArena.deinit();

            self.profiler.deinit(self.allocator);
        }

        /// Start running the application
        fn start(self: *@This(), rate: usize) !void {
            self.shouldQuit.store(false, .release);
            errdefer self.stop();

            if (self.bpfThread != null) return error.ThreadAlreadyRunning;
            self.bpfThread = try std.Thread.spawn(.{}, bpfWorker, .{ self, rate });

            if (self.tuiThread != null) return error.ThreadAlreadyRunning;
            self.tuiThread = try std.Thread.spawn(.{}, tuiWorker, .{self});
        }

        /// Stop the application from running by joining threads
        fn stop(self: *@This()) void {
            self.shouldQuit.store(true, .release);

            if (self.bpfThread) |t| t.join();
            self.bpfThread = null;

            if (self.tuiThread) |t| t.join();
            self.tuiThread = null;
        }

        /// Worker thread, draining bpf events
        fn bpfWorker(self: *@This(), rate: usize) void {
            self.profiler.start(self.allocator, rate) catch {
                @panic("Could not start profiler");
            };

            const interval = std.time.ns_per_s / rate;
            while (!self.shouldQuit.load(.acquire)) {
                var timer = std.time.Timer.start() catch unreachable;

                var count: usize = std.math.maxInt(usize);
                while (count != 0) {
                    count = self.profiler.ring.consume() catch break;
                }

                const elapsed = timer.read();
                if (elapsed < interval) {
                    std.Thread.sleep(interval - elapsed);
                }
            }

            self.profiler.stop(self.allocator);
        }

        /// Manages the tui
        fn tuiWorker(self: *@This()) void {
            self.interface.start() catch {
                @panic("Could not start TUI");
            };

            self.shouldQuit.store(true, .release);
        }
    };
}

/// ===================================================================================================================
/// Ring (--ring)
/// ===================================================================================================================
/// Sliding window. Streams results to TUI, evicts oldest slot when ring is full.
pub const RingApp = struct {
    allocator: std.mem.Allocator,
    context: *RingProfilerContext,
    app: ProfilerApp(RingProfilerContext),

    pub fn init(allocator: std.mem.Allocator, binsStackTrie: usize) !RingApp {
        const context = try allocator.create(RingProfilerContext);
        errdefer allocator.destroy(context);
        context.* = try RingProfilerContext.init(allocator, binsStackTrie);
        errdefer context.deinit();

        return .{
            .allocator = allocator,
            .context = context,
            .app = try ProfilerApp(RingProfilerContext).init(allocator, context, 1),
        };
    }

    pub fn deinit(self: *RingApp) void {
        self.app.deinit();
        self.context.deinit();
        self.allocator.destroy(self.context);
    }

    pub fn run(self: *RingApp, rate: usize, slotNanoseconds: u64) !void {
        self.app.context.binDurationNanoseconds = slotNanoseconds;

        try self.app.start(rate);

        const interval = slotNanoseconds;
        while (!self.app.shouldQuit.load(.acquire)) {
            var timer = try std.time.Timer.start();
            {
                var shouldRedraw = false;

                // We NEVER want to draw the intermediate state between evict and merge...
                try self.app.symbols.lock();
                defer self.app.symbols.unlock();

                if (self.app.context.stacktries.peekReaderTail()) |stack_trie| {
                    // Remove all stale stacktries from the symboltrie
                    try self.app.symbols.mapUnsafe(stack_trie.*, .evict);

                    // Reset the stacktrie so it can be reused
                    stack_trie.reset(self.app.allocator);
                    self.app.context.stacktries.advanceReaderTail();

                    shouldRedraw = true;
                }

                while (self.app.context.stacktries.peekReaderHead()) |stack_trie| {
                    // Merge in all the fresh stacktries
                    try self.app.symbols.mapUnsafe(stack_trie.*, .merge);

                    self.app.context.stacktries.advanceReaderHead();

                    shouldRedraw = true;
                }

                if (shouldRedraw) {
                    if (self.app.interface.loop) |*loop| {
                        loop.postEvent(.{ .redraw = {} });
                    }
                }
            }

            const elapsed = timer.read();
            if (elapsed < interval) {
                std.Thread.sleep(interval - elapsed);
            }
        }
    }
};

/// ===================================================================================================================
/// Aggregate (--aggregate)
/// ===================================================================================================================
/// Aggregate indefinitely. Streams results to TUI, never evicts.
pub const AggregateApp = struct {
    allocator: std.mem.Allocator,
    context: *RingProfilerContext,
    app: ProfilerApp(RingProfilerContext),

    pub fn init(allocator: std.mem.Allocator) !AggregateApp {
        const context = try allocator.create(RingProfilerContext);
        errdefer allocator.destroy(context);
        context.* = try RingProfilerContext.init(allocator, 4);
        errdefer context.deinit();

        return .{
            .allocator = allocator,
            .context = context,
            .app = try ProfilerApp(RingProfilerContext).init(allocator, context, 1),
        };
    }

    pub fn deinit(self: *AggregateApp) void {
        self.app.deinit();
        self.context.deinit();
        self.allocator.destroy(self.context);
    }

    pub fn run(self: *AggregateApp, rate: usize) !void {
        self.app.context.binDurationNanoseconds = 50 * std.time.ns_per_ms;
        try self.app.start(rate);

        while (!self.app.shouldQuit.load(.acquire)) {
            var shouldRedraw = false;

            while (self.app.context.stacktries.peekReaderTail()) |stack_trie| {
                // Remove all stale stacktries from the symboltrie
                stack_trie.reset(self.app.allocator);
                self.app.context.stacktries.advanceReaderTail();
            }

            while (self.app.context.stacktries.peekReaderHead()) |stack_trie| {
                // Merge in all the fresh stacktries
                try self.app.symbols.mapAtomic(stack_trie.*, .merge);

                self.app.context.stacktries.advanceReaderHead();

                shouldRedraw = true;
            }

            if (shouldRedraw) {
                if (self.app.interface.loop) |*loop| {
                    loop.postEvent(.{ .redraw = {} });
                }
            }

            std.Thread.sleep(16 * std.time.ns_per_ms);
        }
    }
};

/// ===================================================================================================================
/// Fixed (--fixed)
/// ===================================================================================================================
/// Fixed duration measurement. Profile, then display the result. No streaming.
/// TODO: Doing this required a bit of a hack with the ProfilerApp. Probably we want to move away from the current
/// design where the context is generic as its kind of confusing. For now I don't care about this.
pub const FixedApp = struct {
    allocator: std.mem.Allocator,
    context: *FixedContext,
    app: ProfilerApp(FixedContext),

    pub fn init(allocator: std.mem.Allocator, binsStackTrie: usize) !FixedApp {
        const bins = @max(binsStackTrie, 1);
        const context = try allocator.create(FixedContext);
        errdefer allocator.destroy(context);
        context.* = try FixedContext.init(allocator, bins);
        errdefer context.deinit();

        return .{
            .allocator = allocator,
            .context = context,
            .app = try ProfilerApp(FixedContext).init(allocator, context, bins),
        };
    }

    pub fn deinit(self: *FixedApp) void {
        self.app.deinit();
        self.context.deinit();
        self.allocator.destroy(self.context);
    }

    pub fn run(self: *FixedApp, rate: usize, timeout_ns: u64) !void {
        const binCount = self.context.stacktries.len;

        if (binCount > 1) {
            self.context.binDurationNanoseconds = timeout_ns / binCount;
        } else {
            self.context.binDurationNanoseconds = std.math.maxInt(u64);
        }

        try self.app.profiler.start(self.allocator, rate);
        defer self.app.profiler.stop(self.allocator);

        var timer = try std.time.Timer.start();
        while (timer.read() < timeout_ns) {
            const count = try self.app.profiler.ring.consume();
            if (count == 0) {
                try self.app.profiler.ring.poll(10);
            }
        }

        {
            const list = self.app.symbols.list.lock();
            defer self.app.symbols.list.unlock();
            for (0..binCount) |i| {
                if (self.context.stacktries[i].nodes.items[StackTrieUnmanaged.RootId].hitCount > 0) {
                    try (list.*)[i].map(self.context.stacktries[i], .merge);
                }
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
