// Main logic for our application
const std = @import("std");
const vaxis = @import("vaxis");
const c = @import("cimport.zig").c;
const bpf = @import("bpf.zig");

const InstructionPointer = @import("profile.zig").InstructionPointer;
const PID = @import("profile.zig").PID;
const UMapEntry = @import("umap.zig").UMapEntry;
const UMapCache = @import("umap.zig").UMapCache;
const UMapUnmanaged = @import("umap.zig").UMapUnmanaged;
const KMapUnmanaged = @import("kmap.zig").KMapUnmanaged;
const SymbolTrie = @import("symboltrie.zig").SymbolTrie;
const StackTrie = @import("stacktrie.zig").StackTrie;
const EventType = @import("profile.zig").EventType;
const EventTypeRaw = @import("profile.zig").EventTypeRaw;
const Program = @import("profile.zig").Program;
const Profiler = @import("profile.zig").Profiler;
const Interface = @import("tui.zig").Interface;
const ThreadSafe = @import("lock.zig").ThreadSafe;

/// ===================================================================================================================
/// Callbacks
/// ===================================================================================================================
/// Profiler ringbuffer callback
const ProfilerContext = struct {
    timestamp: i128,
    timeout: u64,
    iptrie: *StackTrie,
    umapCache: UMapCache,
    ring: *StackTrieRing,

    pub fn callback(context: *ProfilerContext, event: *const EventTypeRaw) void {
        const now = std.time.nanoTimestamp();

        if (now - context.timestamp > context.timeout) {
            if (context.ring.progressWriterHead()) |new| {
                context.iptrie = new;
                context.iptrie.reset();
            }

            context.timestamp = now;
        }

        const parsed = EventType.init(event);
        context.iptrie.add(parsed, &context.umapCache) catch {
            @panic("Could not add to stacktrie");
        };
    }
};

/// ===================================================================================================================
/// RingBuffer
/// ===================================================================================================================
/// Thread-Safe Ring Buffer, inefficient but easy to understand
pub const StackTrieRing = struct {
    allocator: std.mem.Allocator,
    buffer: []StackTrie,
    mutex: std.Thread.Mutex,

    // Currently written by ebpf program
    writerHead: usize,

    // Newest sample, writerHead - 1, should be merged in symboltrie
    readerHead: usize,

    // Oldest sample, writerHead + 1, should be evicted in symboltrie
    readerTail: usize,

    /// Initialize the ring with allocated, empty StackTries
    pub fn init(allocator: std.mem.Allocator, n: usize) !StackTrieRing {
        const buffer = try allocator.alloc(StackTrie, n);
        for (buffer) |*item| {
            item.* = try StackTrie.init(allocator);
        }

        return StackTrieRing{
            .allocator = allocator,
            .buffer = buffer,
            .mutex = .{},
            .writerHead = 0,
            .readerHead = n - 1,
            .readerTail = 1,
        };
    }

    // Returns the next head, or null if it would exceed the readerTail. If null, the eBPF program simply keeps
    // writing to the same "bucket", i.e. stacktrace. Assumptions about time become more dodgy, but things keep working.
    pub fn progressWriterHead(self: *StackTrieRing) ?*StackTrie {
        self.mutex.lock();
        defer self.mutex.unlock();

        const nextSlot = (self.writerHead + 1) % self.buffer.len;

        // Always as close to readerTail as possible, but never overtake
        if (nextSlot == self.readerTail) {
            return null;
        }

        self.writerHead = nextSlot;
        std.log.info(
            "Progressing writer head. Reader head: {}, Reader tail: {}, Writer head: {}",
            .{ self.readerHead, self.readerTail, self.writerHead },
        );
        return &self.buffer[self.writerHead];
    }

    // Returns the next reader head, aka the newest stacktrie. Nominally, this should be 1 behind the writer head.
    // Merges to the symboltrie until null, in which case do nothing.
    pub fn peekReaderHead(self: *StackTrieRing) ?*StackTrie {
        self.mutex.lock();
        defer self.mutex.unlock();

        const nextSlot = (self.readerHead + 1) % self.buffer.len;

        // Always as close to writerHead as possible, but never overtage
        if (nextSlot == self.writerHead) {
            return null;
        }

        return &self.buffer[nextSlot];
    }

    pub fn advanceReaderHead(self: *StackTrieRing) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const nextSlot = (self.readerHead + 1) % self.buffer.len;
        self.readerHead = nextSlot;
        std.log.info(
            "Progressing reader head. Reader head: {}, Reader tail: {}, Writer head: {}",
            .{ self.readerHead, self.readerTail, self.writerHead },
        );
    }

    // Returns the next tail,
    pub fn peekReaderTail(self: *StackTrieRing) ?*StackTrie {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Should be always 1 ahead of writer (thats the oldest), so if next is the slot beyond that null
        if (self.readerTail == (self.writerHead + 1) % self.buffer.len) {
            return &self.buffer[self.readerTail];
        }

        return null;
    }

    pub fn advanceReaderTail(self: *StackTrieRing) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const nextSlot = (self.readerTail + 1) % self.buffer.len;
        self.readerTail = nextSlot;

        std.log.info(
            "Progressing reader tail. Reader head: {}, Reader tail: {}, Writer head: {}",
            .{ self.readerHead, self.readerTail, self.writerHead },
        );
    }

    pub fn deinit(self: *StackTrieRing, allocator: std.mem.Allocator) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.buffer) |*ptr| ptr.deinit();
        allocator.free(self.buffer);
    }
};

/// ===================================================================================================================
/// App
/// ===================================================================================================================
pub const App = struct {
    allocator: std.mem.Allocator,
    profiler: Profiler,
    context: *ProfilerContext,
    ring: *StackTrieRing,
    bpfThread: ?std.Thread = null,
    tuiThread: ?std.Thread = null,
    symbols: *ThreadSafe(SymbolTrie),
    shouldQuit: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    interface: Interface,

    pub fn init(allocator: std.mem.Allocator) anyerror!App {
        const ring = try allocator.create(StackTrieRing);
        ring.* = try StackTrieRing.init(allocator, 16);

        const context = try allocator.create(ProfilerContext);

        context.* = .{
            .ring = ring,
            .iptrie = &ring.buffer[0],
            .umapCache = try UMapCache.init(allocator),
            .timestamp = std.time.nanoTimestamp(),
            .timeout = 100 * std.time.ns_per_ms,
        };

        const profiler = try Profiler.init(ProfilerContext, ProfilerContext.callback, allocator, context);

        const symboltrie = try allocator.create(SymbolTrie);
        symboltrie.* = try SymbolTrie.init(allocator);

        const symbols = try allocator.create(ThreadSafe(SymbolTrie));
        symbols.* = ThreadSafe(SymbolTrie).init(symboltrie);

        var interface = try Interface.init(allocator, symbols);
        interface.missed = &profiler.globals.dropped_events;

        return App{
            .allocator = allocator,
            .interface = interface,
            .profiler = profiler,
            .context = context,
            .symbols = symbols,
            .ring = ring,
        };
    }

    pub fn free(self: *App) void {
        self.shouldQuit.store(true, .release);
        if (self.bpfThread) |t| t.join();
        if (self.tuiThread) |t| t.join();

        self.profiler.deinit();
        self.context.umapCache.deinit();
        self.allocator.destroy(self.context);

        const syms = self.symbols.lock();
        syms.deinit();
        self.symbols.unlock();
        self.allocator.destroy(self.symbols);
        self.allocator.destroy(syms);

        self.ring.deinit(self.allocator);
        self.allocator.destroy(self.ring);
    }

    fn bpfWorker(self: *App, rate: usize) void {
        self.profiler.start(rate) catch {
            @panic("Could not start profiler");
        };

        while (!self.shouldQuit.load(.acquire)) {
            while (true) {
                const count = self.profiler.ring.consume() catch break;
                if (count == 0) break;
            }

            std.Thread.sleep(5 * std.time.ns_per_ms);
        }

        self.profiler.stop();
    }

    fn tuiWorker(self: *App) void {
        self.interface.start() catch {
            @panic("Could not start TUI");
        };

        self.shouldQuit.store(true, .monotonic);
    }

    pub fn tick(self: *App) !void {
        var shouldRedraw = false;
        if (self.ring.peekReaderTail()) |stack_trie| {
            const symbols = self.symbols.lock();
            defer self.symbols.unlock();

            try symbols.map(stack_trie.*, .evict);
            stack_trie.reset();

            self.ring.advanceReaderTail();

            shouldRedraw = true;
        }

        while (self.ring.peekReaderHead()) |stack_trie| {
            const symbols = self.symbols.lock();
            defer self.symbols.unlock();

            try symbols.map(stack_trie.*, .merge);

            self.ring.advanceReaderHead();

            shouldRedraw = true;
        }

        if (self.interface.loop) |*loop| {
            if (shouldRedraw) {
                loop.postEvent(.{ .redraw = {} });
            }
        }
    }

    /// Fixed duration measurement. Profile, then display the result. No streaming.
    pub fn runFixed(self: *App, rate: usize, timeout_ns: u64) anyerror!void {
        // No ring rotation — everything goes into one StackTrie
        self.context.timeout = std.math.maxInt(u64);

        // Profile on this thread, blocking
        try self.profiler.start(rate);
        defer self.profiler.stop();

        var timer = try std.time.Timer.start();
        while (timer.read() < timeout_ns) {
            const count = try self.profiler.ring.consume();
            if (count == 0) {
                try self.profiler.ring.poll(10);
            }
        }

        // Merge the single StackTrie into symbols
        {
            const symbols = self.symbols.lock();
            defer self.symbols.unlock();
            try symbols.map(self.ring.buffer[0], .merge);
        }

        // Show the TUI (blocks until user quits)
        try self.interface.start();
    }

    /// Aggregate indefinitely. Streams results to TUI, never evicts.
    pub fn runAggregate(self: *App, rate: usize) anyerror!void {
        // Rotate the ring, but never evict old data
        self.context.timeout = 50 * std.time.ns_per_ms;

        self.bpfThread = try std.Thread.spawn(.{}, bpfWorker, .{ self, rate });
        self.tuiThread = try std.Thread.spawn(.{}, tuiWorker, .{self});

        const merge_interval = 16 * std.time.ns_per_ms;

        while (!self.shouldQuit.load(.acquire)) {
            try self.tickMergeOnly();
            std.Thread.sleep(merge_interval);
        }
    }

    /// Sliding window. Streams results to TUI, evicts oldest slot when ring is full.
    pub fn runRing(self: *App, rate: usize, slot_ns: u64, ring_slots: usize) anyerror!void {
        // Reinitialize ring with requested size
        self.ring.deinit(self.allocator);
        self.ring.* = try StackTrieRing.init(self.allocator, ring_slots);
        self.context.ring = self.ring;
        self.context.iptrie = &self.ring.buffer[0];

        self.context.timeout = slot_ns;

        self.bpfThread = try std.Thread.spawn(.{}, bpfWorker, .{ self, rate });
        self.tuiThread = try std.Thread.spawn(.{}, tuiWorker, .{self});

        const merge_interval = 16 * std.time.ns_per_ms;

        while (!self.shouldQuit.load(.acquire)) {
            try self.tick();
            std.Thread.sleep(merge_interval);
        }
    }

    /// Merge only, no eviction. Used by aggregate mode.
    fn tickMergeOnly(self: *App) !void {
        var shouldRedraw = false;

        while (self.ring.peekReaderHead()) |stack_trie| {
            const symbols = self.symbols.lock();
            defer self.symbols.unlock();

            try symbols.map(stack_trie.*, .merge);

            self.ring.advanceReaderHead();
            shouldRedraw = true;
        }

        while (self.ring.peekReaderTail()) |stack_trie| {
            stack_trie.reset();
            self.ring.advanceReaderTail();
        }

        if (self.interface.loop) |*loop| {
            if (shouldRedraw) {
                loop.postEvent(.{ .redraw = {} });
            }
        }
    }
};
