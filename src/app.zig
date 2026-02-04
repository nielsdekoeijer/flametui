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
            if (context.ring.progressWriter()) |new| {
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
    head: usize,
    tail: usize,

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
            .head = 0,
            .tail = 0,
        };
    }

    /// Returns the NEW head to continue writing.
    pub fn progressWriter(self: *StackTrieRing) ?*StackTrie {
        self.mutex.lock();
        defer self.mutex.unlock();

        const next = (self.head + 1) % self.buffer.len;

        if (next == self.tail) {
            return null;
        }

        self.head = next;
        return &self.buffer[self.head];
    }

    pub fn progressReader(self: *StackTrieRing) ?*StackTrie {
        self.mutex.lock();
        defer self.mutex.unlock();

        const next = (self.tail + 1) % self.buffer.len;

        if (self.head == self.tail) {
            return null;
        }

        self.tail = next;
        return &self.buffer[self.tail];
    }

    pub fn deinit(self: *StackTrieRing, allocator: std.mem.Allocator) void {
        for (self.buffer) |*ptr| ptr.free();
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
        ring.* = try StackTrieRing.init(allocator, 3);

        const context = try allocator.create(ProfilerContext);

        context.* = .{
            .ring = ring,
            .iptrie = &ring.buffer[0],
            .umapCache = try UMapCache.init(allocator),
            .timestamp = std.time.nanoTimestamp(),
            .timeout = 50 * std.time.ns_per_ms,
        };

        const profiler = try Profiler.init(ProfilerContext, ProfilerContext.callback, allocator, context);

        const symboltrie = try allocator.create(SymbolTrie);
        symboltrie.* = try SymbolTrie.init(allocator);

        const symbols = try allocator.create(ThreadSafe(SymbolTrie));
        symbols.* = ThreadSafe(SymbolTrie).init(symboltrie);

        const interface = try Interface.init(allocator, symbols);

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

        self.profiler.free();
        self.context.umapCache.deinit();
        self.allocator.destroy(self.context);

        const syms = self.symbols.lock();
        syms.free();
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
            const count = self.profiler.ring.consume() catch {
                @panic("Could not start timer");
            };

            if (count == 0) {
                self.profiler.ring.poll(10) catch {
                    @panic("Could not start timer");
                };
            }
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
        while (self.ring.progressReader()) |stack_trie| {
            const symbols = self.symbols.lock();
            defer self.symbols.unlock();
            try symbols.map(stack_trie.*, .merge);

            if (self.interface.loop) |*loop| {
                loop.postEvent(.{ .redraw = {} });
            }
        }
    }

    pub fn run(self: *App, rate: usize, nanoseconds: u64) anyerror!void {
        self.context.timeout = (nanoseconds / 1_000_000) * std.time.ns_per_ms; // Wait, input is ns?
        self.context.timeout = 50 * std.time.ns_per_ms;
        self.bpfThread = try std.Thread.spawn(.{}, bpfWorker, .{ self, rate });
        self.tuiThread = try std.Thread.spawn(.{}, tuiWorker, .{self});

        const merge_interval = 16 * std.time.ns_per_ms;

        while (!self.shouldQuit.load(.acquire)) {
            try self.tick();
            std.Thread.sleep(merge_interval);
        }
    }
};
