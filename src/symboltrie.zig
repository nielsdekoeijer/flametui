const std = @import("std");
const KMap = @import("kmap.zig").KMap;
const StackTrieUnmanaged = @import("stacktrie.zig").StackTrieUnmanaged;
const SharedObjectMapCache = @import("sharedobject.zig").SharedObjectMapCache;
const PID = @import("profile.zig").PID;
const TID = @import("profile.zig").TID;
const StringInternerUnmanaged = @import("interner.zig").StringInternerUnmanaged;
const c = @import("cimport.zig").c;

/// ===================================================================================================================
/// Helpers
/// ===================================================================================================================
/// We link libcpp for this reason
extern "c" fn __cxa_demangle(
    mangled_name: [*c]const u8,
    output_buffer: [*c]u8,
    length: [*c]usize,
    status: *c_int,
) [*c]u8;

/// Helper for C++ demanling, either demangles or dupes
/// TODO: Rust also does mangling doesn't it? Probably someone needs to impl that. How I do not know.
fn tryDemangleOrDupe(
    allocator: std.mem.Allocator,
    interner: *StringInternerUnmanaged,
    mangled_name: []const u8,
) ![]const u8 {
    // C++ symbols start with _Z. If not, return original.
    if (!std.mem.startsWith(u8, mangled_name, "_Z")) {
        return try interner.dupe(allocator, mangled_name);
    }

    // Prepare C-string (null-terminated)
    const c_name = try allocator.dupeZ(u8, mangled_name);
    defer allocator.free(c_name);

    // Call __cxa_demangle
    // ```
    // status:
    //   0 = success
    //  -1 = memory
    //  -2 = invalid name
    //  -3 = invalid arg
    //  ```
    var status: c_int = undefined;

    const demangled_ptr = __cxa_demangle(c_name, null, null, &status);

    if (status == 0 and demangled_ptr != null) {
        // Convert to Zig slice and copy to our allocator
        const len = std.mem.len(demangled_ptr);
        const result = try interner.dupe(allocator, demangled_ptr[0..len]);

        // Free the memory allocated by __cxa_demangle
        c.free(demangled_ptr);
        return result;
    }

    return try interner.dupe(allocator, mangled_name);
}

test "symboltrie.tryDemangleOrDupe dupes original for non-C++ symbols" {
    var interner = StringInternerUnmanaged.init();
    defer interner.deinit(std.testing.allocator);
    const result = try tryDemangleOrDupe(std.testing.allocator, &interner, "main");
    try std.testing.expectEqualStrings("main", result);
}

test "symboltrie.tryDemangleOrDupe demangles C++ symbol" {
    var interner = StringInternerUnmanaged.init();
    defer interner.deinit(std.testing.allocator);
    const result = try tryDemangleOrDupe(std.testing.allocator, &interner, "_ZN3foo3barEv");
    try std.testing.expectEqualStrings("foo::bar()", result);
}

test "symboltrie.tryDemangleOrDupe returns original for invalid mangled name" {
    var interner = StringInternerUnmanaged.init();
    defer interner.deinit(std.testing.allocator);
    const result = try tryDemangleOrDupe(std.testing.allocator, &interner, "_Znonsense");

    // __cxa_demangle fails, should fall back to original
    try std.testing.expectEqualStrings("_Znonsense", result);
}

test "symboltrie.tryDemangleOrDupe handles empty string" {
    var interner = StringInternerUnmanaged.init();
    defer interner.deinit(std.testing.allocator);
    const result = try tryDemangleOrDupe(std.testing.allocator, &interner, "");
    try std.testing.expectEqualStrings("", result);
}

/// ===================================================================================================================
/// SymbolTrie
/// ===================================================================================================================
/// Trie for tracking incoming stacktraces
pub const SymbolTrie = struct {
    /// What we store in a trie for a kernel stack frame
    pub const KTriePayload = struct {
        symbol: []const u8,
    };

    /// What we store in a trie for a userspace stack frame
    pub const UTriePayload = struct {
        dll: []const u8,
        symbol: []const u8,
    };

    /// Trie union, datatype we store in the trie
    pub const TriePayload = union(enum) {
        user: UTriePayload,
        root: KTriePayload,
        kernel: KTriePayload,
        comm: KTriePayload,
        pid: KTriePayload,
        tid: KTriePayload,
    };

    /// Our node type
    pub const TrieNode = struct {
        hitCount: u64,
        parent: NodeId,
        // To be able to walk the trie, we store an array to its children
        children: std.ArrayListUnmanaged(NodeId),
        payload: TriePayload,
    };

    /// Type for indexing nodes
    pub const NodeId = u32;

    /// Unique id for the root
    pub const RootId: NodeId = 0;

    /// Key used for our trie
    pub const Key = struct { parent: NodeId, symbolHash: u64 };

    /// Underlying flat trie
    nodes: std.ArrayListUnmanaged(TrieNode),

    /// Helps us lookup indices for parent <-> child relations
    nodesLookup: std.AutoHashMapUnmanaged(Key, NodeId),

    /// Demangling is expensive, so we cache it
    demangleCache: std.StringHashMapUnmanaged([]const u8),

    /// Store our allocator, not unmanaged
    allocator: std.mem.Allocator,

    /// Kernel maps, assumed static
    kmap: ?*KMap,

    /// For loading dlls
    sharedObjectMapCache: SharedObjectMapCache,

    /// String dedupe
    interner: StringInternerUnmanaged,

    pub fn init(allocator: std.mem.Allocator, kmap: ?*KMap) !SymbolTrie {
        return SymbolTrie{
            .nodes = try std.ArrayListUnmanaged(TrieNode).initCapacity(allocator, 1024),
            .nodesLookup = .{},
            //     try std.AutoHashMapUnmanaged(Key, NodeId).init(
            //     allocator,
            //     &[_]Key{},
            //     &[_]NodeId{},
            // ),
            .allocator = allocator,
            .kmap = kmap,
            .sharedObjectMapCache = try SharedObjectMapCache.init(allocator),
            .demangleCache = .{},
            .interner = .init(),
        };
    }

    /// Creates a symboltrie from a perf script, requires you to use -g!
    pub fn initPerfScript(allocator: std.mem.Allocator, reader: *std.Io.Reader) !SymbolTrie {
        // return try initCollapsed(allocator, reader);
        var self = SymbolTrie{
            .nodes = try std.ArrayListUnmanaged(TrieNode).initCapacity(allocator, 1024),
            .nodesLookup = .{},
            //     try std.AutoHashMapUnmanaged(Key, NodeId).init(
            //     allocator,
            //     &[_]Key{},
            //     &[_]NodeId{},
            // ),
            .allocator = allocator,
            .kmap = null,
            .sharedObjectMapCache = try SharedObjectMapCache.init(allocator),
            .demangleCache = .{},
            .interner = .init(),
        };
        errdefer self.deinit();

        // Append root node
        // GIGA JANK we gotta find a better way
        if (self.nodes.items.len == 0) {
            try self.nodes.append(self.allocator, TrieNode{
                .hitCount = 0,
                .parent = RootId,
                .children = try std.ArrayListUnmanaged(NodeId).initCapacity(self.allocator, 0),
                .payload = .{ .root = .{ .symbol = try self.interner.dupe(self.allocator, "root") } },
            });
            const rootKey = Key{ .parent = RootId, .symbolHash = hashSymbol("root") };
            try self.nodesLookup.put(self.allocator, rootKey, RootId);
        }

        const ParseState = enum {
            seekingHeader,
            parsingStack,
            commitable,
        };

        // Parse the perf file. The tricky part here is that the stack is specified top down, and we require bottom up!
        var state: ParseState = .seekingHeader;

        var payload: std.ArrayListUnmanaged(UTriePayload) = .{};
        defer payload.deinit(allocator);
        var head: ?[]const u8 = null;

        while (true) {
            // Take line by line
            const line = reader.takeDelimiterExclusive('\n') catch break;

            switch (state) {
                .seekingHeader => {
                    // Newline unexpected, but we just continue
                    if (line.len == 0) {
                        std.log.warn("Encountered unexpected newline while parsing perf script", .{});
                        continue;
                    }

                    // On comment, continue we don't care
                    if (line[0] == '#') {
                        continue;
                    }

                    // Split on whitespace
                    var iter = std.mem.tokenizeAny(u8, line, " \t");
                    const comm = iter.next() orelse {
                        std.log.warn("Encountered whitespace newline while parsing perf script", .{});
                        continue;
                    };

                    // Append
                    head = try self.interner.dupe(self.allocator, comm);
                    std.log.debug("Parsed head '{s}'", .{head orelse unreachable});
                    state = .parsingStack;
                },
                .parsingStack => {
                    // Newline designates termination
                    if (line.len == 0) {
                        state = ParseState.commitable;
                    } else {

                        // On comment, continue we don't care
                        if (line[0] == '#') {
                            continue;
                        }

                        var iter = std.mem.tokenizeAny(u8, line, " \t");

                        // this grabs the ip
                        _ = iter.next() orelse return error.StackParsingFailure;

                        // This grabs the symbol
                        const symbolRaw = iter.next() orelse return error.StackParsingFailure;
                        const symbol = if (std.mem.indexOfScalar(u8, symbolRaw, '+')) |idx|
                            symbolRaw[0..idx]
                        else
                            symbolRaw;

                        if (symbol.len == 0) {
                            std.log.err("Encountered zero-length symbol '{s}' ('{s}')", .{ symbol, symbolRaw });
                            return error.StackParsingFailure;
                        }

                        // This grabs the dll
                        const dllBracketed = iter.next() orelse return error.StackParsingFailure;
                        const dll = std.mem.trim(u8, dllBracketed, "()");

                        std.log.debug("Parsed user symbol '{s}' and dll '{s}'", .{ symbol, dll });
                        try payload.append(allocator, .{
                            .dll = try self.interner.dupe(self.allocator, dll),
                            .symbol = try self.interner.dupe(self.allocator, symbol),
                        });
                    }
                },
                else => unreachable,
            }

            if (state == .commitable) {
                state = .seekingHeader;

                try payload.append(allocator, .{
                    .dll = try self.interner.dupe(self.allocator, head orelse unreachable),
                    .symbol = try self.interner.dupe(self.allocator, head orelse unreachable),
                });

                var parentId = RootId;
                self.nodes.items[RootId].hitCount += 1;

                var j = payload.items.len;
                while (j > 0) {
                    j -|= 1;

                    const symbol = payload.items[j].symbol;

                    const key = Key{
                        .parent = parentId,
                        .symbolHash = hashSymbol(symbol),
                    };
                    const found = self.nodesLookup.get(key);
                    if (found) |symbolId| {
                        // Hit! Add the total hitcount
                        self.nodes.items[symbolId].hitCount += 1;
                        parentId = symbolId;
                    } else {
                        try self.nodes.append(self.allocator, TrieNode{
                            .hitCount = 1,
                            .parent = parentId,
                            .payload = .{ .user = .{
                                .symbol = try self.getDemangledOrDupe(payload.items[j].symbol),
                                .dll = try self.interner.dupe(self.allocator, payload.items[j].dll),
                            } },
                            .children = try std.ArrayListUnmanaged(NodeId).initCapacity(self.allocator, 0),
                        });

                        // Compute the new node id
                        const nodeId: NodeId = @intCast(self.nodes.items.len - 1);
                        try self.nodesLookup.put(self.allocator, key, nodeId);

                        // Go to parent, and add self as child
                        if (nodeId != parentId) {
                            try self.nodes.items[parentId].children.append(self.allocator, nodeId);
                        }

                        // Update, new parent
                        parentId = nodeId;
                    }
                }

                self.interner.free(head orelse unreachable);
                head = null;

                for (payload.items) |*p| {
                    self.interner.free(p.symbol);
                    self.interner.free(p.dll);
                }
                payload.clearRetainingCapacity();
            }
        }

        return self;
    }

    // For loading a collapsed stacktrace file
    pub fn initCollapsed(allocator: std.mem.Allocator, reader: *std.Io.Reader) !SymbolTrie {
        var self = SymbolTrie{
            .nodes = try std.ArrayListUnmanaged(TrieNode).initCapacity(allocator, 1024),
            .nodesLookup = .{},
            //     try std.AutoHashMapUnmanaged(Key, NodeId).init(
            //     allocator,
            //     &[_]Key{},
            //     &[_]NodeId{},
            // ),
            .allocator = allocator,
            .kmap = null,
            .sharedObjectMapCache = try SharedObjectMapCache.init(allocator),
            .demangleCache = .{},
            .interner = .init(),
        };
        errdefer self.deinit();

        // Append root node
        // GIGA JANK we gotta find a better way
        if (self.nodes.items.len == 0) {
            try self.nodes.append(self.allocator, TrieNode{
                .hitCount = 0,
                .parent = RootId,
                .children = try std.ArrayListUnmanaged(NodeId).initCapacity(self.allocator, 0),
                .payload = .{ .root = .{ .symbol = try self.interner.dupe(self.allocator, "root") } },
            });
            const rootKey = Key{ .parent = RootId, .symbolHash = hashSymbol("root") };
            try self.nodesLookup.put(self.allocator, rootKey, RootId);
        }

        while (true) {
            // Take line by line
            const line = reader.takeDelimiterExclusive('\n') catch break;

            // Remove unexpected characters
            const trimmed = std.mem.trim(u8, line, "\r\t ");
            if (trimmed.len == 0) {
                continue;
            }

            // Split into stack part and count part on the last space
            const lastSpace = std.mem.lastIndexOfScalar(u8, trimmed, ' ') orelse return error.CollapsedParseFailure;
            const stackPart = trimmed[0..lastSpace];
            const countStr = std.mem.trim(u8, trimmed[lastSpace + 1 ..], " ");
            const count = std.fmt.parseInt(u64, countStr, 10) catch return error.CollapsedParseFailure;

            // Increment root
            self.nodes.items[RootId].hitCount += count;
            // Get all the entries — only tokenize the stack part, not the count
            var colonIter = std.mem.tokenizeAny(u8, stackPart, ";");
            var parentId = RootId;

            // For now, we just treat everything as though its a user
            while (colonIter.next()) |symbol| {
                const key = Key{
                    .parent = parentId,
                    .symbolHash = hashSymbol(symbol),
                };
                const found = self.nodesLookup.get(key);
                if (found) |symbolId| {
                    // Hit! Add the total hitcount
                    self.nodes.items[symbolId].hitCount += count;
                    parentId = symbolId;
                } else {
                    // Miss! Create the node and append
                    try self.nodes.append(self.allocator, TrieNode{
                        // Add the stack items hit count
                        .hitCount = count,
                        .parent = parentId,
                        .payload = .{
                            .user = .{
                                // take the symbol, takes ownership!
                                .symbol = try self.getDemangledOrDupe(symbol),
                                // clone the dll for debug later
                                .dll = try self.interner.dupe(self.allocator, "<Imported from Collapsed>"),
                            },
                        },
                        .children = try std.ArrayListUnmanaged(NodeId).initCapacity(self.allocator, 0),
                    });
                    // Compute the new node id
                    const nodeId: NodeId = @intCast(self.nodes.items.len - 1);
                    try self.nodesLookup.put(self.allocator, key, nodeId);
                    // Go to parent, and add self as child
                    if (nodeId != parentId) {
                        try self.nodes.items[parentId].children.append(self.allocator, nodeId);
                    }
                    // Update, new parent
                    parentId = nodeId;
                }
            }
        }
        return self;
    }

    fn getDemangledOrDupe(self: *SymbolTrie, mangled_name: []const u8) ![]const u8 {
        if (self.demangleCache.get(mangled_name)) |cached| {
            return try self.interner.dupe(self.allocator, cached);
        }

        const result = try tryDemangleOrDupe(self.allocator, &self.interner, mangled_name);
        errdefer self.interner.free(result);

        const key = try self.interner.dupe(self.allocator, mangled_name);
        errdefer self.interner.free(key);

        const val = try self.interner.dupe(self.allocator, result);
        errdefer self.interner.free(val);

        try self.demangleCache.put(self.allocator, key, val);

        return result;
    }

    test "symboltrie.SymbolTrie.initCollapsed parses simple collapsed format" {
        const input = "main;foo;bar 10\nmain;foo;baz 5\n";
        var reader = std.Io.Reader.fixed(input);

        var trie = try SymbolTrie.initCollapsed(std.testing.allocator, &reader);
        defer trie.deinit();

        // root + main + foo + bar + baz = 5 nodes
        try std.testing.expectEqual(5, trie.nodes.items.len);
        try std.testing.expectEqual(15, trie.nodes.items[SymbolTrie.RootId].hitCount);
    }

    test "symboltrie.SymbolTrie.initCollapsed handles empty input" {
        var reader = std.Io.Reader.fixed("");

        var trie = try SymbolTrie.initCollapsed(std.testing.allocator, &reader);
        defer trie.deinit();

        try std.testing.expectEqual(1, trie.nodes.items.len); // just root
    }

    test "symboltrie.SymbolTrie.initCollapsed skips blank lines" {
        const input = "\n\nmain;foo 3\n\n";
        var reader = std.Io.Reader.fixed(input);

        var trie = try SymbolTrie.initCollapsed(std.testing.allocator, &reader);
        defer trie.deinit();

        try std.testing.expectEqual(3, trie.nodes.items.len); // root + main + foo
    }

    pub fn exportCollapsed(self: *const SymbolTrie, writer: anytype) !void {
        // Path buffer: stack of symbol indices from root to current node
        var path: [256]NodeId = undefined;

        for (self.nodes.items, 0..) |node, i| {
            const id: NodeId = @intCast(i);

            // Only emit leaf nodes (no children) with hits
            if (node.children.items.len != 0 or node.hitCount == 0) continue;
            if (id == RootId) continue;

            // Walk up to root to build the path
            var depth: usize = 0;
            var curr = id;
            while (curr != RootId) {
                if (depth >= path.len) return error.StackTooDeep;
                path[depth] = curr;
                depth += 1;
                curr = self.nodes.items[curr].parent;
            }

            // Write symbols root-to-leaf (reverse of what we collected)
            var j = depth;
            while (j > 0) {
                j -= 1;
                const symbol = switch (self.nodes.items[path[j]].payload) {
                    inline else => |s| s.symbol,
                };
                try writer.writeAll(symbol);
                if (j > 0) try writer.writeAll(";");
            }

            // Write the hit count
            try writer.print(" {}\n", .{node.hitCount});
        }
    }

    test "symboltrie.SymbolTrie.exportCollapsed round-trips with initCollapsed" {
        const input = "main;foo;bar 10\nmain;foo;baz 5\nmain;qux 3\n";
        var reader = std.Io.Reader.fixed(input);

        var trie = try SymbolTrie.initCollapsed(std.testing.allocator, &reader);
        defer trie.deinit();

        // Export to buffer
        var buf: [4096]u8 = undefined;
        var stream = std.io.fixedBufferStream(&buf);
        try trie.exportCollapsed(stream.writer());
        const exported = stream.getWritten();

        // Re-parse the exported output
        var reader2 = std.Io.Reader.fixed(exported);
        var trie2 = try SymbolTrie.initCollapsed(std.testing.allocator, &reader2);
        defer trie2.deinit();

        // Same structure: root + main + foo + bar + baz + qux = 6 nodes
        try std.testing.expectEqual(trie.nodes.items.len, trie2.nodes.items.len);
        try std.testing.expectEqual(trie.nodes.items[SymbolTrie.RootId].hitCount, trie2.nodes.items[SymbolTrie.RootId].hitCount);
    }

    test "symboltrie.SymbolTrie.exportCollapsed emits nothing for empty trie" {
        var reader = std.Io.Reader.fixed("");
        var trie = try SymbolTrie.initCollapsed(std.testing.allocator, &reader);
        defer trie.deinit();

        var buf: [4096]u8 = undefined;
        var stream = std.io.fixedBufferStream(&buf);
        try trie.exportCollapsed(stream.writer());

        try std.testing.expectEqual(0, stream.getWritten().len);
    }

    test "symboltrie.SymbolTrie.exportCollapsed single stack" {
        const input = "a;b;c 7\n";
        var reader = std.Io.Reader.fixed(input);
        var trie = try SymbolTrie.initCollapsed(std.testing.allocator, &reader);
        defer trie.deinit();

        var buf: [4096]u8 = undefined;
        var stream = std.io.fixedBufferStream(&buf);
        try trie.exportCollapsed(stream.writer());

        try std.testing.expectEqualStrings("a;b;c 7\n", stream.getWritten());
    }

    /// Our hashing function
    fn hashSymbol(str: []const u8) u64 {
        return std.hash.Wyhash.hash(0, str);
    }

    pub const MapMode = enum { merge, evict };

    // Convert a stacktrie into a symboltrie. What we do is load the symbols
    pub fn map(self: *SymbolTrie, stacktrie: StackTrieUnmanaged, mode: MapMode) !void {
        // The shadowmap is used to resolve parents of the stacktrie to the correct one in the symboltrie. Why
        // cant we have a 1:1 relation? In the symboltrie, we may resolve different instruction pointers to the
        // same symbol name. Idiomatically, for flamegraphs we need to merge them.
        const ShadowMap = std.AutoHashMapUnmanaged(StackTrieUnmanaged.NodeId, SymbolTrie.NodeId);
        var shadowMap: ShadowMap = .{};
            // try ShadowMap.init(self.allocator, &[_]StackTrieUnmanaged.NodeId{}, &[_]SymbolTrie.NodeId{});
        defer shadowMap.deinit(self.allocator);

        // Map the root ids to eachother
        try shadowMap.put(self.allocator, StackTrieUnmanaged.RootId, RootId);

        // We exploit the fact that our tree is laid out from root --> upwards
        for (0..stacktrie.nodes.items.len) |i| {
            // Get stack item
            const stackId: NodeId = @intCast(i);
            const stackItem = stacktrie.nodes.items[stackId];

            // If no hitcount, our eviction logic does nothing
            if (mode == .evict and stackItem.hitCount == 0) {
                continue;
            }

            // Resolve the parent (due to the order, should be garunteed to be known)
            const parentId = shadowMap.get(stackItem.parent) orelse return error.ShadowMapError;

            // Find the symbol based on the type of node
            var interned_symbol: ?[]const u8 = null;
            const symbol = switch (stackItem.payload) {
                // Root is just given
                .root => "root",

                // Comm node
                .comm => |e| blk: {
                    break :blk try self.interner.dupe(self.allocator, e);
                },

                // Use our kmap to resolve the symbol
                // TODO: we throw, do we want to do this differently?
                .kernel => |e| blk: {
                    const s = try self.kmap.?.find(e.kmapip);
                    break :blk s.symbol;
                },

                // Use our umap to resolve the symbol
                // TODO: we throw, do we want to do this differently?
                .user => |e| blk: {
                    const p = stacktrie.umaps.items[e.umapid];
                    const s = try self.sharedObjectMapCache.find(p.path);
                    switch (s.find(e.umapip, p)) {
                        .found => |w| {
                            interned_symbol = try self.getDemangledOrDupe(w.name);
                            break :blk interned_symbol.?;
                        },
                        .notfound => {
                            var buf: [64]u8 = undefined;
                            const text = try std.fmt.bufPrint(&buf, "notfound:0x{x}", .{e.umapip});
                            interned_symbol = try self.interner.dupe(self.allocator, text);
                            break :blk interned_symbol.?;
                        },
                        .unmapped => {
                            var buf: [64]u8 = undefined;
                            const text = try std.fmt.bufPrint(&buf, "unmapped:0x{x}", .{e.umapip});
                            interned_symbol = try self.interner.dupe(self.allocator, text);
                            break :blk interned_symbol.?;
                        },
                    }
                },
                .pid => |e| blk: {
                    var buf: [64]u8 = undefined;
                    const text = try std.fmt.bufPrint(&buf, "pid:{d}", .{e});
                    interned_symbol = try self.interner.dupe(self.allocator, text);
                    break :blk interned_symbol.?;
                },
                .tid => |e| blk: {
                    var buf: [64]u8 = undefined;
                    const text = try std.fmt.bufPrint(&buf, "tid:{d}", .{e});
                    interned_symbol = try self.interner.dupe(self.allocator, text);
                    break :blk interned_symbol.?;
                },
            };

            defer {
                if (interned_symbol) |s| self.interner.free(s);
            }

            // Create the key base on the symbol we just read
            const key = Key{ .parent = parentId, .symbolHash = hashSymbol(symbol) };

            // See if we can find our node
            const found = self.nodesLookup.get(key);
            if (found) |symbolId| {
                // Hit! Add the total hitcount
                switch (mode) {
                    .merge => {
                        self.nodes.items[symbolId].hitCount += stackItem.hitCount;
                    },
                    .evict => {
                        std.log.info(
                            "Evicting {} from {} with hitcount {}",
                            .{ stackItem.hitCount, symbolId, self.nodes.items[symbolId].hitCount },
                        );
                        self.nodes.items[symbolId].hitCount -|= stackItem.hitCount;
                    },
                }
                try shadowMap.put(self.allocator, stackId, symbolId);
            } else {
                switch (mode) {
                    .merge => {
                        // Miss! Create the node and append
                        try self.nodes.append(self.allocator, TrieNode{
                            // Add the stack items hit ount
                            .hitCount = stackItem.hitCount,
                            .parent = parentId,
                            .payload = blk: switch (stackItem.payload) {
                                .root => break :blk TriePayload{
                                    .root = .{
                                        // take the symbol + dupe, takes ownership!
                                        .symbol = try self.interner.dupe(self.allocator, symbol),
                                    },
                                },
                                .kernel => break :blk TriePayload{
                                    .kernel = .{
                                        // take the symbol + dupe, takes ownership!
                                        .symbol = try self.interner.dupe(self.allocator, symbol),
                                    },
                                },
                                .comm,
                                => break :blk TriePayload{
                                    .comm = .{
                                        // take the symbol + dupe, takes ownership!
                                        .symbol = try self.interner.dupe(self.allocator, symbol),
                                    },
                                },
                                .pid,
                                => break :blk TriePayload{
                                    .pid = .{
                                        // take the symbol + dupe, takes ownership!
                                        .symbol = try self.interner.dupe(self.allocator, symbol),
                                    },
                                },
                                .tid,
                                => break :blk TriePayload{
                                    .tid = .{
                                        // take the symbol + dupe, takes ownership!
                                        .symbol = try self.interner.dupe(self.allocator, symbol),
                                    },
                                },
                                .user => |e| break :blk TriePayload{
                                    .user = .{
                                        // take the symbol, takes ownership!
                                        .symbol = try self.interner.dupe(self.allocator, symbol),
                                        // clone the dll for debug later
                                        .dll = try self.interner.dupe(self.allocator, stacktrie.umaps.items[e.umapid].path),
                                    },
                                },
                            },
                            .children = try std.ArrayListUnmanaged(NodeId).initCapacity(self.allocator, 0),
                        });

                        // Compute the new node id
                        const nodeId: NodeId = @intCast(self.nodes.items.len - 1);
                        try self.nodesLookup.put(self.allocator, key, nodeId);

                        // Add a mapping between the stack node refering to this symbol
                        try shadowMap.put(self.allocator, stackId, nodeId);

                        // Go to parent, and add self as child
                        if (nodeId != parentId) {
                            try self.nodes.items[parentId].children.append(self.allocator, nodeId);
                        }
                    },
                    .evict => {
                        // Miss! But this is not possible, return error
                        std.log.info("Evicting {s} failed", .{symbol});
                        return error.RemoveNonExisting;
                    },
                }
            }
        }
    }

    pub fn deinit(self: *SymbolTrie) void {
        for (self.nodes.items) |*node| {
            node.children.deinit(self.allocator);
            switch (node.payload) {
                .kernel,
                .root,
                .comm,
                .pid,
                .tid,
                => |s| self.interner.free(s.symbol),
                .user => |s| {
                    self.interner.free(s.symbol);
                    self.interner.free(s.dll);
                },
            }
        }

        self.nodes.deinit(self.allocator);
        self.nodesLookup.deinit(self.allocator);
        self.sharedObjectMapCache.deinit();

        var it = self.demangleCache.iterator();
        while (it.next()) |entry| {
            self.interner.free(entry.key_ptr.*);
            self.interner.free(entry.value_ptr.*);
        }

        // Finally, destroy the map's internal arrays
        self.demangleCache.deinit(self.allocator);

        self.interner.deinit(self.allocator);
    }
};
