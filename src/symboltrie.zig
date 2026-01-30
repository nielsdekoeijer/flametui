const std = @import("std");

const KMapUnmanaged = @import("kmap.zig").KMapUnmanaged;

const StackTrie = @import("stacktrie.zig").StackTrie;

const SharedObjectMapCache = @import("sharedobject.zig").SharedObjectMapCache;

extern "c" fn __cxa_demangle(
    mangled_name: [*c]const u8,
    output_buffer: [*c]u8,
    length: [*c]usize,       // <-- CHANGE THIS to [*c]usize
    status: *c_int,
) [*c]u8;

/// Helper for C++ demanling
fn tryDemangle(allocator: std.mem.Allocator, mangled_name: []const u8) ![]const u8 {
    // 1. C++ symbols start with _Z. If not, return original.
    if (!std.mem.startsWith(u8, mangled_name, "_Z")) {
        return try allocator.dupe(u8, mangled_name);
    }

    // 2. Prepare C-string (null-terminated)
    const c_name = try allocator.dupeZ(u8, mangled_name);
    defer allocator.free(c_name);

    // 3. Call __cxa_demangle
    // status: 0 = success, -1 = memory, -2 = invalid name, -3 = invalid arg
    var status: c_int = undefined;

    // cimport.zig must include <cxxabi.h> and <stdlib.h>
    const c = @import("cimport.zig").c;

    const demangled_ptr = __cxa_demangle(c_name, null, null, &status);

    if (status == 0 and demangled_ptr != null) {
        // 4. Convert to Zig slice and copy to our allocator
        // We use span to calculate length of the C string
        const len = std.mem.len(demangled_ptr);
        const result = try allocator.dupe(u8, demangled_ptr[0..len]);

        // 5. IMPORTANT: Free the memory allocated by __cxa_demangle
        c.free(demangled_ptr);
        return result;
    }

    // Fallback: return original if demangling failed
    return try allocator.dupe(u8, mangled_name);
}

/// ===================================================================================================================
/// SymbolTrie
/// ===================================================================================================================
/// Trie for tracking incoming stacktraces
pub const SymbolTrie = struct {
    /// The different entry types in our trie
    pub const TrieKind = enum {
        root,
        kernel,
        user,
    };

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
    pub const TriePayload = union(TrieKind) {
        root: KTriePayload,
        kernel: KTriePayload,
        user: UTriePayload,
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
    nodesLookup: std.AutoArrayHashMapUnmanaged(Key, NodeId),

    /// Store our allocator, not unmanaged
    allocator: std.mem.Allocator,

    /// Kernel maps, assumed static
    kmap: KMapUnmanaged,

    /// For loading dlls
    sharedObjectMapCache: SharedObjectMapCache,

    pub fn init(allocator: std.mem.Allocator) !SymbolTrie {
        return SymbolTrie{
            .nodes = try std.ArrayListUnmanaged(TrieNode).initCapacity(allocator, 0),
            .nodesLookup = try std.AutoArrayHashMapUnmanaged(Key, NodeId).init(
                allocator,
                &[_]Key{},
                &[_]NodeId{},
            ),
            .allocator = allocator,
            .kmap = try KMapUnmanaged.init(allocator),
            .sharedObjectMapCache = try SharedObjectMapCache.init(allocator),
        };
    }

    /// Our hashing function
    fn hashSymbol(str: []const u8) u64 {
        return std.hash.Wyhash.hash(0, str);
    }

    // Convert a stacktrie into a symboltrie. What we do is load the symbols
    pub fn add(self: *SymbolTrie, stacks: StackTrie) !void {
        // The shadowmap is used to resolve parents of the stacktrie to the correct one in the symboltrie. Why
        // cant we have a 1:1 relation? In the symboltrie, we may resolve different instruction pointers to the
        // same symbol name. Idiomatically, for flamegraphs we need to merge them.
        const ShadowMap = std.AutoArrayHashMapUnmanaged(StackTrie.NodeId, SymbolTrie.NodeId);
        var shadowMap = try ShadowMap.init(self.allocator, &[_]StackTrie.NodeId{}, &[_]SymbolTrie.NodeId{});
        defer shadowMap.deinit(self.allocator);

        // Map the root ids to eachother
        try shadowMap.put(self.allocator, StackTrie.RootId, RootId);

        // We exploit the fact that our tree is laid out from root --> upwards
        for (0..stacks.nodes.items.len) |i| {
            // Get stack item
            const stackId: NodeId = @intCast(i);
            const stackItem = stacks.nodes.items[stackId];

            // Resolve the parent (due to the order, should be garunteed to be known)
            const parentId = shadowMap.get(stackItem.parent) orelse return error.ShadowMapError;

            // Find the symbol based on the type of node
            const symbol = switch (stackItem.payload) {
                // Root is just given
                .root => "root",
                // Use our kmap to resolve the symbol
                // TODO: we throw, do we want to do this differently?
                .kernel => |e| blk: {
                    const s = try self.kmap.find(e.kmapip);
                    break :blk try self.allocator.dupe(u8, s.symbol);
                },
                // Use our umap to resolve the symbol
                // TODO: we throw, do we want to do this differently?
                .user => |e| blk: {
                    const p = stacks.umaps.items[e.umapid];
                    const s = try self.sharedObjectMapCache.find(p.path);
                    switch (s.find(e.umapip, p)) {
                        .found => |w| {
                            break :blk try self.allocator.dupe(u8, w.name);
                        },
                        .notfound => break :blk "notfound",
                        .unmapped => break :blk "unmapped",
                    }
                },
            };

            // Create the key base on the symbol we just read
            const key = Key{ .parent = parentId, .symbolHash = hashSymbol(symbol) };

            // See if we can find our node
            const found = self.nodesLookup.get(key);
            if (found) |symbolId| {
                // Hit! Add the total hitcount
                self.nodes.items[symbolId].hitCount += stackItem.hitCount;
                try shadowMap.put(self.allocator, stackId, symbolId);
            } else {
                // Miss! Create the node and append
                try self.nodes.append(self.allocator, TrieNode{
                    // Add the stack items hit ount
                    .hitCount = stackItem.hitCount,
                    .parent = parentId,
                    .payload = blk: switch (stackItem.payload) {
                        .root => break :blk TriePayload{
                            .root = .{
                                // take the symbol we duped earlier, takes ownership!
                                .symbol = symbol,
                            },
                        },
                        .kernel => break :blk TriePayload{
                            .kernel = .{
                                // take the symbol we duped earlier, takes ownership!
                                .symbol = symbol,
                            },
                        },
                        .user => |e| break :blk TriePayload{
                            .user = .{
                                // take the symbol, takes ownership!
                                .symbol = try tryDemangle(self.allocator, symbol),
                                // clone the dll for debug later
                                .dll = try self.allocator.dupe(u8, stacks.umaps.items[e.umapid].path),
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
            }
        }
    }

    pub fn free(self: *SymbolTrie) void {
        for (self.nodes.items) |node| {
            switch (node.payload) {
                .kernel => |s| self.allocator.free(s.symbol),
                .user => |s| {
                    self.allocator.free(s.symbol);
                    self.allocator.free(s.dll);
                },
            }
        }
        self.nodes.deinit(self.allocator);
        self.nodesLookup.deinit(self.allocator);
        self.kmap.deinit(self.allocator);
    }
};
