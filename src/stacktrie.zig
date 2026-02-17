const std = @import("std");

const PID = @import("profile.zig").PID;
const TID = @import("profile.zig").TID;
const InstructionPointer = @import("profile.zig").InstructionPointer;

const UMapEntryUnmanaged = @import("umap.zig").UMapEntryUnmanaged;
const UMapCacheUnmanaged = @import("umap.zig").UMapCacheUnmanaged;
const UMapUnmanaged = @import("umap.zig").UMapUnmanaged;

const EventType = @import("profile.zig").EventType;

/// ===================================================================================================================
/// StackTrie
/// ===================================================================================================================
/// Trie for tracking incoming stacktraces. The design here is meant to be quite minimal. When a stack trace comes in,
/// we want to handle it as fast as we can to not conjest the ringbuffer. However, in order to properly handle short
/// running programs we have to do some resolution as fast as possible. This is because if a program dies, we lose
/// the ability to resolve instruction pointers. Of course, there is still a chance the process dies before we can
/// resolve it. The design must thus be robust against that.
///
/// Note that we DONT resolve symbols until later. This is also quite expensive. We only read the map file in
/// /proc/*/maps. This stores what shared object contains the line of code. We don't resolve the symbol from said
/// shared object.
///
/// We store it in a `trie`, which is essentially a tree with a path from the bottom to the top.
pub const StackTrie = struct {
    /// Identifier to identify a node
    pub const UMapId = u32;

    /// Identifier to identify a node
    pub const NodeId = u32;

    /// The different entry types in our stack trie
    const TrieKind = enum {
        /// Should only have one of these
        root,
        /// Name of proc
        comm,
        /// The pid
        pid,
        /// The tid
        tid,
        /// Coming from the kernel stack
        kernel,
        /// Coming from the userspace stack
        user,
    };

    /// What we store in a trie for a given kernel stack frame
    pub const KTriePayload = struct {
        // location in the kernel map
        kmapip: InstructionPointer,
    };

    /// What we store in a trie for a given userspace stack frame
    pub const UTriePayload = struct {
        // location in the userspace map, when
        umapip: InstructionPointer,

        umapid: UMapId,
    };

    /// Trie union, datatype we store in the trie
    pub const TriePayload = union(TrieKind) {
        root: void,
        comm: []const u8,
        pid: PID,
        tid: TID,
        kernel: KTriePayload,
        user: UTriePayload,
    };

    /// Node in the trie
    pub const TrieNode = struct {
        hitCount: u64,
        parent: NodeId,
        payload: TriePayload,
    };

    /// Where we can find the root node. Should be only one of these in a given trie.
    pub const RootId: NodeId = 0;

    /// Key used for our trie, describes a node uniquely. We also store the kind in case of a degenerate corner case
    /// for a userspace and kernespace instruction pointer collision. Probably the heatdeath of the universe comes
    /// first though.
    pub const Key = struct { pid: PID, tid: TID, parent: NodeId, ip: InstructionPointer, kind: TrieKind };

    /// Contains the entries of the umaps that are in the trie. This is indexed by the UmapId. After resolving a
    /// UMapEntryUnmanaged from the UMapCacheUnmanaged, we place a copy in this umaps, owning a copy of it. This is critical because
    /// our UMapCacheUnmanaged may choose to unload a umap for a given pid if it dies.
    umaps: std.ArrayListUnmanaged(UMapEntryUnmanaged),

    /// The underlying trie of nodes stored as a flat array. The root node is always the first entry.
    nodes: std.ArrayListUnmanaged(TrieNode),

    /// Maps keys to indices in `nodes`.
    nodesLookup: std.AutoArrayHashMapUnmanaged(Key, NodeId),

    /// Store our allocator, not unmanaged.
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) !StackTrie {
        var nodes = try std.ArrayListUnmanaged(TrieNode).initCapacity(allocator, 1024);

        // Initialize the root
        try nodes.append(allocator, .{
            // Starts at zero, but incremented by children
            .hitCount = 0,
            // Parent is ourselves, only reserved index
            .parent = RootId,
            .payload = .root,
        });

        return StackTrie{
            .umaps = try std.ArrayListUnmanaged(UMapEntryUnmanaged).initCapacity(allocator, 1024),
            .nodes = nodes,
            .nodesLookup = try std.AutoArrayHashMapUnmanaged(Key, NodeId).init(
                allocator,
                &[_]Key{},
                &[_]NodeId{},
            ),
            .allocator = allocator,
        };
    }

    test "init creates root node" {
        var trie = try StackTrie.init(std.testing.allocator);
        defer trie.deinit();

        try std.testing.expectEqual(1, trie.nodes.items.len);
        try std.testing.expectEqual(0, trie.nodes.items[StackTrie.RootId].hitCount);
        try std.testing.expectEqual(StackTrie.RootId, trie.nodes.items[StackTrie.RootId].parent);
    }

    /// Adds an event to the trie
    pub fn add(self: *StackTrie, event: EventType, umapCache: *UMapCacheUnmanaged) !void {
        const pid = @as(PID, @intCast(event.pid));
        const tid = @as(TID, @intCast(event.tid));

        // Obtain the umap
        const umap = try umapCache.find(self.allocator, pid);
        const comm = switch (umap.*) {
            .loaded => |u| u.name,
            .zombie => "nocomm",
        };

        // A stack trace starts at the root.
        var parent: NodeId = RootId;

        // Each node comes from the parent node. Thus, we increment its hit count
        self.nodes.items[RootId].hitCount += 1;

        // Next, we add the comm node
        {
            const key = Key{ .kind = .comm, .pid = pid, .tid = tid, .parent = parent, .ip = 0 };

            const found = self.nodesLookup.get(key);
            if (found) |index| {
                // Hit! Update hitcount of parent that was found
                self.nodes.items[index].hitCount += 1;

                // Update parent to self for next node
                parent = @intCast(index);
            } else {
                // Add a new node
                try self.nodes.append(self.allocator, TrieNode{
                    .hitCount = 1,
                    .parent = parent,
                    .payload = TriePayload{
                        .comm = try self.allocator.dupe(u8, comm),
                    },
                });

                // We compute the NodeId from the length of the node list
                const nodeId: NodeId = @intCast(self.nodes.items.len - 1);

                // Add the id to the hash map for the given key
                try self.nodesLookup.put(self.allocator, key, nodeId);

                // Update parent to be new node
                parent = nodeId;
            }
        }

        // Next, we add the pid node
        {
            const key = Key{ .kind = .pid, .pid = pid, .tid = tid, .parent = parent, .ip = 0 };

            const found = self.nodesLookup.get(key);
            if (found) |index| {
                // Hit! Update hitcount of parent that was found
                self.nodes.items[index].hitCount += 1;

                // Update parent to self for next node
                parent = @intCast(index);
            } else {
                // Add a new node
                try self.nodes.append(self.allocator, TrieNode{
                    .hitCount = 1,
                    .parent = parent,
                    .payload = TriePayload{
                        .pid = pid,
                    },
                });

                // We compute the NodeId from the length of the node list
                const nodeId: NodeId = @intCast(self.nodes.items.len - 1);

                // Add the id to the hash map for the given key
                try self.nodesLookup.put(self.allocator, key, nodeId);

                // Update parent to be new node
                parent = nodeId;
            }
        }

        // Next, we add the tid node
        {
            const key = Key{ .kind = .tid, .pid = pid, .tid = tid, .parent = parent, .ip = 0 };

            const found = self.nodesLookup.get(key);
            if (found) |index| {
                // Hit! Update hitcount of parent that was found
                self.nodes.items[index].hitCount += 1;

                // Update parent to self for next node
                parent = @intCast(index);
            } else {
                // Add a new node
                try self.nodes.append(self.allocator, TrieNode{
                    .hitCount = 1,
                    .parent = parent,
                    .payload = TriePayload{
                        .tid = tid,
                    },
                });

                // We compute the NodeId from the length of the node list
                const nodeId: NodeId = @intCast(self.nodes.items.len - 1);

                // Add the id to the hash map for the given key
                try self.nodesLookup.put(self.allocator, key, nodeId);

                // Update parent to be new node
                parent = nodeId;
            }
        }
        // Resolve user stack frames. We consider them in reverse as that is the one closest to the root node.
        var i = event.uips.len;
        while (i > 0) {
            i -= 1;

            // Grab the userspace instruction pointer
            const ip = event.uips[i];

            // Build key
            const key = Key{ .kind = .user, .pid = pid, .tid = tid, .parent = parent, .ip = ip };

            // Check if key exists
            const found = self.nodesLookup.get(key);
            if (found) |index| {
                // Hit! Update hitcount of parent that was found
                self.nodes.items[index].hitCount += 1;

                // Update parent to self for next node
                parent = @intCast(index);
            } else {
                // Miss! Grab a reference to the UMap, then use the instruction pointer to find the UMapEntryUnmanaged
                var item: UMapEntryUnmanaged = switch (umap.*) {
                    .loaded => |entry| if (try entry.findAndDupe(self.allocator, ip)) |e|
                        e
                    else
                        UMapEntryUnmanaged{
                            .path = try self.allocator.dupe(u8, "not found"),
                            .offset = 0,
                            .addressBeg = 0,
                            .addressEnd = 0,
                        },

                    // TODO: we flatten our typesystem here, can be improved
                    .zombie => UMapEntryUnmanaged{
                        .path = try self.allocator.dupe(u8, "zombie"),
                        .offset = 0,
                        .addressBeg = 0,
                        .addressEnd = 0,
                    },
                };

                errdefer item.deinit(self.allocator);

                // Append it to self
                try self.umaps.append(self.allocator, item);

                // We compute the UmapId from the length of the node list
                const umapId: UMapId = @intCast(self.umaps.items.len - 1);

                // Add a new node
                try self.nodes.append(self.allocator, TrieNode{
                    .hitCount = 1,
                    .parent = parent,
                    .payload = TriePayload{
                        .user = .{
                            .umapip = ip,
                            .umapid = umapId,
                        },
                    },
                });

                // We compute the NodeId from the length of the node list
                const nodeId: NodeId = @intCast(self.nodes.items.len - 1);

                // Add the id to the hash map for the given key
                try self.nodesLookup.put(self.allocator, key, nodeId);

                // Update parent to be new node
                parent = nodeId;
            }
        }

        // Resolve kernel stack frames
        var j = event.kips.len;
        while (j > 0) {
            j -= 1;

            // Grab the kernel instruction pointer
            const ip = event.kips[j];

            // Build the key
            const key = Key{ .kind = .kernel, .pid = pid, .tid = tid, .parent = parent, .ip = ip };

            // Check if key exists
            const found = self.nodesLookup.get(key);
            if (found) |index| {
                // Hit! Update hitcount of parent that was found
                self.nodes.items[index].hitCount += 1;

                // Update parent to self for next node
                parent = @intCast(index);
            } else {
                // Miss! Make the node and append it
                try self.nodes.append(self.allocator, TrieNode{
                    .hitCount = 1,
                    .parent = parent,
                    .payload = TriePayload{
                        .kernel = .{
                            .kmapip = ip,
                        },
                    },
                });

                // We compute the NodeId from the length of the node list
                const nodeId: NodeId = @intCast(self.nodes.items.len - 1);

                // Add the id to the hash map for the given key
                try self.nodesLookup.put(self.allocator, key, nodeId);

                // Update parent to be new node
                parent = nodeId;
            }
        }
    }

    test "stacktrie.StackTrie add kernel-only event creates correct trie structure" {
        var trie = try StackTrie.init(std.testing.allocator);
        defer trie.deinit();

        var cache = try UMapCacheUnmanaged.init(std.testing.allocator);
        defer cache.deinit(std.testing.allocator);

        const event = EventType{
            .pid = 1,
            .tid = 0,
            .timestamp = 0,
            .uips = &[_]u64{},
            .kips = &[_]u64{ 0xAAAA, 0xBBBB },
        };

        try trie.add(event, &cache);

        // root + 2 kernel frames + pid/tid/comm
        try std.testing.expectEqual(6, trie.nodes.items.len);
        try std.testing.expectEqual(1, trie.nodes.items[StackTrie.RootId].hitCount);

        // Deepest kernel frame (0xBBBB, added first since reversed) is child of root
        try std.testing.expectEqual(StackTrie.RootId, trie.nodes.items[1].parent);
        try std.testing.expectEqual(0xBBBB, trie.nodes.items[4].payload.kernel.kmapip);

        // 0xAAAA is child of 0xBBBB's node
        try std.testing.expectEqual(1, trie.nodes.items[2].parent);
        try std.testing.expectEqual(0xAAAA, trie.nodes.items[5].payload.kernel.kmapip);
    }

    test "stacktrie.StackTrie add duplicate kernel event increments hit counts" {
        var trie = try StackTrie.init(std.testing.allocator);
        defer trie.deinit();

        var cache = try UMapCacheUnmanaged.init(std.testing.allocator);
        defer cache.deinit(std.testing.allocator);

        const event = EventType{
            .pid = 1,
            .tid = 0,
            .timestamp = 0,
            .uips = &[_]u64{},
            .kips = &[_]u64{0xAAAA},
        };

        try trie.add(event, &cache);
        try trie.add(event, &cache);

        // Still only root + 1 kernel node (deduped) + pid/tid/comm
        try std.testing.expectEqual(5, trie.nodes.items.len);
        try std.testing.expectEqual(2, trie.nodes.items[StackTrie.RootId].hitCount);
        try std.testing.expectEqual(2, trie.nodes.items[4].hitCount);
    }

    test "stacktrie.StackTrie different PIDs create distinct nodes for same IP" {
        var trie = try StackTrie.init(std.testing.allocator);
        defer trie.deinit();

        var cache = try UMapCacheUnmanaged.init(std.testing.allocator);
        defer cache.deinit(std.testing.allocator);

        for ([_]u64{ 1, 2 }) |pid| {
            try trie.add(.{ .pid = pid, .tid = 0, .timestamp = 0, .uips = &[_]u64{}, .kips = &[_]u64{0xAAAA} }, &cache);
        }

        // root + 2 separate kernel nodes + pid/tid/comm each
        try std.testing.expectEqual(9, trie.nodes.items.len);
        try std.testing.expectEqual(2, trie.nodes.items[StackTrie.RootId].hitCount);
    }

    /// Remove all entries, but keep root node
    pub fn reset(self: *StackTrie) void {
        for (self.nodes.items[1..]) |node| {
            switch (node.payload) {
                .comm => |s| self.allocator.free(s),
                else => {},
            }
        }

        // We keep the root node (index 0) alive, but reset its hit count.
        self.nodes.shrinkRetainingCapacity(1);
        self.nodes.items[RootId].hitCount = 0;

        // Keep allocation, but clear entries
        self.nodesLookup.clearRetainingCapacity();

        // Keep allocation, but clear entries
        for (self.umaps.items) |*entry| entry.deinit(self.allocator);
        self.umaps.clearRetainingCapacity();
    }

    test "stacktrie.StackTrie reset preserves root, clears everything else" {
        var trie = try StackTrie.init(std.testing.allocator);
        defer trie.deinit();

        // Manually add a dummy node to simulate state
        try trie.nodes.append(std.testing.allocator, .{
            .hitCount = 5,
            .parent = StackTrie.RootId,
            .payload = .{ .kernel = .{ .kmapip = 0xdead } },
        });

        trie.nodes.items[StackTrie.RootId].hitCount = 10;

        trie.reset();

        try std.testing.expectEqual(1, trie.nodes.items.len);
        try std.testing.expectEqual(0, trie.nodes.items[StackTrie.RootId].hitCount);
        try std.testing.expectEqual(0, trie.nodesLookup.count());
        try std.testing.expectEqual(0, trie.umaps.items.len);
    }

    pub fn deinit(self: *StackTrie) void {
        for (self.nodes.items) |node| {
            switch (node.payload) {
                .comm => |s| self.allocator.free(s),
                else => {},
            }
        }
        for (self.umaps.items) |*umap| umap.deinit(self.allocator);
        self.umaps.deinit(self.allocator);
        self.nodes.deinit(self.allocator);
        self.nodesLookup.deinit(self.allocator);
    }
};
