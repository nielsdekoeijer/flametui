const std = @import("std");

const PID = @import("typesystem.zig").PID;
const InstructionPointer = @import("typesystem.zig").InstructionPointer;

const UMapEntry = @import("umap.zig").UMapEntry;
const UMapCache = @import("umap.zig").UMapCache;
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
        /// Coming from the kernel stack
        kernel,
        /// Coming from the userspace stack
        user,
    };

    /// What we store in a trie for a given a root stack frame
    pub const RTriePayload = void;

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
        root: RTriePayload,
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
    pub const Key = struct { pid: PID, parent: NodeId, ip: InstructionPointer, kind: TrieKind };

    /// Caches umaps we have see. Essentially, each time we encounter a new umap we serialize it to an internal
    /// datastructure. This is expensive, so we cache it. The key to find the umap is the pid.
    /// TODO: processes can die, then another process can receive its pid. We don't account for this currently
    umapCache: UMapCache,

    /// Contains the entries of the umaps that are in the trie. This is indexed by the UmapId. After resolving a
    /// UMapEntry from the UMapCache, we place a copy in this umaps, owning a copy of it. This is critical because
    /// our UMapCache may choose to unload a umap for a given pid if it dies.
    umaps: std.ArrayListUnmanaged(UMapEntry),

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
            .umapCache = try UMapCache.init(allocator),
            .umaps = try std.ArrayListUnmanaged(UMapEntry).initCapacity(allocator, 0),
            .nodes = nodes,
            .nodesLookup = try std.AutoArrayHashMapUnmanaged(Key, NodeId).init(
                allocator,
                &[_]Key{},
                &[_]NodeId{},
            ),
            .allocator = allocator,
        };
    }

    /// Adds an event to the trie
    pub fn add(self: *StackTrie, event: EventType) !void {
        const pid = @as(PID, @intCast(event.pid));

        // A stack trace starts at the root.
        var parent: NodeId = RootId;

        // Each node comes from the parent node. Thus, we increment its hit count
        self.nodes.items[RootId].hitCount += 1;

        // Resolve user stack frames. We consider them in reverse as that is the one closest to the root node.
        var i = event.uips.len;
        while (i > 0) {
            i -= 1;

            // Grab the userspace instruction pointer
            const ip = event.uips[i];

            // Build key
            const key = Key{
                .kind = .user,
                .pid = pid,
                .parent = parent,
                .ip = ip,
            };

            // Check if key exists
            const found = self.nodesLookup.get(key);
            if (found) |index| {
                // Hit! Update hitcount of parent that was found
                self.nodes.items[index].hitCount += 1;

                // Update parent to self for next node
                parent = @intCast(index);
            } else {
                // Miss! Grab a reference to the UMap, then use the instruction pointer to find the UMapEntry
                const umap: *UMapUnmanaged = try self.umapCache.find(pid);
                const item: UMapEntry = switch (umap.find(ip)) {
                    // If the entry exists in the map, great, clone it
                    .found => |it| try it.clone(self.allocator),
                    // Else return a fixed map
                    .notfound => try UMapUnmanaged.UMapEntryUnmapped.clone(self.allocator),
                    .unmapped => try UMapUnmanaged.UMapEntryUnmapped.clone(self.allocator),
                };

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
            const key = Key{
                .kind = .kernel,
                .pid = pid,
                .parent = parent,
                .ip = ip,
            };

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

    pub fn free(self: *StackTrie) void {
        self.umapCache.deinit();
        for (self.umaps.items) |umap| umap.deinit(self.allocator);
        self.umaps.deinit(self.allocator);
        self.nodes.deinit(self.allocator);
        self.nodesLookup.deinit(self.allocator);
    }
};
