const std = @import("std");
const InstructionPointer = @import("typesystem.zig").InstructionPointer;

/// ===================================================================================================================
/// KMap
/// ===================================================================================================================
/// Kernel map entry, essentially a model of one line in /proc/kallsyms
pub const KMapEntry = struct {
    /// Symbol corresponding to the kernel map
    symbol: []const u8,
    /// Instruction pointer corresponding to said symbol
    ip: InstructionPointer,
};

/// Model of the symbols in /proc/kallsyms
/// TODO: write unit tests
pub const KMapUnmanaged = struct {
    /// Kernel map, a model of /proc/kallsyms
    backend: std.ArrayListUnmanaged(KMapEntry),

    // TODO: this is kind of a hack to make the non-recording workflow boot faster. Probably we can do better.
    // Basically, we conflate the logic in the SymbolTrie to "need" a kmap for the "add" function. The thing is,
    // when we load from file we don't need to "add" shit, so probably I should have another type entirely
    pub fn initEmpty(allocator: std.mem.Allocator) !KMapUnmanaged {
        return KMapUnmanaged{
            .backend = try std.ArrayListUnmanaged(KMapEntry).initCapacity(allocator, 0),
        };
    }

    pub fn init(allocator: std.mem.Allocator) !KMapUnmanaged {
        // Allocate backend, with a huge size
        var backend = try std.ArrayListUnmanaged(KMapEntry).initCapacity(allocator, 512_000);
        errdefer {
            for (backend.items) |entry| allocator.free(entry.symbol);
            backend.deinit(allocator);
        }

        // Relates kernel symbols and addresses
        const file = try std.fs.openFileAbsolute("/proc/kallsyms", .{});
        defer file.close();

        // Grab the whole file, note that this file is massive (20 MB+) and this just takes a long time.
        // We assume the kmap static. This likely a big approximation. 
        const content = try file.readToEndAlloc(allocator, std.math.maxInt(usize));
        defer allocator.free(content);

        // Populate + sort
        try populate(allocator, &backend, content);

        // I'm pretty sure we don't have to sort it, but I'm gonna do it anyway
        sort(&backend);

        return KMapUnmanaged{
            .backend = backend,
        };
    }

    /// Find an entry given an instruction pointer
    pub fn find(self: KMapUnmanaged, ip: InstructionPointer) !KMapEntry {
        // Find the entry strictly larger than our ip, then the correct symbol will be the preceding
        const index = std.sort.upperBound(KMapEntry, self.backend.items, ip, struct {
            fn lessThan(lhs_ip: u64, rhs_map: KMapEntry) std.math.Order {
                if (lhs_ip < rhs_map.ip) return .lt;
                if (lhs_ip > rhs_map.ip) return .gt;
                return .eq;
            }
        }.lessThan);

        // Sort invalid
        if (index == self.backend.items.len or index == 0) {
            std.log.err("Failed to lookup KMap with ip: {}", .{ip});
            return error.KMapEntryLookupFailure;
        }

        // We find the upper bound, so one symbol beyond the one we want.
        return self.backend.items[index - 1];
    }

    pub fn deinit(self: *KMapUnmanaged, allocator: std.mem.Allocator) void {
        for (self.backend.items) |item| allocator.free(item.symbol);
        self.backend.deinit(allocator);
    }

    // Helper function that populates the map
    // Works as follows, splits into fields:
    // Note that the line has the following structure:
    //
    // ```
    // 0000000000000000 T srso_alias_untrain_ret<\t>[module]<\t>metadata<\n>
    // <-- 16 chars -->   <-- from index 19 onwards                      -->
    // ```
    //
    fn populate(allocator: std.mem.Allocator, backend: *std.ArrayListUnmanaged(KMapEntry), content: []const u8) !void {
        var lines = std.mem.tokenizeScalar(u8, content, '\n');

        // Loop through file contents
        while (lines.next()) |line| {

            // Grab the address
            const address = std.fmt.parseInt(u64, line[0..16], 16) catch continue;

            // Read the symbol, duplicate our own copy
            var iter = std.mem.splitScalar(u8, line[19..], '\t');
            const symbolString = iter.next() orelse continue;

            // Append to our representation
            // Note that we own the memory, and thus must clean it
            try backend.append(allocator, KMapEntry{
                .ip = address,
                .symbol = try allocator.dupe(u8, symbolString),
            });
        }
    }

    /// Sorts the map in ascending order for easy binary search
    fn sort(backend: *std.ArrayListUnmanaged(KMapEntry)) void {
        // Sort the map so it is easier to search at a later stage
        std.sort.block(KMapEntry, backend.items, {}, struct {
            fn lessThan(_: void, a: KMapEntry, b: KMapEntry) bool {
                return a.ip < b.ip;
            }
        }.lessThan);
    }
};
