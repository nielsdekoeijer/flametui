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
/// TODO: confirm that this one is static, do we need a cache and check for invalidation?
/// TODO: write unit tests
pub const KMapUnmanaged = struct {
    /// Kernel map, a model of /proc/kallsyms
    backend: std.ArrayListUnmanaged(KMapEntry),

    pub fn init(allocator: std.mem.Allocator) !KMapUnmanaged {
        // Allocate backend
        var backend = try std.ArrayListUnmanaged(KMapEntry).initCapacity(allocator, 0);
        errdefer {
            for (backend.items) |entry| allocator.free(entry.symbol);
            backend.deinit(allocator);
        }

        // Relates kernel symbols and addresses
        const file = try std.fs.openFileAbsolute("/proc/kallsyms", .{});
        defer file.close();

        // Read the file
        var buf: [64 * 1024]u8 = undefined;
        var reader = file.reader(&buf);

        // Populate + sort
        try populate(allocator, &backend, &reader.interface);
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
    fn populate(allocator: std.mem.Allocator, backend: *std.ArrayListUnmanaged(KMapEntry), reader: *std.Io.Reader) !void {
        // Loop through file contents
        while (true) {
            // Read until we cannot take more lines --> implies EOF
            var line = reader.takeDelimiterExclusive('\n') catch break;

            // Remove carriage returns
            line = @constCast(std.mem.trim(u8, line, "\r\t "));

            // Split into fields.
            // Note that the line has the following structure:
            //
            // ```
            // 0000000000000000 T srso_alias_untrain_ret
            // ```
            var iter = std.mem.splitAny(u8, line, " \t");

            // Grab the address
            const addressString = iter.next() orelse continue;
            const address = std.fmt.parseInt(u64, addressString, 16) catch continue;

            // Skip the type
            const @"type" = iter.next();
            _ = @"type";

            // Read the symbol, duplicate our own copy
            const symbolString = iter.next() orelse continue;

            // Note: theres a chance there's another field, like [i915] or [bpf]. I just toss that now. I think
            // its the kernel module the call belongs to? Maybe this is intreesting to store. 
            // TODO: decide if to store, does make symbol resolution slower...

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
