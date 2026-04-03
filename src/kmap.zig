const std = @import("std");
const InstructionPointer = @import("profile.zig").InstructionPointer;

/// ===================================================================================================================
/// KMap
/// ===================================================================================================================
/// Kernel map entry, essentially a model of one line in /proc/kallsyms
pub const KMapEntryUnmanaged = struct {
    /// Symbol corresponding to the kernel map
    symbol: []const u8,

    /// Instruction pointer corresponding to said symbol
    ip: InstructionPointer,

    /// Free and invalidate
    pub fn deinit(self: *KMapEntryUnmanaged, allocator: std.mem.Allocator) void {
        allocator.free(self.symbol);

        self.* = undefined;
    }

    /// Helper for sorting
    pub fn lessThanFn(_: void, a: KMapEntryUnmanaged, b: KMapEntryUnmanaged) bool {
        return a.ip < b.ip;
    }

    test "KMapEntryUnmanaged.lessThanFn works properly" {
        const items = [_]KMapEntryUnmanaged{
            .{ .ip = 200, .symbol = "b" },
            .{ .ip = 100, .symbol = "a" },
        };
        try std.testing.expect(!std.sort.isSorted(KMapEntryUnmanaged, &items, {}, lessThanFn));
    }
};

/// Model of the symbols in /proc/kallsyms
pub const KMapUnmanaged = struct {
    /// Kernel map, a model of /proc/kallsyms
    backend: std.ArrayListUnmanaged(KMapEntryUnmanaged),

    /// Reads the symbols from /proc/kallsyms to a file, and then clone the relevant information into an internal 
    /// representation. 
    ///
    /// Recommended to use with an arena allocator as there are many smaller allocations taking place to dupe the 
    /// symbols defined in /proc/kallsyms. We cannot use any smart caching here as the symbols are by nature unique.
    pub fn init(allocator: std.mem.Allocator) !KMapUnmanaged {
        std.log.info("Populating kernel map...", .{});

        // Allocate backend, with a huge size
        var backend = try std.ArrayListUnmanaged(KMapEntryUnmanaged).initCapacity(allocator, 128_000);

        {
            // Relates kernel symbols and addresses
            const file = try std.fs.openFileAbsolute("/proc/kallsyms", .{});
            defer file.close();

            // Grab the whole file, note that this file is massive (20 MB+) and this just takes a long time.
            //
            // We assume the kmap static. This likely a big approximation as I believe you can add to it with e.g.
            // eBPF programs! This will just have to be a known limitation because we're not reparsing this.
            const content = try file.readToEndAlloc(allocator, std.math.maxInt(usize));
            defer allocator.free(content);

            // Populate the arraylist with the file contents
            try populate(allocator, &backend, content);
        }

        // I'm pretty sure we don't have to sort it, but I'm gonna do it anyway because our program fails without it
        if (!std.sort.isSorted(KMapEntryUnmanaged, backend.items, {}, KMapEntryUnmanaged.lessThanFn)) {
            sort(backend.items);
        }

        // Optimization to save memory
        backend.shrinkAndFree(allocator, backend.items.len);

        std.log.info("Populating kernel map OK", .{});
        return KMapUnmanaged{
            .backend = backend,
        };
    }

    pub fn deinit(self: *KMapUnmanaged, allocator: std.mem.Allocator) void {
        for (self.backend.items) |*item| item.deinit(allocator);
        self.backend.deinit(allocator);

        self.* = undefined;
    }

    /// Find an entry given an instruction pointer
    pub fn find(self: KMapUnmanaged, ip: InstructionPointer) error{KMapLookupFailure}!KMapEntryUnmanaged {
        // Find the entry strictly larger than our ip, then the correct symbol will be the preceding
        const index = std.sort.upperBound(KMapEntryUnmanaged, self.backend.items, ip, struct {
            fn lessThan(lhs_ip: u64, rhs_map: KMapEntryUnmanaged) std.math.Order {
                if (lhs_ip < rhs_map.ip) return .lt;
                if (lhs_ip > rhs_map.ip) return .gt;
                return .eq;
            }
        }.lessThan);

        // Sort invalid
        if (index == 0) {
            std.log.warn("Failed to lookup KMapEntry with ip: {}", .{ip});
            return error.KMapLookupFailure;
        }

        // We find the upper bound, so one symbol beyond the one we want.
        return self.backend.items[index - 1];
    }

    test "kmap.KMapUnmanaged.find returns correct symbol" {
        std.testing.log_level = .err;
        var backend = std.ArrayListUnmanaged(KMapEntryUnmanaged){};
        defer backend.deinit(std.testing.allocator);
        try backend.appendSlice(std.testing.allocator, &.{
            .{ .ip = 100, .symbol = "a" },
            .{ .ip = 200, .symbol = "b" },
            .{ .ip = 300, .symbol = "c" },
        });

        const kmap = KMapUnmanaged{ .backend = backend };

        try std.testing.expectEqualStrings("b", (try kmap.find(250)).symbol);
        try std.testing.expectEqualStrings("c", (try kmap.find(350)).symbol);
        try std.testing.expectError(error.KMapLookupFailure, kmap.find(50));
    }

    // Helper function that populates the map from the /proc/kallsyms file
    //
    // Works as follows, splits into fields:
    // Note that the line has the following structure:
    //
    // ```
    // 0000000000000000 T srso_alias_untrain_ret<\t>[module]<\t>metadata<\n>
    // <-- 16 chars -->   <-- from index 19 onwards                      -->
    // ```
    //
    fn populate(
        allocator: std.mem.Allocator,
        backend: *std.ArrayListUnmanaged(KMapEntryUnmanaged),
        content: []const u8,
    ) error{ ParseError, OutOfMemory }!void {
        var lines = std.mem.tokenizeScalar(u8, content, '\n');

        // Loop through file contents
        while (lines.next()) |line| {
            // Should never happen, sanity
            if (line.len < 19) {
                return error.ParseError;
            }

            // Grab the address
            const address = std.fmt.parseInt(u64, line[0..16], 16) catch continue;

            // Read the symbol
            var iter = std.mem.splitScalar(u8, line[19..], '\t');
            const symbolString = iter.next() orelse return error.ParseError;

            // Append to our representation
            try backend.append(allocator, KMapEntryUnmanaged{
                .ip = address,
                .symbol = try allocator.dupe(u8, symbolString),
            });
        }
    }

    test "kmap.KMapUnmanaged.populate parses valid kallsyms lines" {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        const aa = arena.allocator();
        var backend = std.ArrayListUnmanaged(KMapEntryUnmanaged){};

        try KMapUnmanaged.populate(aa, &backend, "ffffffff81000000 T _stext\nffffffff81000010 t helper\n");

        try std.testing.expectEqual(backend.items.len, 2);
        try std.testing.expectEqual(backend.items[0].ip, 0xffffffff81000000);
        try std.testing.expectEqualStrings("_stext", backend.items[0].symbol);
    }

    test "kmap.KMapUnmanaged.populate skips short and malformed lines" {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        const aa = arena.allocator();
        var backend = std.ArrayListUnmanaged(KMapEntryUnmanaged){};

        try std.testing.expectError(
            error.ParseError,
            KMapUnmanaged.populate(aa, &backend, "short\n\nZZZZZZZZZZZZZZZZ T bad_hex\n"),
        );

        try std.testing.expectEqual(backend.items.len, 0);
    }

    /// Sorts the map in ascending order for easy binary search
    fn sort(items: []KMapEntryUnmanaged) void {
        // Sort the map so it is easier to search at a later stage
        std.sort.block(KMapEntryUnmanaged, items, {}, KMapEntryUnmanaged.lessThanFn);
    }

    test "kmap.KMapUnmanaged.sort works as expected" {
        var items = [_]KMapEntryUnmanaged{
            .{ .ip = 200, .symbol = "b" },
            .{ .ip = 100, .symbol = "a" },
        };

        KMapUnmanaged.sort(&items);

        try std.testing.expect(items[0].ip == 100);
        try std.testing.expect(std.mem.eql(u8, items[0].symbol, "a"));

        try std.testing.expect(items[1].ip == 200);
        try std.testing.expect(std.mem.eql(u8, items[1].symbol, "b"));
    }
};
