const std = @import("std");
const PID = @import("profile.zig").PID;
const InstructionPointer = @import("profile.zig").InstructionPointer;

/// ===================================================================================================================
/// UMap
/// ===================================================================================================================
/// UMaps are expensive to load and also can be invalidated, thus we have a cache. This class is a map between PID
/// and UMap.
///
/// TODO: PIDs can die. Currently we do not have any logic to handle this. I think we should allow PIDs to be
/// invalidated, so that should probably be a method on this class. When invalidated YET used again, we need to
/// trigger a reload. Current risk is that the memory of the program keeps growing while measuring.
pub const UMapCache = struct {
    backend: std.AutoArrayHashMapUnmanaged(PID, UMapUnmanaged),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) !UMapCache {
        const backend = try std.AutoArrayHashMapUnmanaged(PID, UMapUnmanaged).init(
            allocator,
            &[_]PID{},
            &[_]UMapUnmanaged{},
        );

        return UMapCache{
            .allocator = allocator,
            .backend = backend,
        };
    }

    /// Return entry given pid, or create it
    pub fn find(self: *UMapCache, pid: PID) !*UMapUnmanaged {
        // Try to find it
        {
            const found = self.backend.getPtr(pid);
            if (found) |m| {
                return m;
            }
        }

        // If not found, create one.
        const map = try UMapUnmanaged.init(self.allocator, pid);
        try self.backend.put(self.allocator, pid, map);

        // Find it
        {
            const found = self.backend.getPtr(pid);
            if (found) |m| {
                return m;
            }
        }

        // Fail unreachable, we just added it
        unreachable;
    }

    pub fn deinit(self: *UMapCache) void {
        for (self.backend.values()) |*entry| {
            switch (entry.*) {
                .loaded => |*item| item.deinit(self.allocator),
                else => {},
            }
        }

        self.backend.deinit(self.allocator);

        self.* = undefined;
    }
};

/// Userspace process map entry, essentially a model of a line in /proc/*/maps.
pub const UMapEntry = struct {
    /// File path to the dll
    path: []const u8,

    /// Offset relative to the root of the dll for address range
    offset: u64,

    /// Beginning of the address range
    addressBeg: u64,

    /// Ending of the address range
    addressEnd: u64,

    /// Deep copy
    pub fn clone(self: UMapEntry, allocator: std.mem.Allocator) !UMapEntry {
        return UMapEntry{
            .path = try allocator.dupe(u8, self.path),
            .offset = self.offset,
            .addressBeg = self.addressBeg,
            .addressEnd = self.addressEnd,
        };
    }

    test "umap.UMapEntry.clone produces independent copy" {
        const original = UMapEntry{
            .path = "original",
            .offset = 0x1000,
            .addressBeg = 0xA000,
            .addressEnd = 0xB000,
        };

        var cloned = try original.clone(std.testing.allocator);
        defer cloned.deinit(std.testing.allocator);

        try std.testing.expectEqualStrings("original", cloned.path);
        try std.testing.expectEqual(0x1000, cloned.offset);

        // Ensure different allocation
        try std.testing.expect(cloned.path.ptr != original.path.ptr);
    }

    pub fn deinit(self: *UMapEntry, allocator: std.mem.Allocator) void {
        allocator.free(self.path);

        self.* = undefined;
    }
};

pub const UMapUnmanaged = union(enum) {
    loaded: struct {
        backend: std.ArrayListUnmanaged(UMapEntry),

        pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
            for (self.backend.items) |item| {
                allocator.free(item.path);
            }

            self.backend.deinit(allocator);

            self.* = undefined;
        }

        /// Find an entry given an instruction pointer.
        pub fn find(self: @This(), ip: InstructionPointer) ?UMapEntry {
            // Find the entry strictly larger than our ip, then the correct symbol will be the preceding
            const index = std.sort.upperBound(UMapEntry, self.backend.items, ip, struct {
                fn lessThan(lhs_ip: u64, rhs_map: UMapEntry) std.math.Order {
                    if (lhs_ip < rhs_map.addressBeg) return .lt;
                    if (lhs_ip > rhs_map.addressBeg) return .gt;
                    return .eq;
                }
            }.lessThan);

            // Ensure sane output
            if (index == 0) return null;
            if (self.backend.items[index - 1].addressEnd < ip) return null;
            return self.backend.items[index - 1];
        }

        test "umap.UMapUnmanaged.loaded.find returns correct entry for IP in range" {
            var backend = std.ArrayListUnmanaged(UMapEntry){};
            defer {
                for (backend.items) |item| std.testing.allocator.free(item.path);
                backend.deinit(std.testing.allocator);
            }

            try backend.append(std.testing.allocator, .{
                .addressBeg = 0x1000,
                .addressEnd = 0x2000,
                .offset = 0,
                .path = try std.testing.allocator.dupe(u8, "/lib/a.so"),
            });
            try backend.append(std.testing.allocator, .{
                .addressBeg = 0x3000,
                .addressEnd = 0x4000,
                .offset = 0x100,
                .path = try std.testing.allocator.dupe(u8, "/lib/b.so"),
            });

            const umap = UMapUnmanaged{
                .internal = .{ .loaded = .{ .backend = backend } },
            };

            switch (umap.find(0x1500)) {
                .found => |entry| try std.testing.expectEqual(0x1000, entry.addressBeg),
                else => return error.TestUnexpectedResult,
            }

            switch (umap.find(0x3500)) {
                .found => |entry| try std.testing.expectEqual(0x3000, entry.addressBeg),
                else => return error.TestUnexpectedResult,
            }
        }

        test "umap.UMapUnmanaged.loaded.find returns notfound for IP in gap between ranges" {
            var backend = std.ArrayListUnmanaged(UMapEntry){};
            defer {
                for (backend.items) |item| std.testing.allocator.free(item.path);
                backend.deinit(std.testing.allocator);
            }

            try backend.append(std.testing.allocator, .{
                .addressBeg = 0x1000,
                .addressEnd = 0x2000,
                .offset = 0,
                .path = try std.testing.allocator.dupe(u8, "/lib/a.so"),
            });

            const umap = UMapUnmanaged{
                .internal = .{ .loaded = .{ .backend = backend } },
            };

            switch (umap.find(0x2500)) {
                .notfound => {},
                else => return error.TestUnexpectedResult,
            }
        }
    },

    zombie: struct {},

    pub fn init(allocator: std.mem.Allocator, pid: PID) !UMapUnmanaged {
        std.log.info("Creating UMap with pid {}...", .{pid});

        // Allocate backend
        var backend = try std.ArrayListUnmanaged(UMapEntry).initCapacity(allocator, 0);
        errdefer {
            for (backend.items) |entry| allocator.free(entry.path);
            backend.deinit(allocator);
        }

        // Open a file to /proc/*/maps
        const file = blk: {
            // NOTE: we are bounding the length of our path to be 256 here, probably sufficient.
            var pathBuffer: [256]u8 = undefined;
            const path = try std.fmt.bufPrint(&pathBuffer, "/proc/{}/maps", .{pid});

            // It can happen that while we're starting, a process dies. Then we can't load it. In which case we
            // return this "unloaded".
            break :blk std.fs.openFileAbsolute(path, .{}) catch return .zombie;
        };
        defer file.close();

        // Read the whole file in 1 go
        const content = file.readToEndAlloc(allocator, std.math.maxInt(usize)) catch return .zombie;
        defer allocator.free(content);

        // Reader for said file contents
        var fbs = std.Io.Reader.fixed(content);

        // Populate internals + sort based on instruction pointer enabling binary search. Because we rather show
        // the user something rather than nothing, for now return an unmapped instance.
        try populate(allocator, &backend, &fbs);
        sort(&backend);

        std.log.info("Creating UMap with pid {} OK", .{pid});
        return .{
            .loaded = .{
                .backend = backend,
            },
        };
    }

    /// Sorts the map in ascending order for binary search
    fn sort(backend: *std.ArrayListUnmanaged(UMapEntry)) void {
        // Sort the map so it is easier to search at a later stage
        std.sort.block(UMapEntry, backend.items, {}, struct {
            fn lessThan(_: void, a: UMapEntry, b: UMapEntry) bool {
                return a.addressBeg < b.addressBeg;
            }
        }.lessThan);
    }

    fn populate(allocator: std.mem.Allocator, backend: *std.ArrayListUnmanaged(UMapEntry), reader: anytype) !void {
        // Loop over file contents
        while (true) {
            // Read until we cannot take more lines --> implies EOF
            const line = reader.takeDelimiterExclusive('\n') catch break;

            // Split by space.
            // Note that the line has the following structure:
            //
            // ```
            // 7f6687c76000-7f6687c77000 rw-p 00003000 103:02 19296183                  /path/to/prog0
            // 7f6687c77000-7f6687c79000 r--p 00000000 103:02 19553864                  /path/to/prog1
            // 7f6687c79000-7f6687c7c000 r-xp 00002000 103:02 19553864                  /path/to/prog2
            // ```
            var line_iter = std.mem.tokenizeAny(u8, line, " ");

            // Map address range
            const map = line_iter.next() orelse return error.UMapParseError;
            var map_iter = std.mem.splitScalar(u8, map, '-');
            const map_beg_string = map_iter.next() orelse return error.UMapParseError;
            const map_end_string = map_iter.next() orelse return error.UMapParseError;
            const map_beg = try std.fmt.parseInt(u64, map_beg_string, 16);
            const map_end = try std.fmt.parseInt(u64, map_end_string, 16);

            // Skip perms, aren't interesting currently
            const perms = line_iter.next() orelse return error.UMapParseError;
            _ = perms;

            // Get offset
            const offset_string = line_iter.next() orelse return error.UMapParseError;
            const offset = try std.fmt.parseInt(u64, offset_string, 16);

            // Skip device, aren't interesting currently
            const device = line_iter.next() orelse return error.UMapParseError;
            _ = device;

            // Skip inode, aren't interesting currently
            const inode = line_iter.next() orelse return error.UMapParseError;
            _ = inode;

            // Take dll path
            const dll_path = line_iter.rest();

            const owned_path = try allocator.dupe(u8, dll_path);
            errdefer allocator.free(owned_path);
            try backend.append(allocator, .{
                .addressBeg = map_beg,
                .addressEnd = map_end,
                .offset = offset,
                .path = owned_path,
            });
        }
    }

    test "umap.UMapUnmanaged.populate parses valid /proc/pid/maps lines" {
        const input =
            "7f6687c76000-7f6687c77000 rw-p 00003000 103:02 19296183                   /usr/lib/libc.so.6\n" ++
            "7f6687c77000-7f6687c79000 r--p 00000000 103:02 19553864                   /usr/lib/ld-linux.so\n";

        var backend = std.ArrayListUnmanaged(UMapEntry){};
        defer {
            for (backend.items) |item| std.testing.allocator.free(item.path);
            backend.deinit(std.testing.allocator);
        }

        var reader = std.Io.Reader.fixed(input);
        try UMapUnmanaged.populate(std.testing.allocator, &backend, &reader);

        try std.testing.expectEqual(2, backend.items.len);
        try std.testing.expectEqual(0x7f6687c76000, backend.items[0].addressBeg);
        try std.testing.expectEqual(0x7f6687c77000, backend.items[0].addressEnd);
        try std.testing.expectEqual(0x3000, backend.items[0].offset);
    }

    test "umap.UMapUnmanaged.populate handles empty input" {
        var backend = std.ArrayListUnmanaged(UMapEntry){};
        defer backend.deinit(std.testing.allocator);

        var reader = std.Io.Reader.fixed("");
        try UMapUnmanaged.populate(std.testing.allocator, &backend, &reader);

        try std.testing.expectEqual(0, backend.items.len);
    }
};

// /// Model of the symbols in /proc/*/maps
// pub const UMapUnmanaged2 = struct {
//     // The members of this struct is represented by a tagged union. Loaded means we're ready to return symbols,
//     // unmapped means we for whatever reason couldnt read the /proc/*/maps file. We can likely become more robust
//     // by having more entries here.
//     const Internal = union(enum) {
//         loaded: struct {
//             /// Kernel map, a model of /proc/kallsyms
//             backend: std.ArrayListUnmanaged(UMapEntry),
//         },
//         unmapped: struct {},
//     };
//
//     /// A fixed type that can be used as a fallback on error. Arguably, a UMapEntry should be a tagged union. If I
//     /// care I can do this in the future.
//     pub const UMapEntryUnmapped = UMapEntry{
//         .path = "Unmapped",
//         .offset = 0,
//         .addressBeg = 0,
//         .addressEnd = 0,
//     };
//
//     /// Result of a `find` operation. Again, given that this class even exists its clear we should eventually just
//     /// refactor the UMapEntry structure. Future work.
//     pub const UMapEntryResult = union(enum) {
//         found: UMapEntry,
//         notfound: struct {},
//         unmapped: struct {},
//     };
//
//     pub const UnmappedInstance = UMapUnmanaged{
//         .internal = .{
//             .unmapped = .{},
//         },
//     };
//
//     internal: Internal,
//
//     /// Constructor
//     pub fn init(allocator: std.mem.Allocator, pid: PID) !UMapUnmanaged {
//         std.log.info("Creating UMap with pid {}...", .{pid});
//
//         // Allocate backend
//         var backend = try std.ArrayListUnmanaged(UMapEntry).initCapacity(allocator, 0);
//         errdefer {
//             for (backend.items) |entry| allocator.free(entry.path);
//             backend.deinit(allocator);
//         }
//
//         // Open a file to /proc/*/maps
//         const file = blk: {
//             // NOTE: we are bounding the length of our path to be 256 here, probably sufficient.
//             var pathBuffer: [256]u8 = undefined;
//             const path = try std.fmt.bufPrint(&pathBuffer, "/proc/{}/maps", .{pid});
//
//             // It can happen that while we're starting, a process dies. Then we can't load it. In which case we
//             // return this "unloaded".
//             break :blk std.fs.openFileAbsolute(path, .{}) catch return UnmappedInstance;
//         };
//         defer file.close();
//
//         // Read the whole file in 1 go
//         const content = file.readToEndAlloc(allocator, std.math.maxInt(usize)) catch return UnmappedInstance;
//         defer allocator.free(content);
//
//         // Reader for said file contents
//         var fbs = std.Io.Reader.fixed(content);
//
//         // Populate internals + sort based on instruction pointer enabling binary search. Because we rather show
//         // the user something rather than nothing, for now return an unmapped instance.
//         populate(allocator, &backend, &fbs) catch return UnmappedInstance;
//         sort(&backend);
//
//         std.log.info("Creating UMap with pid {} OK", .{pid});
//         return UMapUnmanaged{
//             .internal = .{
//                 .loaded = .{
//                     .backend = backend,
//                 },
//             },
//         };
//     }
//
//     /// Destructor
//     pub fn deinit(self: *UMapUnmanaged, allocator: std.mem.Allocator) void {
//         switch (self.internal) {
//             .loaded => |*s| {
//                 for (s.backend.items) |item| allocator.free(item.path);
//                 s.backend.deinit(allocator);
//             },
//             else => {},
//         }
//
//         self.* = undefined;
//     }
//
//     /// Find an entry given an instruction pointer.
//     pub fn find(self: UMapUnmanaged, ip: InstructionPointer) UMapEntryResult {
//         switch (self.internal) {
//             .loaded => |s| {
//                 // Find the entry strictly larger than our ip, then the correct symbol will be the preceding
//                 const index = std.sort.upperBound(UMapEntry, s.backend.items, ip, struct {
//                     fn lessThan(lhs_ip: u64, rhs_map: UMapEntry) std.math.Order {
//                         if (lhs_ip < rhs_map.addressBeg) return .lt;
//                         if (lhs_ip > rhs_map.addressBeg) return .gt;
//                         return .eq;
//                     }
//                 }.lessThan);
//
//                 // Ensure sane output
//                 if (index == 0) return .{ .notfound = .{} };
//                 if (s.backend.items[index - 1].addressEnd < ip) return .{ .notfound = .{} };
//                 return .{ .found = s.backend.items[index - 1] };
//             },
//             .unmapped => {
//                 return UMapEntryResult{
//                     .unmapped = .{},
//                 };
//             },
//         }
//     }
//
//     // populates the map from e.g. a file
//     fn populate(allocator: std.mem.Allocator, backend: *std.ArrayListUnmanaged(UMapEntry), reader: anytype) !void {
//         // Loop over file contents
//         while (true) {
//             // Read until we cannot take more lines --> implies EOF
//             const line = reader.takeDelimiterExclusive('\n') catch break;
//
//             // Split by space.
//             // Note that the line has the following structure:
//             //
//             // ```
//             // 7f6687c76000-7f6687c77000 rw-p 00003000 103:02 19296183                  /path/to/prog0
//             // 7f6687c77000-7f6687c79000 r--p 00000000 103:02 19553864                  /path/to/prog1
//             // 7f6687c79000-7f6687c7c000 r-xp 00002000 103:02 19553864                  /path/to/prog2
//             // ```
//             var line_iter = std.mem.tokenizeAny(u8, line, " ");
//
//             // Map address range
//             const map = line_iter.next() orelse return error.UMapParseError;
//             var map_iter = std.mem.splitScalar(u8, map, '-');
//             const map_beg_string = map_iter.next() orelse return error.UMapParseError;
//             const map_end_string = map_iter.next() orelse return error.UMapParseError;
//             const map_beg = try std.fmt.parseInt(u64, map_beg_string, 16);
//             const map_end = try std.fmt.parseInt(u64, map_end_string, 16);
//
//             // Skip perms, aren't interesting currently
//             const perms = line_iter.next() orelse return error.UMapParseError;
//             _ = perms;
//
//             // Get offset
//             const offset_string = line_iter.next() orelse return error.UMapParseError;
//             const offset = try std.fmt.parseInt(u64, offset_string, 16);
//
//             // Skip device, aren't interesting currently
//             const device = line_iter.next() orelse return error.UMapParseError;
//             _ = device;
//
//             // Skip inode, aren't interesting currently
//             const inode = line_iter.next() orelse return error.UMapParseError;
//             _ = inode;
//
//             // Take dll path
//             const dll_path = line_iter.rest();
//
//             const owned_path = try allocator.dupe(u8, dll_path);
//             errdefer allocator.free(owned_path);
//             try backend.append(allocator, .{
//                 .addressBeg = map_beg,
//                 .addressEnd = map_end,
//                 .offset = offset,
//                 .path = owned_path,
//             });
//         }
//     }
//
//     test "umap.UMapUnmanaged.populate parses valid /proc/pid/maps lines" {
//         const input =
//             "7f6687c76000-7f6687c77000 rw-p 00003000 103:02 19296183                   /usr/lib/libc.so.6\n" ++
//             "7f6687c77000-7f6687c79000 r--p 00000000 103:02 19553864                   /usr/lib/ld-linux.so\n";
//
//         var backend = std.ArrayListUnmanaged(UMapEntry){};
//         defer {
//             for (backend.items) |item| std.testing.allocator.free(item.path);
//             backend.deinit(std.testing.allocator);
//         }
//
//         var reader = std.Io.Reader.fixed(input);
//         try UMapUnmanaged.populate(std.testing.allocator, &backend, &reader);
//
//         try std.testing.expectEqual(2, backend.items.len);
//         try std.testing.expectEqual(0x7f6687c76000, backend.items[0].addressBeg);
//         try std.testing.expectEqual(0x7f6687c77000, backend.items[0].addressEnd);
//         try std.testing.expectEqual(0x3000, backend.items[0].offset);
//     }
//
//     test "umap.UMapUnmanaged.populate handles empty input" {
//         var backend = std.ArrayListUnmanaged(UMapEntry){};
//         defer backend.deinit(std.testing.allocator);
//
//         var reader = std.Io.Reader.fixed("");
//         try UMapUnmanaged.populate(std.testing.allocator, &backend, &reader);
//
//         try std.testing.expectEqual(0, backend.items.len);
//     }
//
//     /// Sorts the map in ascending order for binary search
//     fn sort(backend: *std.ArrayListUnmanaged(UMapEntry)) void {
//         // Sort the map so it is easier to search at a later stage
//         std.sort.block(UMapEntry, backend.items, {}, struct {
//             fn lessThan(_: void, a: UMapEntry, b: UMapEntry) bool {
//                 return a.addressBeg < b.addressBeg;
//             }
//         }.lessThan);
//     }
// };
