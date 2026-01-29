const std = @import("std");
const PID = @import("typesystem.zig").PID;
const InstructionPointer = @import("typesystem.zig").InstructionPointer;

/// ===================================================================================================================
/// UMap
/// ===================================================================================================================
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

    /// Take owned copy
    pub fn clone(self: UMapEntry, allocator: std.mem.Allocator) !UMapEntry {
        var copy = self;
        copy.path = try allocator.dupe(u8, self.path);
        return copy;
    }

    pub fn deinit(self: UMapEntry, allocator: std.mem.Allocator) void { 
        allocator.free(self.path);
    }
};

/// Model of the symbols in /proc/*/maps
pub const UMapUnmanaged = struct {
    // The members of this struct is represented by a tagged union. Loaded means we're ready to return symbols,
    // unmapped means we for whatever reason couldnt read the /proc/*/maps file. We can likely become more robust
    // by having more entries here.
    const Internal = union((enum { loaded, unmapped })) {
        loaded: struct {
            /// Kernel map, a model of /proc/kallsyms
            backend: std.ArrayListUnmanaged(UMapEntry),
        },
        unmapped: struct {},
    };

    /// A fixed type that can be used as a fallback on error. Arguably, a UMapEntry should be a tagged union. If I
    /// care I can do this in the future.
    pub const UMapEntryUnmapped = UMapEntry{
        .path = "Unmapped",
        .offset = 0,
        .addressBeg = 0,
        .addressEnd = 0,
    };

    /// Result of a `find` operation. Again, given that this class even exists its clear we should eventually just
    /// refactor the UMapEntry structure. Future work.
    pub const UMapEntryResult = union((enum { found, notfound, unmapped })) {
        found: UMapEntry,
        notfound: struct {},
        unmapped: struct {},
    };

    pub const UnmappedInstance = UMapUnmanaged{
        .internal = .{
            .unmapped = .{},
        },
    };

    internal: Internal,

    /// Constructor
    pub fn init(allocator: std.mem.Allocator, pid: PID) !UMapUnmanaged {
        // Allocate backend
        var backend = try std.ArrayListUnmanaged(UMapEntry).initCapacity(allocator, 0);
        errdefer {
            for (backend.items) |entry| allocator.free(entry.path);
            backend.deinit(allocator);
        }

        // Open a file to /proc/*/maps
        const file = blk: {
            var pathBuffer: [128]u8 = undefined;
            const path = try std.fmt.bufPrint(&pathBuffer, "/proc/{}/maps", .{pid});

            // It can happen that while we're starting, a process dies. Then we can't load it. In which case we
            // return this "unloaded".
            break :blk std.fs.openFileAbsolute(path, .{}) catch return UnmappedInstance;
        };
        defer file.close();

        // Reader for said file contents
        var fileBuffer: [4096]u8 = undefined;
        var fileReader = file.reader(&fileBuffer);

        // Populate internals + sort based on instruction pointer enabling binary search. Because we rather show
        // the user something rather than nothing, for now return an unmapped instance.
        populate(allocator, &backend, &fileReader.interface) catch return UnmappedInstance;
        sort(&backend);

        return UMapUnmanaged{
            .internal = .{
                .loaded = .{
                    .backend = backend,
                },
            },
        };
    }

    /// Find an entry given an instruction pointer. 
    pub fn find(self: UMapUnmanaged, ip: InstructionPointer) UMapEntryResult {
        switch (self.internal) {
            .loaded => |s| {
                // Find the entry strictly larger than our ip, then the correct symbol will be the preceding
                const index = std.sort.upperBound(UMapEntry, s.backend.items, ip, struct {
                    fn lessThan(lhs_ip: u64, rhs_map: UMapEntry) std.math.Order {
                        if (lhs_ip < rhs_map.addressBeg) return .lt;
                        if (lhs_ip > rhs_map.addressBeg) return .gt;
                        return .eq;
                    }
                }.lessThan);

                // Ensure sane output
                if (index == s.backend.items.len or index == 0) return .{ .notfound = .{} };
                if (s.backend.items[index - 1].addressEnd < ip) return .{ .notfound = .{} };
                return .{ .found = s.backend.items[index - 1] };
            },
            .unmapped => {
                return UMapEntryResult{
                    .unmapped = .{},
                };
            },
        }
    }

    /// Destructor
    pub fn deinit(self: *UMapUnmanaged, allocator: std.mem.Allocator) void {
        switch (self.internal) {
            .loaded => |*s| {
                for (s.backend.items) |item| allocator.free(item.path);
                s.backend.deinit(allocator);
            },
            else => {},
        }
    }

    // populates the map from e.g. a file
    fn populate(allocator: std.mem.Allocator, backend: *std.ArrayListUnmanaged(UMapEntry), reader: *std.Io.Reader) !void {
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

            try backend.append(allocator, .{
                .addressBeg = map_beg,
                .addressEnd = map_end,
                .offset = offset,
                .path = try allocator.dupe(u8, dll_path),
            });
        }
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
};

/// UMaps are expensive to load and also can be invalidated, thus we have a cache. This class is a map between PID
/// and UMap. 
///
/// TODO: PIDs can die. Currently we do not have any logic to handle this. I think we should allow PIDs to be 
/// invalidated, so that should probably be a method on this class. When invalidated YET used again, we need to 
/// trigger a reload.
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

        // Fail unreachable
        unreachable;
    }

    pub fn deinit(self: *UMapCache) void {
        for (self.backend.values()) |*item| item.deinit(self.allocator);
        self.backend.deinit(self.allocator);
    }
};
