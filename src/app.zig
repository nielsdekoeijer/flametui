// Main logic for our application
const std = @import("std");
const bpf = @import("bpf.zig");
const c = @import("cimport.zig").c;
const vaxis = @import("vaxis");
const profile_program = @import("profile_streaming");
const profile_definitions = @cImport({
    @cInclude("profile_streaming.bpf.h");
});

/// ===================================================================================================================
/// Helpers
/// ===================================================================================================================
/// The event type from bpf
const EventTypeRaw = u64; // profile_definitions.sample_event;

/// Our parsed view over the raw data, note we dont clone for efficiencies sake
const EventType = struct {
    pid: u64,
    kips: []const u64,
    uips: []const u64,

    pub fn init(raw: *const EventTypeRaw) EventType {
        const ev = @as([*]const u64, @ptrCast(raw));
        const us = ev[1] / 8;
        const ks = ev[2] / 8;

        const event = EventType{
            .pid = ev[0],
            .uips = ev[3 .. 3 + us],
            .kips = ev[3 + us .. 3 + us + ks],
        };

        return event;
    }
};

/// Alias for the kernel type
pub const InstructionPointer = u64;

/// Alias for the kernel type
pub const PID = u32;

/// Our hashing function
fn hash(str: []const u8) u64 {
    return std.hash.Wyhash.hash(0, str);
}

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
        var buf: [4096]u8 = undefined;
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
        return self.backend.items[index - 1];
    }

    pub fn deinit(self: *KMapUnmanaged, allocator: std.mem.Allocator) void {
        for (self.backend.items) |item| allocator.free(item.symbol);
        self.backend.deinit(allocator);
    }

    fn populate(allocator: std.mem.Allocator, backend: *std.ArrayListUnmanaged(KMapEntry), reader: *std.Io.Reader) !void {
        // Loop through file contents
        while (true) {
            // Read until we cannot take more lines --> implies EOF
            const line = reader.takeDelimiterExclusive('\n') catch break;

            // Split into fields.
            // Note that the line has the following structure:
            //
            // ```
            // 0000000000000000 T srso_alias_untrain_ret
            // ```
            var iter = std.mem.splitScalar(u8, line, ' ');

            // Grab the address
            const addressString = iter.next() orelse continue;
            const address = std.fmt.parseInt(u64, addressString, 16) catch continue;

            // Skip the type
            const @"type" = iter.next();
            _ = @"type";

            // Read the symbol, duplicate our own copy
            const symbolString = iter.next() orelse continue;

            // Append to our representation
            // Note that we own the memory, and thus must clean it
            try backend.append(allocator, KMapEntry{
                .ip = address,
                .symbol = try allocator.dupe(u8, symbolString),
            });
        }
    }

    /// Sorts the map in ascending order for binary search
    fn sort(backend: *std.ArrayListUnmanaged(KMapEntry)) void {
        // Sort the map so it is easier to search at a later stage
        std.sort.block(KMapEntry, backend.items, {}, struct {
            fn lessThan(_: void, a: KMapEntry, b: KMapEntry) bool {
                return a.ip < b.ip;
            }
        }.lessThan);
    }
};

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
};

/// Model of the symbols in /proc/*/maps
pub const UMapUnmanaged = struct {
    const Internal = union((enum { loaded, unmapped })) {
        loaded: struct {
            /// Kernel map, a model of /proc/kallsyms
            backend: std.ArrayListUnmanaged(UMapEntry),
        },
        unmapped: struct {},
    };

    /// A fixed type that can be used as a fallback on error
    pub const UMapEntryUnmapped = UMapEntry{
        .path = "Unmapped",
        .offset = 0,
        .addressBeg = 0,
        .addressEnd = 0,
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

        const file = blk: {
            var pathBuffer: [128]u8 = undefined;
            const path = try std.fmt.bufPrint(&pathBuffer, "/proc/{}/maps", .{pid});
            // It can happen that while we're starting, a process dies. Then we can't load it. In which case we
            // return this "unloaded".
            break :blk std.fs.openFileAbsolute(path, .{}) catch return UMapUnmanaged{
                .internal = .{
                    .unmapped = .{},
                },
            };
        };
        defer file.close();

        var fileBuffer: [4096]u8 = undefined;
        var fileReader = file.reader(&fileBuffer);

        try populate(allocator, &backend, &fileReader.interface);
        sort(&backend);

        return UMapUnmanaged{
            .internal = .{
                .loaded = .{
                    .backend = backend,
                },
            },
        };
    }

    /// Result of a `find` operation
    pub const UMapEntryResult = union((enum { found, notfound, unmapped })) {
        found: UMapEntry,
        notfound: struct {},
        unmapped: struct {},
    };

    /// Find an entry given an instruction pointer
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

/// ===================================================================================================================
/// UMapCache
/// ===================================================================================================================
/// UMaps are expensive to load and also can be invalidated, thus we have a cache
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

/// ===================================================================================================================
/// StackTrie
/// ===================================================================================================================
/// Trie for tracking incoming stacktraces
pub const StackTrie = struct {
    /// The different entry types in our trie
    const TrieEntryKind = enum {
        root,
        kernel,
        user,
    };

    /// What we store in a trie for a kernel stack frame
    pub const KTrieEntry = struct {
        kmapip: u64,
    };

    /// What we store in a trie for a userspace stack frame
    pub const UTrieEntry = struct {
        umapip: u64,
        umapid: u64,
    };

    /// Trie union, datatype we store in the trie
    pub const TriePayload = union(TrieEntryKind) {
        root: void,
        kernel: KTrieEntry,
        user: UTrieEntry,
    };

    /// Our node type
    pub const TrieEntry = struct {
        hitCount: u64,
        parent: Id,
        entry: TriePayload,
    };

    /// Type for the parent index
    pub const Id = u32;
    pub const RootId: Id = 0;

    /// Key used for our trie
    pub const Key = struct { pid: PID, parent: Id, ip: InstructionPointer };

    /// Umaps we have seen
    umap: std.ArrayListUnmanaged(UMapEntry),

    /// User maps cache, can be dynamic, i.e. key <-> value pair non-unique
    umapLookup: UMapCache,

    /// Underlying flat trie
    entries: std.ArrayListUnmanaged(TrieEntry),

    /// Helps us lookup indices for parent <-> child relations
    entriesLookup: std.AutoArrayHashMapUnmanaged(Key, u64),

    /// Store our allocator, not unmanaged
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) !StackTrie {
        var entries = try std.ArrayListUnmanaged(TrieEntry).initCapacity(allocator, 0);

        // initialize the root
        try entries.append(allocator, .{
            .hitCount = 0,
            .parent = 0,
            .entry = .root,
        });

        return StackTrie{
            .umap = try std.ArrayListUnmanaged(UMapEntry).initCapacity(allocator, 0),
            .umapLookup = try UMapCache.init(allocator),
            .entries = entries,
            .entriesLookup = try std.AutoArrayHashMapUnmanaged(Key, u64).init(
                allocator,
                &[_]Key{},
                &[_]u64{},
            ),
            .allocator = allocator,
        };
    }

    /// Add an event to the trie
    /// TODO: this whole logic is cooked
    pub fn add(self: *StackTrie, event: EventType) !void {
        const pid = @as(PID, @intCast(event.pid));
        var parent: Id = RootId;

        // Resolve user stack frames
        var i = event.uips.len;
        while (i > 0) {
            i -= 1;
            const ip = event.uips[i];

            const key = Key{
                .pid = pid,
                .parent = parent,
                .ip = ip,
            };

            const found = self.entriesLookup.get(key);

            if (found) |index| {
                self.entries.items[index].hitCount += 1;
                parent = @intCast(index);
            } else {
                const umap = try self.umapLookup.find(pid);
                const item = switch (umap.find(ip)) {
                    .found => |it| it,
                    .notfound => UMapUnmanaged.UMapEntryUnmapped,
                    .unmapped => UMapUnmanaged.UMapEntryUnmapped,
                };

                try self.umap.append(self.allocator, item);

                try self.entries.append(self.allocator, TrieEntry{
                    .hitCount = 1,
                    .parent = parent,
                    .entry = TriePayload{
                        .user = .{
                            .umapip = ip,
                            .umapid = self.umap.items.len - 1,
                        },
                    },
                });

                try self.entriesLookup.put(self.allocator, key, self.entries.items.len - 1);
            }
        }

        // Resolve kernel stack frames
        var j = event.kips.len;
        while (j > 0) {
            j -= 1;
            const ip = event.kips[j];

            const key = Key{
                .pid = pid,
                .parent = parent,
                .ip = ip,
            };

            const found = self.entriesLookup.get(key);
            if (found) |index| {
                self.entries.items[index].hitCount += 1;
                parent = @intCast(index);
            } else {
                try self.entries.append(self.allocator, TrieEntry{
                    .hitCount = 1,
                    .parent = parent,
                    .entry = TriePayload{
                        .kernel = .{
                            .kmapip = ip,
                        },
                    },
                });

                try self.entriesLookup.put(self.allocator, key, self.entries.items.len - 1);
            }
        }
    }

    pub fn free(self: *StackTrie) void {
        self.umap.deinit(self.allocator);
        self.umapLookup.deinit();
        self.entries.deinit(self.allocator);
        self.entriesLookup.deinit(self.allocator);
    }
};

/// ===================================================================================================================
/// SharedObjectMap
/// ===================================================================================================================
pub const SharedObjectSymbol = struct {
    addr: u64,
    size: u64,
    name: []const u8,
};

/// Class that describes a shared object, containing a collection of symbols
pub const SharedObjectMap = struct {
    // We have a funny pattern here: we still want to be able to query a shared object map if its not mapped
    // If this is great design is to be determined.
    const Internal = union((enum { loaded, unmapped })) {
        loaded: struct {
            mappedSharedObject: []align(std.heap.page_size_min) const u8,
            symbols: std.ArrayListUnmanaged(SharedObjectSymbol),
            allocator: std.mem.Allocator,
            path: []const u8,
            object: std.elf.ET,
        },
        unmapped: struct {},
    };

    internal: Internal,

    pub fn init(allocator: std.mem.Allocator, path: []const u8) !SharedObjectMap {
        // If the path is not absolute, do not proceed
        if (!std.fs.path.isAbsolute(path)) {
            return SharedObjectMap{
                .internal = .{
                    .unmapped = .{},
                },
            };
        }

        // Create list
        var symbols = try std.ArrayListUnmanaged(SharedObjectSymbol).initCapacity(allocator, 0);

        // Open file
        const file = std.fs.openFileAbsolute(path, .{}) catch {
            // this means either the path we obtained is not valid, or it seized to exist since our first check
            // TODO: there are edge cases here, probably we want to log a bit to learn what they are
            return SharedObjectMap{
                .internal = .{
                    .unmapped = .{},
                },
            };
        };
        defer file.close();

        // Get file details and mmap
        const stat = try file.stat();
        const mappedSharedObject = try std.posix.mmap(
            null,
            stat.size,
            std.posix.PROT.READ,
            .{ .TYPE = .PRIVATE },
            file.handle,
            0,
        );
        errdefer std.posix.munmap(mappedSharedObject);

        // Create a reader
        populate(allocator, mappedSharedObject, &symbols) catch {
            // its possible for this to fail, I'm not quite sure why that happens
            return SharedObjectMap{
                .internal = .{
                    .unmapped = .{},
                },
            };
        };

        sort(&symbols);

        return SharedObjectMap{
            .internal = .{
                .loaded = .{
                    .mappedSharedObject = mappedSharedObject,
                    .symbols = symbols,
                    .allocator = allocator,
                    .path = try allocator.dupe(u8, path),
                    .object = try queryObjectType(mappedSharedObject),
                },
            },
        };
    }

    /// Result of a `find` operation
    pub const SharedObjectSymbolResult = union((enum { found, notfound, unmapped })) {
        found: SharedObjectSymbol,
        notfound: struct {},
        unmapped: struct {},
    };

    /// Find an entry given an instruction pointer, or null if this instance wasn't mapped
    pub fn find(self: SharedObjectMap, ipRaw: u64, uentry: UMapEntry) SharedObjectSymbolResult {
        switch (self.internal) {
            .loaded => |s| {
                // The IP we should use depends on what we get here
                const ip = blk: {
                    if (s.object == std.elf.ET.EXEC) {
                        break :blk ipRaw;
                    } else {
                        break :blk ipRaw - uentry.addressBeg + uentry.offset;
                    }
                };

                // Find the entry strictly larger than our ip, then the correct symbol will be the preceding
                const index = std.sort.upperBound(SharedObjectSymbol, s.symbols.items, ip, struct {
                    fn lessThan(lhs_ip: u64, rhs_sym: SharedObjectSymbol) std.math.Order {
                        if (lhs_ip < rhs_sym.addr) return .lt;
                        if (lhs_ip > rhs_sym.addr) return .gt;
                        return .eq;
                    }
                }.lessThan);

                // Sort invalid
                if (index == s.symbols.items.len or index == 0) {
                    return .{ .notfound = .{} };
                }

                const candidate = s.symbols.items[index - 1];
                if (ip < candidate.addr + candidate.size) {
                    return .{ .found = candidate };
                }

                return .{ .found = candidate };

                // NOTE: this would make sense, but apparently we can just return the candidate. I'm not sure if I
                // understand why this happens. It's a major TODO to figure this out.
                //
                // ```
                // std.log.err(
                //     "Failed to find ip {} in shared object '{s}', best candidate address at {} with size {}",
                //     .{ ip, s.path, candidate.addr, candidate.size },
                // );
                // return error.SharedObjectMapLookupFailure;
                // ```
            },
            .unmapped => |_| {
                return .{ .unmapped = .{} };
            },
        }
    }

    pub fn deinit(self: *SharedObjectMap) void {
        std.posix.munmap(self.mappedSharedObject);
        self.symbols.deinit(self.allocator);
        self.allocator.free(self.path);
    }

    fn readHeader(mappedSharedObject: []align(std.heap.page_size_min) const u8) !std.elf.Header {
        const header = blk: {
            var reader = std.Io.Reader.fixed(mappedSharedObject);
            break :blk try std.elf.Header.read(&reader);
        };

        return header;
    }

    fn readHeaderArchitecture(header: std.elf.Header) enum { @"64", @"32" } {
        if (header.is_64) {
            return .@"64";
        } else {
            return .@"32";
        }
    }

    fn queryObjectType(mappedSharedObject: []align(std.heap.page_size_min) const u8) !std.elf.ET {
        const header = try readHeader(mappedSharedObject);
        return header.type;
    }

    fn populate(allocator: std.mem.Allocator, mappedSharedObject: []align(std.heap.page_size_min) const u8, symbols: *std.ArrayListUnmanaged(SharedObjectSymbol)) !void {
        const header = try readHeader(mappedSharedObject);
        switch (readHeaderArchitecture(header)) {
            inline else => |val| {
                const Shdr = switch (comptime val) {
                    .@"32" => std.elf.Elf32_Shdr,
                    .@"64" => std.elf.Elf64_Shdr,
                };

                const Sym = switch (comptime val) {
                    .@"32" => std.elf.Elf32_Sym,
                    .@"64" => std.elf.Elf64_Sym,
                };

                var sectionIterator = header.iterateSectionHeadersBuffer(mappedSharedObject);
                while (try sectionIterator.next()) |section| {
                    if (section.sh_type == std.elf.SHT_SYMTAB or section.sh_type == std.elf.SHT_DYNSYM) {
                        // Get symbol count
                        const symbolCount = section.sh_size / section.sh_entsize;

                        // NOTE: shoff is the start of the table
                        // NOTE: sh_link points to "The section header index of the associated string table"
                        // NOTE: shentsize is the size of each section
                        const stringTableHeaderOffset = header.shoff + (section.sh_link * header.shentsize);

                        // Read the string table header
                        var stringTableHeaderReader = std.Io.Reader.fixed(mappedSharedObject[stringTableHeaderOffset..]);
                        const stringTableHeader = try stringTableHeaderReader.takeStruct(Shdr, header.endian);

                        // Read symbols
                        const stringTable = mappedSharedObject[stringTableHeader.sh_offset .. stringTableHeader.sh_offset + stringTableHeader.sh_size];
                        var stringTableReader = std.Io.Reader.fixed(mappedSharedObject[section.sh_offset..]);
                        for (0..symbolCount) |_| {
                            const symbol = try stringTableReader.takeStruct(Sym, header.endian);

                            // This is odd: it breaks without this, although I think it makes sense.
                            // TODO: Read elf header documentation to try to understand what I'm actually doing
                            // if (symbol.st_size == 0) continue;
                            const name = std.mem.sliceTo(stringTable[symbol.st_name..], 0);
                            try symbols.append(allocator, .{
                                .addr = symbol.st_value,
                                .size = @intCast(symbol.st_size),
                                .name = name,
                            });
                        }
                    }
                }
            },
        }
    }

    /// Sorts the map in ascending order for binary search
    fn sort(symbols: *std.ArrayListUnmanaged(SharedObjectSymbol)) void {
        // Sort the map so it is easier to search at a later stage
        std.sort.block(SharedObjectSymbol, symbols.items, {}, struct {
            fn lessThan(_: void, a: SharedObjectSymbol, b: SharedObjectSymbol) bool {
                return a.addr < b.addr;
            }
        }.lessThan);
    }
};

/// SharedObjectMaps are expensive to load and parse, and also can be invalidated, thus we have a cache to track this
/// for us.
pub const SharedObjectMapCache = struct {
    backend: std.AutoArrayHashMapUnmanaged(u64, SharedObjectMap),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) !SharedObjectMapCache {
        const backend = try std.AutoArrayHashMapUnmanaged(u64, SharedObjectMap).init(
            allocator,
            &[_]u64{},
            &[_]SharedObjectMap{},
        );

        return SharedObjectMapCache{
            .allocator = allocator,
            .backend = backend,
        };
    }

    /// Return entry given pid, or create it
    pub fn find(self: *SharedObjectMapCache, path: []const u8) !*SharedObjectMap {
        const hashed = hash(path);

        // Try to find it
        {
            const found = self.backend.getPtr(hashed);
            if (found) |m| {
                return m;
            }
        }

        // If not found, create one
        try self.backend.put(self.allocator, hashed, try SharedObjectMap.init(self.allocator, path));

        // Find it
        {
            const found = self.backend.getPtr(hashed);
            if (found) |m| {
                return m;
            }
        }

        // Fail unreachable
        unreachable;
    }

    pub fn deinit(self: *SharedObjectMapCache) void {
        for (self.backend.values()) |*item| item.deinit(self.allocator);
        self.backend.deinit(self.allocator);
    }
};

/// ===================================================================================================================
/// SymbolTrie
/// ===================================================================================================================
/// Trie for tracking incoming stacktraces
pub const SymbolTrie = struct {
    /// The different entry types in our trie
    const TrieEntryKind = enum {
        root,
        kernel,
        user,
    };

    /// What we store in a trie for a kernel stack frame
    pub const KTrieEntry = struct {
        symbol: []const u8,
    };

    /// What we store in a trie for a userspace stack frame
    pub const UTrieEntry = struct {
        dll: []const u8,
        symbol: []const u8,
    };

    /// Trie union, datatype we store in the trie
    pub const TriePayload = union(TrieEntryKind) {
        root: KTrieEntry,
        kernel: KTrieEntry,
        user: UTrieEntry,
    };

    /// Our node type
    pub const TrieEntry = struct {
        hitCount: u64,
        parent: Id,
        // To be able to walk the trie, we store an array to its children
        children: std.ArrayListUnmanaged(Id),
        entry: TriePayload,
    };

    /// Type for the parent index
    pub const Id = u32;
    pub const RootId: Id = 0;

    /// Key used for our trie
    pub const Key = struct { parent: Id, symbolHash: u64 };

    /// Underlying flat trie
    entries: std.ArrayListUnmanaged(TrieEntry),

    /// Helps us lookup indices for parent <-> child relations
    entriesLookup: std.AutoArrayHashMapUnmanaged(Key, Id),

    /// Store our allocator, not unmanaged
    allocator: std.mem.Allocator,

    /// Kernel maps, assumed static
    kmap: KMapUnmanaged,

    /// For loading dlls
    sharedObjectMapCache: SharedObjectMapCache,

    pub fn init(allocator: std.mem.Allocator) !SymbolTrie {
        const entries = try std.ArrayListUnmanaged(TrieEntry).initCapacity(allocator, 1);

        // try entries.append(allocator, .{
        //     .hitCount = 0,
        //     .parent = 0,
        //     .children = try std.ArrayListUnmanaged(Id).initCapacity(allocator, 0),
        //     .entry = .root,
        // });

        return SymbolTrie{
            .entries = entries,
            .entriesLookup = try std.AutoArrayHashMapUnmanaged(Key, Id).init(
                allocator,
                &[_]Key{},
                &[_]Id{},
            ),
            .allocator = allocator,
            .kmap = try KMapUnmanaged.init(allocator),
            .sharedObjectMapCache = try SharedObjectMapCache.init(allocator),
        };
    }

    // add from a stacktrie
    // NOTE: the shadowmap logic is all fucked, this is kinda complicated. We need to review this code and understand it
    pub fn add(self: *SymbolTrie, stacks: StackTrie) !void {
        // The shadowmap is used to resolve parents of the stacktrie to the correct one in the symboltrie.
        // * Imagine the mapping stack root --> symbol root
        // * Imagine also that there may be multiple stack nodes with the same symboltrie key
        const ShadowMap = std.AutoArrayHashMapUnmanaged(StackTrie.Id, SymbolTrie.Id);
        var shadowMap = try ShadowMap.init(self.allocator, &[_]StackTrie.Id{}, &[_]SymbolTrie.Id{});
        defer shadowMap.deinit(self.allocator);

        // Map the root ids to eachother
        try shadowMap.put(self.allocator, StackTrie.RootId, RootId);

        // we exploit the fact that our tree is laid out from root --> upwards
        for (0..stacks.entries.items.len) |i| {
            const stackId: Id = @intCast(i);
            // get stack item
            const stackItem = stacks.entries.items[stackId];

            // resolve the parent (due to the order, should be garunteed to be known)
            const parentId = shadowMap.get(stackItem.parent) orelse return error.ShadowMapError;

            // find the symbol
            const symbol = switch (stackItem.entry) {
                .root => "root",
                .kernel => |e| blk: {
                    const s = try self.kmap.find(e.kmapip);
                    break :blk try self.allocator.dupe(u8, s.symbol);
                },
                .user => |e| blk: {
                    const p = stacks.umap.items[e.umapid];
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

            // create the key
            const key = Key{ .parent = parentId, .symbolHash = hash(symbol) };

            // trie update / insertion
            const found = self.entriesLookup.get(key);
            if (found) |symbolId| {
                // hit
                self.entries.items[symbolId].hitCount += 1;
                try shadowMap.put(self.allocator, stackId, symbolId);
            } else {
                // create the payload depending on the trie that came in
                const payload = blk: switch (stackItem.entry) {
                    .root => break :blk TriePayload{
                        .root = .{
                            .symbol = symbol,
                        },
                    },
                    .kernel => break :blk TriePayload{
                        .kernel = .{
                            .symbol = symbol,
                        },
                    },
                    .user => |e| break :blk TriePayload{
                        .user = .{
                            .symbol = symbol,
                            .dll = try self.allocator.dupe(u8, stacks.umap.items[e.umapid].path),
                        },
                    },
                };

                // append + add to map
                try self.entries.append(self.allocator, TrieEntry{
                    .hitCount = 1,
                    .parent = parentId,
                    .entry = payload,
                    .children = try std.ArrayListUnmanaged(Id).initCapacity(self.allocator, 0),
                });

                // grab our id
                const symbolId: Id = @intCast(self.entries.items.len - 1);

                try self.entriesLookup.put(self.allocator, key, symbolId);
                try shadowMap.put(self.allocator, stackId, symbolId);

                // go to parent, and add self as child
                if (symbolId != parentId) {
                    try self.entries.items[parentId].children.append(self.allocator, symbolId);
                }
            }
        }
    }

    pub fn free(self: *SymbolTrie) void {
        self.kmap.deinit(self.allocator);
        self.entries.deinit(self.allocator);
        self.entriesLookup.deinit(self.allocator);
    }
};

/// ===================================================================================================================
/// TUI
/// ===================================================================================================================
/// Helper that leprs between two vaxis colors with interpolation parameter t
fn lerpColor(a: vaxis.Color, b: vaxis.Color, t: f32) vaxis.Color {
    return .{
        .rgb = .{
            @intFromFloat(@as(f32, @floatFromInt(a.rgb[0])) * (1.0 - t) + @as(f32, @floatFromInt(b.rgb[0])) * t),
            @intFromFloat(@as(f32, @floatFromInt(a.rgb[1])) * (1.0 - t) + @as(f32, @floatFromInt(b.rgb[1])) * t),
            @intFromFloat(@as(f32, @floatFromInt(a.rgb[2])) * (1.0 - t) + @as(f32, @floatFromInt(b.rgb[2])) * t),
        },
    };
}

/// Helper that dims a vaxis color with a factor t
fn dimColor(color: vaxis.Color, t: f32) vaxis.Color {
    switch (color) {
        .rgb => |rgb| {
            return .{
                .rgb = .{
                    @intFromFloat(@as(f32, @floatFromInt(rgb[0])) * t),
                    @intFromFloat(@as(f32, @floatFromInt(rgb[1])) * t),
                    @intFromFloat(@as(f32, @floatFromInt(rgb[2])) * t),
                },
            };
        },

        else => return color,
    }
}

/// Colors using greg's original version
pub fn getColorFromName(symbolName: []const u8) vaxis.Color {
    const hashName = struct {
        pub fn hashName(name: []const u8, reverse: bool) f32 {
            var vector: f32 = 0;
            var weight: f32 = 1;
            var max: f32 = 1;
            var mod: f32 = 10;

            for (0..name.len) |i| {
                const idx = blk: {
                    if (reverse) {
                        break :blk i;
                    } else {
                        break :blk name.len - 1 - i;
                    }
                };

                const chr = name[idx];
                const val = @as(f32, @floatFromInt(@mod(chr, @as(u8, @intFromFloat(mod)))));

                vector += (val / (mod - 1.0)) * weight;
                max += weight;
                weight *= 0.70;
                mod += 1;

                if (mod > 12) {
                    break;
                }
            }

            return (1.0 - (vector / max));
        }
    }.hashName;

    const v1 = hashName(symbolName, true);
    const v2 = hashName(symbolName, false);
    const v3 = v2;

    return .{
        .rgb = .{
            @as(u8, @intFromFloat(50.0 * v3)) + 205,
            @as(u8, @intFromFloat(230.0 * v1)),
            @as(u8, @intFromFloat(55.0 * v2)),
        },
    };
}

/// Object managing plotting and events
const Interface = struct {
    backgroundGradientBeg: vaxis.Color = .{ .rgb = .{ 0xEE, 0xEE, 0xB0 } },
    backgroundGradientEnd: vaxis.Color = .{ .rgb = .{ 0xEE, 0xEE, 0xEE } },
    textColor: vaxis.Color = .{ .rgb = .{ 0x00, 0x00, 0x00 } },

    allocator: std.mem.Allocator,
    tty: vaxis.Tty,
    ttyBuffer: []u8,
    vx: vaxis.Vaxis,
    loop: vaxis.Loop(Event),
    symbols: ?*SymbolTrie,

    // vaxis events we want to subscribe to
    const Event = union(enum) {
        key_press: vaxis.Key,
        winsize: vaxis.Winsize,
        mouse: vaxis.Mouse,
    };

    pub fn init(allocator: std.mem.Allocator) !Interface {
        // open tty
        const buffer: []u8 = try allocator.alloc(u8, 4096);
        var tty = try vaxis.Tty.init(buffer);
        errdefer tty.deinit();

        // start vaxis
        var vx = try vaxis.init(allocator, .{});
        errdefer vx.deinit(allocator, tty.writer());

        // setup loop
        var loop = vaxis.Loop(Event){ .tty = &tty, .vaxis = &vx };
        try loop.init();

        // configure vaxis
        try vx.setMouseMode(tty.writer(), true);
        try vx.enterAltScreen(tty.writer());
        try vx.queryTerminal(tty.writer(), 1 * std.time.ns_per_s);

        return Interface{
            .allocator = allocator,
            .tty = tty,
            .ttyBuffer = buffer,
            .vx = vx,
            .loop = loop,
            .symbols = null,
        };
    }

    pub fn populate(self: *Interface, symbols: *SymbolTrie) void {
        self.symbols = symbols;
    }

    pub fn start(self: *Interface) !void {
        var mouse: ?vaxis.Mouse = null;
        {
            const win = self.vx.window();
            try self.draw(win, mouse);
        }

        try self.loop.start();
        while (true) {
            const event = self.loop.nextEvent();

            switch (event) {
                .key_press => |key| {
                    if (key.matches('q', .{}) or key.matches('c', .{ .ctrl = true })) {
                        break;
                    }
                },
                .winsize => |winsize| {
                    try self.vx.resize(self.allocator, self.tty.writer(), winsize);
                },
                .mouse => |m| {
                    mouse = m;
                },
            }

            const win = self.vx.window();
            try self.draw(win, mouse);
            try self.vx.render(self.tty.writer());
        }
    }

    // padding on the sides
    const FlamegraphBorderWBeg = 2;
    const FlamegraphBorderWEnd = 2;
    const FlamegraphBorderHBeg = 4;
    const FlamegraphBorderHEnd = 4;

    pub fn clearBackground(self: Interface, win: vaxis.Window) !void {
        const h = win.height;
        const w = win.width;

        for (0..h) |y| {
            const alpha = 1.0 - @as(f32, @floatFromInt(y)) / @as(f32, @floatFromInt(h - 1));
            const color = lerpColor(self.backgroundGradientBeg, self.backgroundGradientEnd, alpha);
            for (0..w) |x| {
                win.writeCell(@intCast(x), @intCast(y), .{
                    .char = .{ .grapheme = " " },
                    .style = .{ .bg = color },
                });
            }
        }
    }

    pub fn draw(self: *Interface, win: vaxis.Window, mouse: ?vaxis.Mouse) !void {
        // Clear the background
        try self.clearBackground(win);

        // Mouse support is tbd
        _ = mouse;

        // We may not have any symbols loaded, in which case return
        if (self.symbols) |symbols| {
            const toSmallW = win.width <= FlamegraphBorderWBeg + FlamegraphBorderWEnd;
            const toSmallH = win.height <= FlamegraphBorderHBeg + FlamegraphBorderHEnd;

            if (toSmallW or toSmallH) return;

            // Internal size exclusive of the border
            const flamegraphW = win.width - FlamegraphBorderWBeg - FlamegraphBorderWEnd;
            const flamegraphH = win.height - FlamegraphBorderHBeg - FlamegraphBorderHEnd;
            _ = flamegraphH;

            // Draw recursively, first node is the root node
            std.debug.assert(symbols.entries.items[0].entry == .root);
            try self.drawSymbol(symbols.entries.items[0], win, .{
                // We want to draw 100% of the availible space
                .widthNormalized = 1.0,

                // We start at the beginning
                .offsetNormalized = 0.0,

                // We have space consisting
                .widthCells = flamegraphW,

                // Where to start drawing X coord
                .currentX = FlamegraphBorderWBeg + 1,

                // Where to start drawing Y coord
                .currentY = win.height - FlamegraphBorderHEnd,
            });
        } else {
            return;
        }
    }

    pub fn drawSymbol(
        self: *Interface,
        entry: SymbolTrie.TrieEntry,
        win: vaxis.Window,
        context: struct {
            offsetNormalized: f32,
            widthNormalized: f32,
            widthCells: u16,
            currentX: u16,
            currentY: u16,
        },
    ) !void {
        // How we get the symbol name, works for all enums
        const symbol = blk: switch (entry.entry) {
            inline else => |s| break :blk s.symbol,
        };

        // How we draw the bar
        const style = vaxis.Style{
            .fg = self.textColor,
            .bg = getColorFromName(symbol),
            .bold = false,
        };

        // The Y coordinate is fixed and given by the arguments. We have to calculate the X coordinate though.
        const rawBegX = (context.offsetNormalized) * @as(f32, @floatFromInt(context.widthCells)) + @as(f32, @floatFromInt(context.currentX));
        const rawEndX = (context.offsetNormalized + context.widthNormalized) * @as(f32, @floatFromInt(context.widthCells)) + @as(f32, @floatFromInt(context.currentX));
        const begX: u16 = @intFromFloat(rawBegX);
        const endX: u16 = @intFromFloat(rawEndX);
        const len = endX - begX;

        switch (entry.entry) {
            else => {
                const space: []const u8 = &[_]u8{' '};
                for (0..len) |i| {
                    const glyph = if (i < symbol.len) @as([]const u8, @ptrCast(&symbol[i])) else space;
                    win.writeCell(begX + @as(u16, @intCast(i)), context.currentY, .{
                        .char = .{ .grapheme = glyph },
                        .style = style,
                    });
                }
            },
        }

        if (context.currentY == 0) {
            return;
        }

        var childOffset: f32 = context.offsetNormalized;
        for (entry.children.items) |id| {
            // safe to do
            const child = self.symbols.?.entries.items[id];

            const childWidth = @as(f32, @floatFromInt(child.hitCount)) / @as(f32, @floatFromInt(entry.hitCount)) * context.widthNormalized;
            std.debug.assert(childWidth <= 1.0);

            try self.drawSymbol(child, win, .{
                .widthCells = context.widthCells,
                .currentX = context.currentX,
                .currentY = context.currentY - 1,
                .widthNormalized = childWidth,
                .offsetNormalized = childOffset,
            });

            childOffset += childWidth;
        }
    }

    pub fn stop(self: *Interface) void {
        self.loop.stop();
    }

    pub fn deinit(self: *Interface) void {
        self.vx.deinit(self.allocator, self.tty.writer());
        self.tty.deinit();
    }
};

/// ===================================================================================================================
/// App
/// ===================================================================================================================
pub const App = struct {
    allocator: std.mem.Allocator,
    code: []const u8,
    object: bpf.Object,
    links: []bpf.Object.Link,
    ring: bpf.Object.RingBufferMap,
    missed: *u64,
    iptrie: *StackTrie,

    pub fn eventCallback(iptrie: *StackTrie, event: *const EventTypeRaw) void {
        const parsed = EventType.init(event);
        iptrie.add(parsed) catch unreachable;
    }

    pub fn init(allocator: std.mem.Allocator) anyerror!App {
        // disable logging
        try bpf.setupLoggerBackend(.zig);

        // load our embedded code into an byte array with 8 byte alignment
        const code = try bpf.loadProgramAligned(allocator, profile_program.bytecode);
        errdefer allocator.free(code);
        const object = try bpf.Object.load(code);
        errdefer object.free();

        // create links structure
        const cpuCount = try std.Thread.getCpuCount();
        const links = try allocator.alloc(bpf.Object.Link, cpuCount);
        for (links) |*link| link.internal = null;
        errdefer {
            for (links) |*link| {
                link.free();
            }
        }

        // StackTrie
        const iptrie = try allocator.create(StackTrie);
        iptrie.* = try StackTrie.init(allocator);

        // create event ring buffer
        const ring = try object.attachRingBufferMapCallback(StackTrie, EventTypeRaw, eventCallback, iptrie, "events");

        // grab global counters
        const missed = try object.getGlobals(u64);

        // store
        return App{
            .allocator = allocator,
            .code = code,
            .object = object,
            .links = links,
            .ring = ring,
            .missed = missed,
            .iptrie = iptrie,
        };
    }

    pub fn free(self: *App) void {
        self.allocator.free(self.code);
        self.object.free();
        for (self.links) |*link| {
            link.free();
        }

        self.iptrie.free();
        self.allocator.destroy(self.iptrie);
    }

    pub fn run(self: App, rate: usize, nanoseconds: u64) anyerror!void {
        // specify our perf events
        var attributes = std.os.linux.perf_event_attr{
            .type = .SOFTWARE,
            .sample_period_or_freq = rate,
            .config = c.PERF_COUNT_SW_CPU_CLOCK,
            .flags = .{
                .freq = true,
                .mmap = true,
            },
        };

        // attach programs to each cpu
        for (0..self.links.len) |i| {
            self.links[i] = try self.object.attachProgramPerfEventByName("do_sample", i, &attributes);
        }
        defer {
            for (self.links) |*link| {
                link.free();
            }
        }

        // run
        var timer = try std.time.Timer.start();
        while (timer.read() < nanoseconds) {
            try self.ring.consume();
            std.atomic.spinLoopHint();
        }

        var symboltrie = try SymbolTrie.init(self.allocator);
        try symboltrie.add(self.iptrie.*);
        for (symboltrie.entries.items) |item| {
            std.log.info("{}", .{item});
        }

        // report how many we missed, reset it
        std.log.info("missed: {d}", .{self.missed.*});
        self.missed.* = 0;

        var interface = try Interface.init(self.allocator);
        defer interface.deinit();

        interface.populate(&symboltrie);

        try interface.start();
        defer interface.stop();
    }
};
