const std = @import("std");
const UMapEntry = @import("umap.zig").UMapEntry;

/// Our hashing function
/// TODO: use the StringHashMap instead?
fn hash(str: []const u8) u64 {
    return std.hash.Wyhash.hash(0, str);
}

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
