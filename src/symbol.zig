const std = @import("std");


// ------------------------
// Resolve Symbols Kernel
// ------------------------
pub const KernelSymbolResolver = struct {
    pub const Symbol = struct {
        address: u64,
        name: []const u8,

        pub fn lessThan(_: void, lhs: Symbol, rhs: Symbol) bool {
            return lhs.address < rhs.address;
        }

        pub fn compare(context: u64, item: Symbol) std.math.Order {
            if (context < item.address) return .lt;
            if (context > item.address) return .gt;
            return .eq;
        }
    };

    allocator: std.mem.Allocator,
    symbols: std.ArrayListUnmanaged(Symbol),

    pub fn init(allocator: std.mem.Allocator) !KernelSymbolResolver {
        var symbols = std.ArrayListUnmanaged(Symbol){};

        // build symbol table
        const file = try std.fs.openFileAbsolute("/proc/kallsyms", .{});
        defer file.close();

        var buf: [4096]u8 = undefined;
        var reader = file.reader(&buf);

        while (true) {
            const line = reader.interface.takeDelimiterExclusive('\n') catch break;
            var iter = std.mem.splitScalar(u8, line, ' ');

            // address
            const address_string = iter.next() orelse continue;
            const address = std.fmt.parseInt(u64, address_string, 16) catch continue;

            // skip type
            _ = iter.next();

            // read name
            const name_str = iter.next() orelse continue;
            const name = try allocator.dupe(u8, name_str);

            // add allocator
            try symbols.append(allocator, .{
                .address = address,
                .name = name,
            });
        }

        // sort the list for quicker lookup
        std.mem.sort(Symbol, symbols.items, {}, Symbol.lessThan);

        return KernelSymbolResolver{
            .allocator = allocator,
            .symbols = symbols,
        };
    }

    pub fn free(self: KernelSymbolResolver) void {
        for (self.symbols.items) |symbol| {
            self.allocator.free(symbol.name);
        }

        self.symbols.clearAndFree(self.allocator);
    }

    pub fn resolve(self: KernelSymbolResolver, address: u64) ?[]const u8 {
        // our list of symbols
        const items = self.symbols.items;
        if (items.len == 0) return null;

        // check name of closest starting symbol
        const index = std.sort.upperBound(Symbol, items, address, Symbol.compare);
        if (index == 0) return null;

        return items[index - 1].name;
    }
};

// ------------------------
// Resolve Symbols User
// ------------------------
pub const UserSymbolResolver = struct {
    pub fn resolve(allocator: std.mem.Allocator, pid: u64, address: u64) !?[]const u8 {
        // build symbol table
        var path_buf: [128]u8 = undefined;
        const path = try std.fmt.bufPrint(&path_buf, "/proc/{}/maps", .{pid});

        const file = std.fs.openFileAbsolute(path, .{}) catch {
            return try std.fmt.allocPrint(allocator, "map not found: {s}", .{path});
        };
        defer file.close();
        var file_buf: [4096]u8 = undefined;
        var file_reader = file.reader(&file_buf);

        while (true) {
            // take one line
            const line = file_reader.interface.takeDelimiterExclusive('\n') catch break;

            // grab individual parts
            var line_iter = std.mem.tokenizeAny(u8, line, " ");

            // first, parse the map
            const map = line_iter.next() orelse return error.ExpectedMap;
            var map_iter = std.mem.splitScalar(u8, map, '-');
            const map_beg_string = map_iter.next() orelse return error.ExpectedMapBeg;
            const map_end_string = map_iter.next() orelse return error.ExpectedMapEnd;
            const map_beg = try std.fmt.parseInt(u64, map_beg_string, 16);
            const map_end = try std.fmt.parseInt(u64, map_end_string, 16);

            // if we are within the maps bounds, we are inside the specified
            if (map_beg <= address and address <= map_end) {

                // perms, no use for it now
                const perms = line_iter.next() orelse return error.ExpectedPermissions;
                _ = perms;

                // offset,
                const offset_string = line_iter.next() orelse return error.ExpectedOffset;
                const offset = try std.fmt.parseInt(u64, offset_string, 16);

                // skips
                const device = line_iter.next() orelse return error.ExpectedDevice;
                _ = device;

                const inode = line_iter.next() orelse return error.ExpectedInode;
                _ = inode;

                // name
                const dll_path = line_iter.rest();
                if (dll_path.len == 0) continue;
                if (std.fs.path.isAbsolute(dll_path)) {
                    const dll = std.fs.openFileAbsolute(dll_path, .{}) catch return "NOTFOUND";
                    defer dll.close();
                    var dll_buf: [512]u8 = undefined;
                    var dll_reader = dll.reader(&dll_buf);

                    const header = try std.elf.Header.read(&dll_reader.interface);
                    const ip = (address - map_beg) + offset;

                    // if ET_EXEC is set its not PIE
                    const lookup_addr = if (header.type == std.elf.ET.EXEC) address else ip;

                    // foreach header
                    var section_iter = header.iterateSectionHeaders(&dll_reader);
                    while (section_iter.next() catch break) |section| {

                        // only look for .symtab and .dyntab secntions
                        if (section.sh_type == std.elf.SHT_SYMTAB or section.sh_type == std.elf.SHT_DYNSYM) {
                            const symbol_count = section.sh_size / section.sh_entsize;

                            // go to the section in the code
                            try dll_reader.seekTo(section.sh_offset);

                            // find the closest symbol, we do this cause sometimes symbols don't define their size
                            for (0..symbol_count) |_| {

                                // read a symbol
                                const symbol = try dll_reader.interface.takeStruct(std.elf.Elf64_Sym, header.endian);

                                // check if we're inside for exact match
                                if (symbol.st_size > 0) {
                                    if (lookup_addr >= symbol.st_value and lookup_addr < symbol.st_value + symbol.st_size) {
                                        const strtab_shdr_offset = header.shoff + (section.sh_link * header.shentsize);
                                        try dll_reader.seekTo(strtab_shdr_offset);

                                        const strtab_shdr = try dll_reader.interface.takeStruct(std.elf.Elf64_Shdr, header.endian);
                                        try dll_reader.seekTo(strtab_shdr.sh_offset + symbol.st_name);

                                        return try allocator.dupe(u8, try dll_reader.interface.peekDelimiterExclusive(0));
                                    }
                                }
                            }

                            // std.log.debug("could not find exact match in section", .{});
                            continue;
                        }
                    }
                } else {
                    return try std.fmt.allocPrint(allocator, "dll not found: {s}", .{dll_path});
                }
            }
        }

        return try std.fmt.allocPrint(allocator, "???", .{});
    }
};

