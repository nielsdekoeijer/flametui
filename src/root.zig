const std = @import("std");
const Io = std.Io;

const c = @cImport({
    @cInclude("libbpf.h");
    @cInclude("stdio.h");
    @cInclude("bpf.h");
    @cInclude("linux/perf_event.h");
});

const test_definitions = @cImport({
    @cInclude("test.bpf.h");
});

const profile_definitions = @cImport({
    @cInclude("profile.bpf.h");
});

// ------------------------
// BPF helpers
// ------------------------
const bpf = struct {
    fn log(level: c.enum_libbpf_print_level, fmt: [*c]const u8, ap: [*c]c.struct___va_list_tag_1) callconv(.c) c_int {
        var buf: [512]u8 = undefined;
        const len_c = c.vsnprintf(&buf, buf.len, fmt, ap);
        if (len_c == 0) {
            return 0;
        }

        const len = @max(0, @min(@as(usize, @intCast(len_c)), buf.len) - 2);
        if (len > 0) {
            const slice = buf[0..len];
            switch (level) {
                c.LIBBPF_WARN => {
                    std.log.warn("{s}", .{slice});
                },
                c.LIBBPF_INFO => {
                    std.log.info("{s}", .{slice});
                },
                c.LIBBPF_DEBUG => {
                    std.log.debug("{s}", .{slice});
                },
                else => {
                    unreachable;
                },
            }
        }

        return len_c;
    }

    pub fn setupLoggerBackend(mode: enum { zig, none }) !void {
        const result = switch (mode) {
            .zig => c.libbpf_set_print(log),
            .none => c.libbpf_set_print(null),
        };

        if (result == null) {
            return error.LoggerUnset;
        }
    }

    // ------------------------
    // Represents a BPF Object
    // ------------------------
    const Object = struct {
        internal: *c.struct_bpf_object,

        pub fn load(mem: []const u8) anyerror!Object {
            const obj = c.bpf_object__open_mem(@ptrCast(mem), mem.len, null) orelse return error.OpenFailure;
            errdefer c.bpf_object__close(obj);

            if (c.bpf_object__load(obj) != 0) {
                return error.LoadFailure;
            }

            return Object{
                .internal = obj,
            };
        }

        pub fn attachProgramByName(self: Object, name: [*c]const u8) !Link {
            const prog: *c.bpf_program = c.bpf_object__find_program_by_name(self.internal, name) orelse return error.ProgramNotFound;
            // _ = c.bpf_program__attach(prog) orelse return error.AttachFailure;
            const link = c.bpf_program__attach(prog) orelse return error.AttachFailure;
            return Link{ .internal = link };
        }

        pub fn attachProgramPerfEventByName(
            object: Object,
            name: [*c]const u8,
            cpu: usize,
            perfEventAttributes: *std.os.linux.perf_event_attr,
        ) anyerror!Link {
            const prog: ?*c.bpf_program = c.bpf_object__find_program_by_name(object.internal, name) orelse return error.ProgramNotFound;

            const pfd = blk: {
                const pfd = std.os.linux.perf_event_open(perfEventAttributes, -1, @intCast(cpu), -1, 0);
                if (pfd == 0) {
                    return error.PerfEventOpenFailure;
                }

                break :blk pfd;
            };

            errdefer {
                _ = std.os.linux.close(@intCast(pfd));
            }
            const link = c.bpf_program__attach_perf_event(prog, @intCast(pfd)) orelse return error.AttachFailure;
            return Link{ .internal = link };
        }

        pub fn free(self: Object) void {
            c.bpf_object__close(self.internal);
        }

        // ------------------------
        // Link
        // ------------------------
        const Link = struct {
            internal: *c.struct_bpf_link,

            pub fn free(link: Link) void {
                if (c.bpf_link__destroy(link.internal) != 0) {
                    @panic("ebpf link destruction failure");
                }
            }
        };

        // ------------------------
        // RingBufferMaps
        // ------------------------
        const RingBufferMap = struct {
            rb: *c.struct_ring_buffer,
            pub fn createCallback(comptime EventType: type, comptime handler: *const fn (EventType) void) type {
                return struct {
                    pub fn handlerWrapper(ctx: ?*anyopaque, data: ?*anyopaque, size: usize) callconv(.c) c_int {
                        _ = ctx;
                        _ = size;

                        if (data) |d| {
                            const event = @as(*const EventType, @ptrCast(@alignCast(d)));
                            handler(event.*);
                        }

                        return 0;
                    }
                };
            }

            pub fn poll(self: RingBufferMap, ms: i64) !void {
                if (c.ring_buffer__poll(self.rb, @intCast(ms)) < 0) {
                    return error.PollFailure;
                }
            }

            pub fn free(self: RingBufferMap) void {
                c.ring_buffer__free(self.rb);
            }
        };

        pub fn attachRingBufferMapCallback(
            object: Object,
            comptime EventType: type,
            comptime handler: *const fn (EventType) void,
            name: [*c]const u8,
        ) anyerror!RingBufferMap {
            const fd = blk: {
                const fd = c.bpf_object__find_map_fd_by_name(object.internal, name);
                if (fd < 0) {
                    return error.RingBufferMapNotFound;
                }

                break :blk fd;
            };

            const cb = RingBufferMap.createCallback(EventType, handler).handlerWrapper;
            const rb = c.ring_buffer__new(fd, cb, null, null) orelse return error.OpenFailure;
            errdefer c.ring_buffer__free(rb);

            return RingBufferMap{
                .rb = rb,
            };
        }
    };
};

// ------------------------
// Test
// ------------------------
const Event = test_definitions.event;

pub fn callback(event: Event) void {
    const comm_slice = std.mem.sliceTo(&event.comm, 0);
    std.log.info("Received Event: PID={d} COMM='{s}'", .{ event.pid, comm_slice });
}

pub fn run_test(allocator: std.mem.Allocator) anyerror!void {
    // simple test program, just shows how it works
    try bpf.setupLoggerBackend(.zig);

    const code = try allocator.alignedAlloc(u8, .@"8", @import("test").bytecode.len);
    defer allocator.free(code);

    @memcpy(code, @import("test").bytecode);
    const object = try bpf.Object.load(code);
    defer object.free();
    const map = try object.attachRingBufferMapCallback(Event, callback, "rb");
    defer map.free();
    const link = try object.attachProgramByName("handle_exec");
    defer link.free();
    while (true) {
        try map.poll(100);
    }
}

// ------------------------
// Profile
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

    pub fn init(io: std.Io, allocator: std.mem.Allocator) !KernelSymbolResolver {
        var symbols = std.ArrayListUnmanaged(Symbol){};

        // build symbol table
        const file = try std.Io.Dir.openFileAbsolute(io, "/proc/kallsyms", .{});
        defer file.close(io);

        var buf: [4096]u8 = undefined;
        var reader = file.reader(io, &buf);

        while (true) {
            const line = try reader.interface.takeDelimiter('\n') orelse break;
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

pub const UserSymbolResolver = struct {
    pub fn resolve(io: std.Io, allocator: std.mem.Allocator, pid: u64, address: u64) !?[]const u8 {
        // build symbol table
        var path_buf: [128]u8 = undefined;
        const path = try std.fmt.bufPrint(&path_buf, "/proc/{}/maps", .{pid});

        const file = std.Io.Dir.openFileAbsolute(io, path, .{}) catch {
            return try std.fmt.allocPrint(allocator, "map not found: {s}", .{path});
        };
        defer file.close(io);
        var file_buf: [4096]u8 = undefined;
        var file_reader = file.reader(io, &file_buf);

        while (true) {
            // take one line
            const line = try file_reader.interface.takeDelimiter('\n') orelse break;

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
                    const dll = try std.Io.Dir.openFileAbsolute(io, dll_path, .{});
                    defer dll.close(io);
                    var dll_buf: [512]u8 = undefined;
                    var dll_reader = dll.reader(io, &dll_buf);

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

        return try std.fmt.allocPrint(allocator, "symbol not found: {s}", .{path});
    }
};

pub fn run_profile(io: std.Io, allocator: std.mem.Allocator) anyerror!void {
    // for flamegraph creation
    try bpf.setupLoggerBackend(.zig);

    const code = try allocator.alignedAlloc(u8, .@"8", @import("profile").bytecode.len);
    defer allocator.free(code);

    @memcpy(code, @import("profile").bytecode);

    const object = try bpf.Object.load(code);
    defer object.free();

    const freq = 49;
    const cpuCount = try std.Thread.getCpuCount();

    var links = try std.ArrayListUnmanaged(bpf.Object.Link).initCapacity(allocator, cpuCount);
    defer links.clearAndFree(allocator);
    defer {
        for (links.items) |link| {
            link.free();
        }
    }

    for (0..cpuCount) |cpu| {
        var attributes: std.os.linux.perf_event_attr = .{
            .type = .SOFTWARE,
            .sample_period_or_freq = freq,
            .config = c.PERF_COUNT_SW_CPU_CLOCK,
            .flags = .{
                .freq = true,
                .mmap = true,
            },
        };

        const link = try object.attachProgramPerfEventByName("do_sample", cpu, &attributes);
        errdefer link.free();
        try links.append(allocator, link);
    }

    try std.Io.Clock.Duration.sleep(.{ .clock = .awake, .raw = .fromMilliseconds(500) }, io);

    const counts_map = c.bpf_object__find_map_by_name(object.internal, "counts") orelse return error.MapNotFound;
    const stacks_map = c.bpf_object__find_map_by_name(object.internal, "stack_traces") orelse return error.MapNotFound;
    const counts_fd = c.bpf_map__fd(counts_map);
    const stacks_fd = c.bpf_map__fd(stacks_map);

    var prev_key: ?*const anyopaque = null;
    var curr_key: profile_definitions.key_t = undefined;
    var next_key: profile_definitions.key_t = undefined;
    var count: u64 = 0;

    const resolver = try KernelSymbolResolver.init(io, allocator);

    std.log.info("Iterating over maps...", .{});
    while (c.bpf_map_get_next_key(counts_fd, prev_key, &next_key) == 0) {
        curr_key = next_key;
        prev_key = &curr_key;

        if (c.bpf_map_lookup_elem(counts_fd, &curr_key, &count) != 0) {
            continue;
        }

        const comm_slice = std.mem.sliceTo(&curr_key.comm, 0);
        std.log.info("Entry with:", .{});
        std.log.info(" - count: {d:<6}", .{count});
        std.log.info(" - pid:   {d:<6}", .{curr_key.pid});
        std.log.info(" - tgid:  {d:<6}", .{curr_key.tgid});
        std.log.info(" - comm:  {s:<16}", .{comm_slice});

        if (curr_key.kernel_stack_id >= 0) {
            var stack_ips: [127]u64 = undefined;
            if (c.bpf_map_lookup_elem(stacks_fd, &curr_key.kernel_stack_id, &stack_ips) == 0) {
                var i: usize = 0;
                while (i < stack_ips.len and stack_ips[i] != 0) : (i += 1) {
                    std.log.info(" --> [KERN][{d:3}] 0x{x}:{s}", .{ i, stack_ips[i], resolver.resolve(stack_ips[i]) orelse "NOTFOUND" });
                }
            } else {
                unreachable;
            }
        }

        if (curr_key.user_stack_id >= 0) {
            var stack_ips: [127]u64 = undefined;

            if (c.bpf_map_lookup_elem(stacks_fd, &curr_key.user_stack_id, &stack_ips) == 0) {
                var i: usize = 0;
                while (i < stack_ips.len and stack_ips[i] != 0) : (i += 1) {
                    std.log.info(" --> [USER][{d:3}] 0x{x}:{s}", .{
                        i,
                        stack_ips[i],
                        try UserSymbolResolver.resolve(io, allocator, curr_key.pid, stack_ips[i]) orelse "NOTFOUND",
                    });
                }
            } else {
                std.log.warn(" --> [USER][{d:3}] Stack ID missing", .{curr_key.user_stack_id});
            }
        } else if (curr_key.user_stack_id == -14) {
            std.log.info(" --> [USER][ERR] binary may lack frame pointers", .{});
        }

        std.log.info("", .{});
    }
}
