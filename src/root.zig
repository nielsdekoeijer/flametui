const std = @import("std");
const vaxis = @import("vaxis");
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
                    const dll = try std.fs.openFileAbsolute(dll_path, .{});
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

const VaxisEvent = union(enum) {
    key_press: vaxis.Key,
    winsize: vaxis.Winsize,
    // mouse: vaxis.Mouse,
};

pub const StackFrame = struct {
    pub const FrameKind = enum {
        Kernel,
        User,
        Jit,
        Root,
    };

    symbol: []const u8,
    // module: []const u8,
    // address: u64,
    kind: FrameKind,
};

pub const CallGraphNode = struct {
    frame: StackFrame,
    hit_count: u64,
    children: std.StringHashMap(CallGraphNode),
    allocator: std.mem.Allocator,

    pub fn insert(self: *CallGraphNode, frames: []const StackFrame) !void {
        self.hit_count += 1;

        if (frames.len == 0) return;

        const current_frame = frames[0];
        const remaining = frames[1..];

        const result = try self.children.getOrPut(current_frame.symbol);
        if (!result.found_existing) {
            result.value_ptr.* = try CallGraphNode.init(self.allocator, current_frame);
        }

        try result.value_ptr.insert(remaining);
    }

    pub fn init(allocator: std.mem.Allocator, frame: StackFrame) !CallGraphNode {
        return CallGraphNode{
            .allocator = allocator,
            .frame = frame,
            .hit_count = 0,
            .children = std.StringHashMap(CallGraphNode).init(allocator),
        };
    }

    pub fn deinit(self: *CallGraphNode) void {
        var iter = self.children.iterator();
        while (iter.next()) |entry| {
            entry.value_ptr.*.deinit(self.allocator);
        }

        self.children.deinit();
    }

    fn sortNodesDescending(_: void, lhs: *CallGraphNode, rhs: *CallGraphNode) bool {
        return lhs.hit_count > rhs.hit_count;
    }
};

pub const FlameGraph = struct {
    allocator: std.mem.Allocator,

    const FlameGraphNode = struct {
        level: u32,
        hitCount: u32,
        symbol: []const u8,
    };

    pub fn init(node: CallGraphNode, allocator: std.mem.Allocator) FlameGraph {
    }
};

pub const FlamegraphWidget = struct {
    root: *CallGraphNode,
    allocator: std.mem.Allocator,
    text_color: vaxis.Color = .{ .rgb = .{ 0x00, 0x00, 0x00 } },
    bg_grad_beg: vaxis.Color = .{ .rgb = .{ 0xEE, 0xEE, 0xB0 } },
    bg_grad_end: vaxis.Color = .{ .rgb = .{ 0xEE, 0xEE, 0xEE } },

    pub fn clearBackground(self: *FlamegraphWidget, win: vaxis.Window) !void {
        const h = win.height;
        const w = win.width;

        for (0..h) |y| {
            const alpha = 1.0 - @as(f32, @floatFromInt(y)) / @as(f32, @floatFromInt(h - 1));
            const color = lerpColor(self.bg_grad_beg, self.bg_grad_end, alpha);
            for (0..w) |x| {
                win.writeCell(@intCast(x), @intCast(y), .{
                    .char = .{ .grapheme = " " },
                    .style = .{ .bg = color },
                });
            }
        }
    }

    /// Simplified from brendan greg's version
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

    pub fn getColorFromName(name: []const u8) vaxis.Color {
        const v1 = hashName(name, false);
        const v2 = hashName(name, true);
        const v3 = v2;

        return .{
            .rgb = .{
                @as(u8, @intFromFloat(50.0 * v3)) + 205,
                @as(u8, @intFromFloat(230.0 * v1)),
                @as(u8, @intFromFloat(55.0 * v2)),
            },
        };
    }

    pub fn init(allocator: std.mem.Allocator, root: *CallGraphNode) FlamegraphWidget {
        return .{
            .allocator = allocator,
            .root = root,
        };
    }

    /// The main entry point to draw the widget into a specific window
    pub fn draw(self: *FlamegraphWidget, win: vaxis.Window) !void {
        if (self.root.hit_count == 0) return;
        const marginW = 4;
        const width = @as(f32, @floatFromInt(win.width - marginW));
        const samples_total = @as(f32, @floatFromInt(self.root.hit_count));

        try self.clearBackground(win);
        try self.renderNode(win, self.root, marginW / 2, win.height - 5, width, samples_total, 0);
    }

    fn renderNode(
        self: *FlamegraphWidget,
        win: vaxis.Window,
        node: *CallGraphNode,
        x_start: f32,
        y_pos: usize,
        total_screen_width: f32,
        total_root_samples: f32,
        depth: usize,
    ) !void {
        // const ratio = @as(f32, @floatFromInt(node.hit_count)) / total_root_samples;
        // const width: usize = @intFromFloat(@floor(ratio * total_screen_width));
        const ratio = @as(f32, @floatFromInt(node.hit_count)) / total_root_samples;
        const x_end = x_start + (ratio * total_screen_width);
        const draw_x_start: usize = @intFromFloat(x_start);
        const draw_x_end: usize = @intFromFloat(x_end);
        const width = draw_x_end -| draw_x_start;

        // if bar is less than 1 wide, we skip
        if (width < 1) {
            return;
        }

        // define the style
        const style: vaxis.Style = .{
            .fg = self.text_color,
            .bg = getColorFromName(node.frame.symbol),
            .bold = true,
        };

        for (0..width) |i| {
            var char_content: []const u8 = " ";

            if (i == 0 and width > 1) {
                char_content = " ";
            } else if (i < node.frame.symbol.len + 1) {
                const char_idx = i -| 1;
                if (char_idx < node.frame.symbol.len) {
                    char_content = node.frame.symbol[char_idx .. char_idx + 1];
                }
            }

            if (@as(usize, @intFromFloat(x_start)) + i < win.width and y_pos > 0 and y_pos < win.height) {
                win.writeCell(@intCast(@as(usize, @intFromFloat(x_start)) + i), @intCast(y_pos), .{
                    .char = .{ .grapheme = char_content },
                    .style = style,
                });
            }
        }

        // D. Sort Children (Crucial for UI stability!)
        // HashMaps are unordered. If we don't sort, the bars will "dance" randomly.
        var child_list = try std.ArrayList(*CallGraphNode).initCapacity(self.allocator, 0);
        defer child_list.deinit(self.allocator);

        var iter = node.children.iterator();
        while (iter.next()) |entry| {
            try child_list.append(self.allocator, entry.value_ptr);
        }

        // Sort by hit_count descending (Widest bars on the left)
        std.mem.sort(*CallGraphNode, child_list.items, {}, CallGraphNode.sortNodesDescending);

        // E. Recurse to Children
        var current_x_offset = x_start;

        // If we are at the top of the screen, stop recursion
        if (y_pos == 0) return;

        for (child_list.items) |child| {

            // Advance X offset by this child's width
            const child_ratio = @as(f32, @floatFromInt(child.hit_count)) / total_root_samples;
            const child_width_f = child_ratio * total_screen_width;

            try self.renderNode(win, child, current_x_offset, y_pos - 1, // Move UP the screen
                total_screen_width, total_root_samples, // Keep denominator constant to maintain proportion
                depth + 1);

            current_x_offset += child_width_f;
        }
    }

    fn lerpColor(c1: vaxis.Color, c2: vaxis.Color, t: f32) vaxis.Color {
        return .{
            .rgb = .{
                @intFromFloat(@as(f32, @floatFromInt(c1.rgb[0])) * (1.0 - t) + @as(f32, @floatFromInt(c2.rgb[0])) * t),
                @intFromFloat(@as(f32, @floatFromInt(c1.rgb[1])) * (1.0 - t) + @as(f32, @floatFromInt(c2.rgb[1])) * t),
                @intFromFloat(@as(f32, @floatFromInt(c1.rgb[2])) * (1.0 - t) + @as(f32, @floatFromInt(c2.rgb[2])) * t),
            },
        };
    }
};

pub fn run_profile(allocator: std.mem.Allocator) anyerror!void {
    // try bpf.setupLoggerBackend(.zig);
    try bpf.setupLoggerBackend(.none);

    const code = try allocator.alignedAlloc(u8, .@"8", @import("profile").bytecode.len);
    defer allocator.free(code);

    @memcpy(code, @import("profile").bytecode);

    const object = try bpf.Object.load(code);
    defer object.free();

    const freq = 49;
    const cpuCount = try std.Thread.getCpuCount();
    {
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

        std.Thread.sleep(1_000_000_000);
    }

    const counts_map = c.bpf_object__find_map_by_name(object.internal, "counts") orelse return error.MapNotFound;
    const stacks_map = c.bpf_object__find_map_by_name(object.internal, "stack_traces") orelse return error.MapNotFound;
    const counts_fd = c.bpf_map__fd(counts_map);
    const stacks_fd = c.bpf_map__fd(stacks_map);

    var prev_key: ?*const anyopaque = null;
    var curr_key: profile_definitions.key_t = undefined;
    var next_key: profile_definitions.key_t = undefined;
    var count: u64 = 0;

    const resolver = try KernelSymbolResolver.init(allocator);
    var root = try CallGraphNode.init(allocator, .{
        .kind = .Root,
        .symbol = "root",
    });

    std.log.info("Iterating over maps...", .{});
    while (c.bpf_map_get_next_key(counts_fd, prev_key, &next_key) == 0) {
        curr_key = next_key;
        prev_key = &curr_key;

        if (c.bpf_map_lookup_elem(counts_fd, &curr_key, &count) != 0) {
            continue;
        }

        var frames = try std.ArrayListUnmanaged(StackFrame).initCapacity(allocator, 0);
        defer frames.deinit(allocator);
        if (curr_key.user_stack_id >= 0) {
            var stack_ips: [127]u64 = undefined;

            if (c.bpf_map_lookup_elem(stacks_fd, &curr_key.user_stack_id, &stack_ips) == 0) {
                var i: usize = 0;
                while (i < stack_ips.len and stack_ips[i] != 0) : (i += 1) {
                    const symbol = try UserSymbolResolver.resolve(allocator, curr_key.pid, stack_ips[i]) orelse "NOTFOUND";
                    try frames.append(
                        allocator,
                        StackFrame{
                            .symbol = symbol,
                            .kind = .Kernel,
                        },
                    );
                }
            } else {
                // std.log.warn(" --> [USER][{d:3}] Stack ID missing", .{curr_key.user_stack_id});
            }
        } else if (curr_key.user_stack_id == -14) {
            // std.log.info(" --> [USER][ERR] binary may lack frame pointers", .{});
        }

        if (curr_key.kernel_stack_id >= 0) {
            var stack_ips: [127]u64 = undefined;
            if (c.bpf_map_lookup_elem(stacks_fd, &curr_key.kernel_stack_id, &stack_ips) == 0) {
                var i: usize = 0;
                while (i < stack_ips.len and stack_ips[i] != 0) : (i += 1) {
                    const symbol = resolver.resolve(stack_ips[i]) orelse "NOTFOUND";
                    try frames.append(
                        allocator,
                        StackFrame{
                            .symbol = symbol,
                            .kind = .Kernel,
                        },
                    );
                }
            } else {
                unreachable;
            }
        }

        try root.insert(frames.items);
    }

    var buffer: [4096]u8 = undefined;
    var tty = try vaxis.Tty.init(&buffer);
    defer tty.deinit();

    var vx = try vaxis.init(allocator, .{});
    defer vx.deinit(allocator, tty.writer());

    var loop = vaxis.Loop(VaxisEvent){ .tty = &tty, .vaxis = &vx };
    try loop.init();
    try loop.start();
    defer loop.stop();

    try vx.enterAltScreen(tty.writer());
    try vx.queryTerminal(tty.writer(), 1 * std.time.ns_per_s);

    var flamegraph = FlamegraphWidget.init(allocator, &root);

    while (true) {
        const event = loop.nextEvent();

        switch (event) {
            .key_press => |key| {
                if (key.matches('q', .{}) or key.matches('c', .{ .ctrl = true })) {
                    break;
                }
            },
            .winsize => |winsize| {
                try vx.resize(allocator, tty.writer(), winsize);
            },
        }

        const win = vx.window();

        // 4. Draw
        try flamegraph.draw(win);

        try vx.render(tty.writer());
    }
}
