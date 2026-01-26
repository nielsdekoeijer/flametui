const std = @import("std");
const bpf = @import("bpf.zig");
const vaxis = @import("vaxis");
pub const App = @import("app.zig").App;

const KernelSymbolResolver = @import("symbol.zig").KernelSymbolResolver;
const UserSymbolResolver = @import("symbol.zig").UserSymbolResolver;

const c = @import("cimport.zig").c;

const profile_definitions = @cImport({
    @cInclude("profile.bpf.h");
});

const VaxisEvent = union(enum) {
    key_press: vaxis.Key,
    winsize: vaxis.Winsize,
    mouse: vaxis.Mouse,
};

pub const StackFrame = struct {
    pub const FrameKind = enum {
        Kernel,
        User,
        Jit,
        Root,
    };

    pub const Status = enum {
        Found,
        Unknown,
    };

    symbol: []const u8,
    pid: ?u64,
    address: u64,
    kind: FrameKind,
};

/// Trie containing our measurement
pub const CallGraphNode = struct {
    frame: StackFrame,
    hitCount: u64,
    children: std.StringHashMap(CallGraphNode),
    allocator: std.mem.Allocator,

    pub fn insert(self: *CallGraphNode, frames: []const StackFrame) !void {
        self.hitCount += 1;

        if (frames.len == 0) return;

        var current_frame = frames[0];
        const remaining = frames[1..];

        const result = try self.children.getOrPut(current_frame.symbol);
        if (!result.found_existing) {
            // ensure we own
            current_frame.symbol = try self.allocator.dupe(u8, current_frame.symbol);
            result.value_ptr.* = try CallGraphNode.init(self.allocator, current_frame);
        }

        try result.value_ptr.insert(remaining);
    }

    pub fn init(allocator: std.mem.Allocator, frame: StackFrame) !CallGraphNode {
        return CallGraphNode{
            .allocator = allocator,
            .frame = frame,
            .hitCount = 0,
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

    pub fn getChildrenCount(self: CallGraphNode) usize {
        return self.children.count();
    }

    fn sortNodesDescending(_: void, lhs: *CallGraphNode, rhs: *CallGraphNode) bool {
        return lhs.hitCount > rhs.hitCount;
    }
};

pub const FlameGraph = struct {
    allocator: std.mem.Allocator,
    nodes: []FlameGraphNode,
    childCount: usize,
    hitCountTotal: u64,

    const FlameGraphNode = struct {
        level: usize,
        width: f32,
        offset: f32,
        symbol: []const u8,
        kind: StackFrame.FrameKind,
        hitCount: u64,
        pid: ?u64, 

        fn sort(_: void, lhs: FlameGraphNode, rhs: FlameGraphNode) bool {
            if (lhs.level == rhs.level) {
                return std.mem.order(u8, lhs.symbol, rhs.symbol) == .lt;
            } else return lhs.level < rhs.level;
        }
    };

    fn populateRecursive(
        self: *FlameGraph,
        node: CallGraphNode,
        list: *std.ArrayListUnmanaged(FlameGraphNode),
        level: usize,
        initialOffset: f32,
        initialWidth: f32,
    ) !void {
        var offset = initialOffset;
        if (node.children.count() > 0) {
            var childrenIt = node.children.iterator();
            while (true) {
                if (childrenIt.next()) |child| {
                    self.childCount += 1;

                    const width = (@as(f32, @floatFromInt(child.value_ptr.hitCount)) / @as(f32, @floatFromInt(node.hitCount))) * initialWidth;
                    try self.populateRecursive(child.value_ptr.*, list, level + 1, offset, width);

                    try list.append(
                        self.allocator,
                        FlameGraphNode{
                            .level = level,
                            .symbol = child.value_ptr.frame.symbol,
                            .offset = offset,
                            .width = width,
                            .kind = child.value_ptr.frame.kind,
                            .hitCount = child.value_ptr.hitCount,
                            .pid = child.value_ptr.frame.pid,
                        },
                    );

                    offset += width;
                } else {
                    break;
                }
            }
        }
    }

    pub fn init(allocator: std.mem.Allocator, node: CallGraphNode) !FlameGraph {
        var self = FlameGraph{
            .allocator = allocator,
            .nodes = &[_]FlameGraphNode{},
            .childCount = 0,
            .hitCountTotal = node.hitCount,
        };

        var list = try std.ArrayListUnmanaged(FlameGraphNode).initCapacity(allocator, 0);
        try self.populateRecursive(node, &list, 1, 0.0, 1.0);
        try list.append(
            self.allocator,
            FlameGraphNode{
                .level = 0,
                .symbol = node.frame.symbol,
                .offset = 0,
                .width = 1,
                .kind = .Root,
                .hitCount = node.hitCount,
                .pid = null,
            },
        );
        self.nodes = try list.toOwnedSlice(allocator);

        std.mem.sort(FlameGraphNode, self.nodes, {}, FlameGraphNode.sort);

        return self;
    }
};

fn lerpColor(a: vaxis.Color, b: vaxis.Color, t: f32) vaxis.Color {
    return .{
        .rgb = .{
            @intFromFloat(@as(f32, @floatFromInt(a.rgb[0])) * (1.0 - t) + @as(f32, @floatFromInt(b.rgb[0])) * t),
            @intFromFloat(@as(f32, @floatFromInt(a.rgb[1])) * (1.0 - t) + @as(f32, @floatFromInt(b.rgb[1])) * t),
            @intFromFloat(@as(f32, @floatFromInt(a.rgb[2])) * (1.0 - t) + @as(f32, @floatFromInt(b.rgb[2])) * t),
        },
    };
}

fn dimColor(color: vaxis.Color, factor: f32) vaxis.Color {
    switch (color) {
        .rgb => |rgb| {
            return .{
                .rgb = .{
                    @intFromFloat(@as(f32, @floatFromInt(rgb[0])) * factor),
                    @intFromFloat(@as(f32, @floatFromInt(rgb[1])) * factor),
                    @intFromFloat(@as(f32, @floatFromInt(rgb[2])) * factor),
                },
            };
        },

        else => return color,
    }
}

pub const FlameGraphInterface = struct {
    const graphPaddingWBeg: u16 = 2;
    const graphPaddingWEnd: u16 = 2;
    const graphPaddingHBeg: u16 = 2;
    const graphPaddingHEnd: u16 = 7;

    root: *FlameGraph,
    allocator: std.mem.Allocator,
    text_color: vaxis.Color = .{ .rgb = .{ 0x00, 0x00, 0x00 } },
    bg_grad_beg: vaxis.Color = .{ .rgb = .{ 0xEE, 0xEE, 0xB0 } },
    bg_grad_end: vaxis.Color = .{ .rgb = .{ 0xEE, 0xEE, 0xEE } },
    infoBuf0: [512]u8 = std.mem.zeroes([512]u8),
    infoBuf1: [512]u8 = std.mem.zeroes([512]u8),
    infoBuf2: [512]u8 = std.mem.zeroes([512]u8),

    pub fn init(allocator: std.mem.Allocator, root: *FlameGraph) FlameGraphInterface {
        return .{
            .allocator = allocator,
            .root = root,
        };
    }

    /// Clears the background with a gradient
    pub fn clearBackground(self: FlameGraphInterface, win: vaxis.Window) !void {
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

    fn drawCellOverBackground(self: FlameGraphInterface, win: vaxis.Window, x: u16, y: u16, char: []const u8, style: vaxis.Style) void {
        _ = self;
        if (win.readCell(x, y)) |bg_cell| {
            var s = style;
            s.bg = bg_cell.style.bg;
            win.writeCell(x, y, .{
                .char = .{ .grapheme = char },
                .style = s,
            });
        }
    }

    fn drawBorder(self: FlameGraphInterface, window: vaxis.Window, x1: u16, y1: u16, x2: u16, y2: u16, color: vaxis.Color) void {
        const style = vaxis.Style{
            .fg = color,
        };

        self.drawCellOverBackground(window, x1, y1, "┏", style);
        self.drawCellOverBackground(window, x2, y1, "┓", style);
        self.drawCellOverBackground(window, x1, y2, "┗", style);
        self.drawCellOverBackground(window, x2, y2, "┛", style);

        for ((x1 + 1)..x2) |x| {
            self.drawCellOverBackground(window, @intCast(x), y1, "━", style);
            self.drawCellOverBackground(window, @intCast(x), y2, "━", style);
        }

        for ((y1 + 1)..y2) |y| {
            self.drawCellOverBackground(window, x1, @intCast(y), "┃", style);
            self.drawCellOverBackground(window, x2, @intCast(y), "┃", style);
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

    /// Colors using greg's original version
    pub fn getColorFromName(name: []const u8) vaxis.Color {
        const v1 = hashName(name, true);
        const v2 = hashName(name, false);
        const v3 = v2;

        return .{
            .rgb = .{
                @as(u8, @intFromFloat(50.0 * v3)) + 205,
                @as(u8, @intFromFloat(230.0 * v1)),
                @as(u8, @intFromFloat(55.0 * v2)),
            },
        };
    }

    pub fn draw(self: *FlameGraphInterface, win: vaxis.Window, mouse: ?vaxis.Mouse) !void {
        try self.clearBackground(win);

        if (win.width <= graphPaddingWBeg + graphPaddingWEnd or win.height <= graphPaddingHBeg + graphPaddingHEnd) return;

        self.drawBorder(win, graphPaddingWBeg - 1, graphPaddingHBeg - 1, win.width - graphPaddingWEnd + 1, win.height - graphPaddingHEnd + 1, self.text_color);

        // rest
        const localW = @as(f32, @floatFromInt(win.width - (graphPaddingWBeg + graphPaddingWEnd))) + 1;
        const localH = win.height - (graphPaddingHBeg + graphPaddingHEnd);
        for (self.root.nodes) |node| {
            const start_f = localW * node.offset;
            const end_f = localW * (node.offset + node.width);
            const X = @as(u16, @intFromFloat(start_f)) + graphPaddingWBeg;
            const end_x = @as(u16, @intFromFloat(end_f)) + graphPaddingWEnd;
            const W = end_x - X;

            if (W == 0) continue;
            if (node.level > localH) continue;
            const Y = localH - @as(u16, @intCast(node.level)) + graphPaddingHBeg;

            // detect hover
            const hovered: bool = if (mouse) |m| m.row == Y and m.col >= X and m.col < end_x else false;

            const style: vaxis.Style = blk: {
                if (hovered) {
                    break :blk .{
                        .fg = self.text_color,
                        .bg = dimColor(getColorFromName(node.symbol), 0.9),
                        .bold = true,
                    };
                }

                break :blk .{
                    .fg = self.text_color,
                    .bg = getColorFromName(node.symbol),
                    .bold = false,
                };
            };

            var count: usize = 0;
            for (X..end_x) |x| {
                var char: []const u8 = " ";
                if (count > 0 and count < W - 1) {
                    if (count - 1 < node.symbol.len) {
                        char = node.symbol[count - 1 .. count];
                    }
                }

                win.writeCell(@as(u16, @intCast(x)), Y, .{
                    .char = .{ .grapheme = char },
                    .style = style,
                });
                count += 1;
            }

            if (hovered) {
                {
                    self.infoBuf0 = @splat(0);
                    const str = try std.fmt.bufPrint(&self.infoBuf0, "name: {s}", .{node.symbol});
                    for (0..str.len) |i| {
                        self.drawCellOverBackground(
                            win,
                            @as(u16, @intCast(graphPaddingWBeg + i)),
                            win.height - graphPaddingHEnd + 2,
                            str[i .. i + 1],
                            .{
                                .fg = self.text_color,
                                .bold = true,
                            },
                        );
                    }
                }
                {
                    self.infoBuf1 = @splat(0);
                    const percentage = @as(f32, @floatFromInt(node.hitCount)) / @as(f32, @floatFromInt(self.root.hitCountTotal)) * 100.0;
                    const str = try std.fmt.bufPrint(&self.infoBuf1, "hits: {} / {} ({:2.2}%)", .{ node.hitCount, self.root.hitCountTotal, percentage });

                    for (0..str.len) |i| {
                        self.drawCellOverBackground(
                            win,
                            @as(u16, @intCast(graphPaddingWBeg + i)),
                            win.height - graphPaddingHEnd + 3,
                            str[i .. i + 1],
                            .{
                                .fg = self.text_color,
                                .bold = true,
                            },
                        );
                    }
                }
                {
                    self.infoBuf2 = @splat(0);
                    const str = try std.fmt.bufPrint(&self.infoBuf2, "kind: {s}:{}", .{@tagName(node.kind), if (node.pid) |pid| pid else 0});

                    for (0..str.len) |i| {
                        self.drawCellOverBackground(
                            win,
                            @as(u16, @intCast(graphPaddingWBeg + i)),
                            win.height - graphPaddingHEnd + 4,
                            str[i .. i + 1],
                            .{
                                .fg = self.text_color,
                                .bold = true,
                            },
                        );
                    }
                }
            }
        }
    }
};

pub fn run_profile(allocator: std.mem.Allocator) anyerror!void {
    // try bpf.setupLoggerBackend(.zig);
    try bpf.setupLoggerBackend(.none);

    const code = try bpf.loadProgramAligned(allocator, @import("profile").bytecode);
    defer allocator.free(code);

    const object = try bpf.Object.load(code);
    defer object.free();

    const freq = 49;
    const cpuCount = try std.Thread.getCpuCount();
    {
        var links = try std.ArrayListUnmanaged(bpf.Object.Link).initCapacity(allocator, cpuCount);
        defer links.clearAndFree(allocator);
        defer {
            for (links.items) |*link| {
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

            var link = try object.attachProgramPerfEventByName("do_sample", cpu, &attributes);
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
        .pid = null,
        .address = 0,
    });

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
                            .kind = .User,
                            .address = stack_ips[i],
                            .pid = curr_key.pid,
                        },
                    );
                    count += 1;
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
                            .address = stack_ips[i],
                            .pid = null,
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

    try vx.setMouseMode(tty.writer(), true);
    try vx.enterAltScreen(tty.writer());
    try vx.queryTerminal(tty.writer(), 1 * std.time.ns_per_s);

    var flamegraph = try FlameGraph.init(allocator, root);
    var interface = FlameGraphInterface.init(allocator, &flamegraph);

    var mouse: ?vaxis.Mouse = null;
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
            .mouse => |m| {
                mouse = m;
            },
        }

        const win = vx.window();

        try interface.draw(win, mouse);
        try vx.render(tty.writer());
    }
}
