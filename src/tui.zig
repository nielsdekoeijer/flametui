const vaxis = @import("vaxis");
const std = @import("std");
const SymbolTrie = @import("symboltrie.zig").SymbolTrie;

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

/// Object managing plotting and events
pub const Interface = struct {
    backgroundGradientBeg: vaxis.Color = .{ .rgb = .{ 0xEE, 0xEE, 0xB0 } },
    backgroundGradientEnd: vaxis.Color = .{ .rgb = .{ 0xEE, 0xEE, 0xEE } },
    textColor: vaxis.Color = .{ .index = 15 },
    rootColor: vaxis.Color = .{ .index = 1 },
    kernColor: vaxis.Color = .{ .index = 2 },
    userColor: vaxis.Color = .{ .index = 4 },

    infoBuf0: [512]u8 = std.mem.zeroes([512]u8),
    infoSlice0: ?[]u8 = null,
    infoBuf1: [512]u8 = std.mem.zeroes([512]u8),
    infoSlice1: ?[]u8 = null,
    infoBuf2: [512]u8 = std.mem.zeroes([512]u8),
    infoSlice2: ?[]u8 = null,

    allocator: std.mem.Allocator,
    symbols: ?*SymbolTrie,

    /// Colors using greg's original version
    pub fn getColorFromName(self: Interface, symbolName: []const u8, node: SymbolTrie.TrieNode) vaxis.Color {
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

        const v1 = 0.5 - hashName(symbolName, true);
        const v2 = 0.5 - hashName(symbolName, false);
        const v3 = v2;

        const baseColor = switch (node.payload) {
            .kernel => self.kernColor, // Use the user's Native Red for kernel
            .user => self.userColor, // Use the user's Native Green for user space
            .root => self.rootColor, // Use the user's Native Yellow for root
        };

        return vaxis.Color{
            .rgb = .{
                @as(u8, @intCast(@max(0, @min(255, @as(i16, @intFromFloat(120.0 * v3)) + @as(i16, @intCast(baseColor.rgb[0])))))),
                @as(u8, @intCast(@max(0, @min(255, @as(i16, @intFromFloat(120.0 * v1)) + @as(i16, @intCast(baseColor.rgb[1])))))),
                @as(u8, @intCast(@max(0, @min(255, @as(i16, @intFromFloat(120.0 * v2)) + @as(i16, @intCast(baseColor.rgb[2])))))),
            },
        };

        // return .{
        //     .rgb = .{
        //         @as(u8, @intFromFloat(50.0 * v3)) + 205,
        //         @as(u8, @intFromFloat(230.0 * v1)),
        //         @as(u8, @intFromFloat(55.0 * v2)),
        //     },
        // };
    }

    // Vaxis events we want to subscribe to
    const Event = union(enum) {
        key_press: vaxis.Key,
        winsize: vaxis.Winsize,
        mouse: vaxis.Mouse,
        color_report: vaxis.Color.Report,
    };

    pub fn init(allocator: std.mem.Allocator) !Interface {
        return Interface{
            .allocator = allocator,
            .symbols = null,
        };
    }

    // Switch out the symboltrie we use on the backend
    // TODO: this is shit we should improve it
    pub fn populate(self: *Interface, symbols: *SymbolTrie) void {
        self.symbols = symbols;
    }

    // Start drawing + event loop
    pub fn start(self: *Interface) !void {
        // Create tty handle
        const buffer: []u8 = try self.allocator.alloc(u8, 4096);
        defer self.allocator.free(buffer);
        var tty = try vaxis.Tty.init(buffer);
        defer tty.deinit();

        // Start vaxis
        var vx = try vaxis.init(self.allocator, .{});
        defer vx.deinit(self.allocator, tty.writer());

        // Setup event loop
        var loop = vaxis.Loop(Event){ .tty = &tty, .vaxis = &vx };
        try loop.init();
        defer tty.deinit();

        // Configure vaxis
        try vx.setMouseMode(tty.writer(), true);
        defer vx.setMouseMode(tty.writer(), false) catch @panic("couldn't unset mouse mode");
        try vx.enterAltScreen(tty.writer());
        defer vx.exitAltScreen(tty.writer()) catch @panic("couldn't exit alt screen");
        try vx.queryTerminal(tty.writer(), 1 * std.time.ns_per_s);

        try loop.start();
        defer loop.stop();

        var mouse: ?vaxis.Mouse = null;

        try vx.queryColor(tty.writer(), .{ .index = 1 });
        try vx.queryColor(tty.writer(), .{ .index = 2 });
        try vx.queryColor(tty.writer(), .{ .index = 4 });

        tui_loop: while (true) {
            var event = loop.nextEvent();
            event_loop: while (true) {
                // Handle events
                switch (event) {
                    .color_report => |c| {
                        switch (c.kind) {
                            .index => |i| {
                                switch (i) {
                                    1 => {
                                        self.rootColor = vaxis.Color{
                                            .rgb = c.value,
                                        };
                                    },
                                    2 => {
                                        self.userColor = vaxis.Color{
                                            .rgb = c.value,
                                        };
                                    },
                                    4 => {
                                        self.kernColor = vaxis.Color{
                                            .rgb = c.value,
                                        };
                                    },
                                    else => {},
                                }
                                self.textColor = vaxis.Color{ .index = i };
                            },
                            else => {},
                        }
                    },
                    .key_press => |key| {
                        if (key.matches('q', .{}) or key.matches('c', .{ .ctrl = true })) {
                            break :tui_loop;
                        }
                    },
                    .winsize => |winsize| {
                        try vx.resize(self.allocator, tty.writer(), winsize);
                    },
                    .mouse => |m| {
                        mouse = m;
                    },
                }

                if (loop.tryEvent()) |next| {
                    event = next;
                } else {
                    break :event_loop;
                }
            }

            {
                self.infoSlice0 = null;
                self.infoSlice1 = null;
                self.infoSlice2 = null;

                const win = vx.window();
                win.clear();
                try self.draw(win, mouse);
                try vx.render(tty.writer());
            }
        }
    }

    // Padding for the flamegrapg, we plot it slightly offset
    const FlamegraphBorderWBeg = 3;
    const FlamegraphBorderWEnd = 4;
    const FlamegraphBorderHBeg = 2;
    const FlamegraphBorderHEnd = 10;

    // Info defined relative to flamegraph
    const InfoBorderWBeg = 3;
    const InfoBorderWEnd = 4;
    const InfoBorderHBeg = 2;
    const InfoBorderHEnd = 1;

    // Clear a window with a nice gradient background
    fn drawBackgroundGradient(self: Interface, win: vaxis.Window) void {
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

    fn drawBackground(self: Interface, win: vaxis.Window) void {
        _ = win;
        _ = self;
    }

    // Draw a border
    fn drawBorder(self: Interface, title: []const u8, window: vaxis.Window, x1: u16, y1: u16, x2: u16, y2: u16, color: vaxis.Color) void {
        const style = vaxis.Style{
            .fg = color,
            .bold = true,
        };

        // Using Rounded corners for a more modern feel
        self.drawCellOverBackground(window, x1, y1, "╔", style);
        self.drawCellOverBackground(window, x2, y1, "╗", style);
        self.drawCellOverBackground(window, x1, y2, "╚", style);
        self.drawCellOverBackground(window, x2, y2, "╝", style);

        // Standard lines for sides
        for ((x1 + 1)..x2) |x| {
            self.drawCellOverBackground(window, @intCast(x), y1, "═", style);
            self.drawCellOverBackground(window, @intCast(x), y2, "═", style);
        }


        for (0..title.len) |i| {
            self.drawCellOverBackground(window, x1 + 2 + @as(u16, @intCast(i)), y1, (&title[i])[0..1], style);
        }

        for ((y1 + 1)..y2) |y| {
            self.drawCellOverBackground(window, x1, @intCast(y), "║", style);
            self.drawCellOverBackground(window, x2, @intCast(y), "║", style);
        }
    }

    fn drawInfo(self: Interface, window: vaxis.Window) void {
        if (self.infoSlice0) |slice| {
            for (0..slice.len) |i| {
                self.drawCellOverBackground(
                    window,
                    FlamegraphBorderWBeg + @as(u16, @intCast(i)),
                    window.height - FlamegraphBorderHEnd + 3,
                    (&slice[i])[0..1],
                    .{
                        .fg = self.textColor,
                        .bold = true,
                    },
                );
            }
        }

        if (self.infoSlice1) |slice| {
            for (0..slice.len) |i| {
                self.drawCellOverBackground(
                    window,
                    FlamegraphBorderWBeg + @as(u16, @intCast(i)),
                    window.height - FlamegraphBorderHEnd + 4,
                    (&slice[i])[0..1],
                    .{
                        .fg = self.textColor,
                        .bold = true,
                    },
                );
            }
        }

        if (self.infoSlice2) |slice| {
            for (0..slice.len) |i| {
                self.drawCellOverBackground(
                    window,
                    FlamegraphBorderWBeg + @as(u16, @intCast(i)),
                    window.height - FlamegraphBorderHEnd + 5,
                    (&slice[i])[0..1],
                    .{
                        .fg = self.textColor,
                        .bold = true,
                    },
                );
            }
        }
    }

    // Draw everything to the window
    fn draw(self: *Interface, win: vaxis.Window, mouse: ?vaxis.Mouse) !void {
        // Clear the background
        self.drawBackground(win);
        self.drawBorder(
            "FlameGraph",
            win,
            FlamegraphBorderWBeg - 1,
            FlamegraphBorderHBeg - 1,
            win.width - FlamegraphBorderWEnd + 1,
            win.height - FlamegraphBorderHEnd + 1,
            self.textColor,
        );

        self.drawBorder(
            "NodeInfo",
            win,
            InfoBorderWBeg - 1,
            win.height - FlamegraphBorderHEnd - InfoBorderHEnd + 3, 
            win.width - FlamegraphBorderWEnd + 1,
            win.height - InfoBorderHBeg + 1,
            self.textColor,
        );

        // We may not have any symbols loaded, in which case return
        if (self.symbols) |symbols| {
            const toSmallW = win.width <= FlamegraphBorderWBeg + FlamegraphBorderWEnd;
            const toSmallH = win.height <= FlamegraphBorderHBeg + FlamegraphBorderHEnd;

            if (toSmallW or toSmallH) return;

            // Internal size exclusive of the border
            const flamegraphW = win.width - FlamegraphBorderWBeg - FlamegraphBorderWEnd - 1;
            const flamegraphH = win.height - FlamegraphBorderHBeg - FlamegraphBorderHEnd;

            // Draw recursively, first node is the root node
            std.debug.assert(symbols.nodes.items[0].payload == .root);
            try self.drawSymbol(symbols.nodes.items[0], win, mouse, .{
                // We want to draw 100% of the availible space
                .widthNormalized = 1.0,

                // We start at the beginning
                .offsetNormalized = 0.0,

                // We have space consisting
                .widthCells = flamegraphW,

                // We have space consisting
                .heightCells = flamegraphH,

                // Where to start drawing X coord
                .currentX = FlamegraphBorderWBeg + 1,

                // Where to start drawing Y coord
                .currentY = win.height - FlamegraphBorderHEnd,
            });
        }

        self.drawInfo(win);
    }

    pub fn drawSymbol(
        self: *Interface,
        entry: SymbolTrie.TrieNode,
        win: vaxis.Window,
        mouse: ?vaxis.Mouse,
        context: struct {
            offsetNormalized: f32,
            widthNormalized: f32,
            widthCells: u16,
            heightCells: u16,
            currentX: u16,
            currentY: u16,
        },
    ) !void {
        // How we get the symbol name, works for all enums
        const symbol = blk: switch (entry.payload) {
            inline else => |s| break :blk s.symbol,
        };

        // How we draw the bar
        var style = vaxis.Style{
            .fg = .{ .index = 0 },
            .bg = self.getColorFromName(symbol, entry),
            .bold = true,
        };

        // The Y coordinate is fixed and given by the arguments. We have to calculate the X coordinate though.
        const rawBegX = (context.offsetNormalized) * @as(f32, @floatFromInt(context.widthCells)) + @as(f32, @floatFromInt(context.currentX));
        const rawEndX = (context.offsetNormalized + context.widthNormalized) * @as(f32, @floatFromInt(context.widthCells)) + @as(f32, @floatFromInt(context.currentX));
        const begX: u16 = @intFromFloat(rawBegX);
        const endX: u16 = @intFromFloat(rawEndX);
        const len = endX - begX;

        // If we have no cell to draw, no sense going any deeper
        if (len == 0) return;
        if (mouse) |m| {
            if ((begX <= m.col and m.col < endX) and m.row == context.currentY) {
                switch (entry.payload) {
                    .kernel => |payload| {
                        self.infoSlice0 = try std.fmt.bufPrint(&self.infoBuf0, "hit count:     {}", .{entry.hitCount});
                        self.infoSlice1 = try std.fmt.bufPrint(&self.infoBuf1, "[user] symbol: {s}", .{payload.symbol});
                    },
                    .root => |payload| {
                        self.infoSlice0 = try std.fmt.bufPrint(&self.infoBuf0, "hit count:     {}", .{entry.hitCount});
                        self.infoSlice1 = try std.fmt.bufPrint(&self.infoBuf1, "[root] symbol: {s}", .{payload.symbol});
                    },
                    .user => |payload| {
                        self.infoSlice0 = try std.fmt.bufPrint(&self.infoBuf0, "hit count:     {}", .{entry.hitCount});
                        self.infoSlice1 = try std.fmt.bufPrint(&self.infoBuf1, "[kern] symbol: {s}", .{payload.symbol});
                        self.infoSlice2 = try std.fmt.bufPrint(&self.infoBuf2, "object:        {s}", .{payload.dll});
                    },
                }
                style.bg = dimColor(style.bg, 0.7);
            }
        }

        // Collapse tagged union
        switch (entry.payload) {
            else => {
                const space: []const u8 = &[_]u8{' '};
                for (0..len) |i| {
                    const x = begX + @as(u16, @intCast(i));
                    const y = context.currentY;

                    const glyph = if (i < symbol.len) @as([]const u8, @ptrCast(&symbol[i])) else space;
                    win.writeCell(x, y, .{
                        .char = .{
                            .grapheme = glyph,
                            .width = 1,
                        },
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
            const child = self.symbols.?.nodes.items[id];

            const childWidth = @as(f32, @floatFromInt(child.hitCount)) / @as(f32, @floatFromInt(entry.hitCount)) * context.widthNormalized;
            std.debug.assert(childWidth <= 1.1);

            // stop drawing if we leave the screen
            if (context.currentY - 1 < FlamegraphBorderHBeg) {
                return;
            }

            try self.drawSymbol(child, win, mouse, .{
                .currentX = context.currentX,
                .currentY = context.currentY - 1,
                .widthCells = context.widthCells,
                .heightCells = context.heightCells,
                .widthNormalized = childWidth,
                .offsetNormalized = childOffset,
            });

            childOffset += childWidth;
        }
    }

    // Helper to draw over an existing node, keeping its background style
    fn drawCellOverBackground(self: Interface, win: vaxis.Window, x: u16, y: u16, char: []const u8, style: vaxis.Style) void {
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
};
