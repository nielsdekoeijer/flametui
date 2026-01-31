const vaxis = @import("vaxis");
const std = @import("std");
const SymbolTrie = @import("symboltrie.zig").SymbolTrie;

/// ===================================================================================================================
/// TUI
/// ===================================================================================================================

// TODO: Kind of not robust, probably better to use actual vaxis apis. I can't be bothered with that though,
// moreover this might be easier to swap out to a different plotting library (or roll our own?) down the line
const Canvas = struct {
    // Fixed constants, w.r.t provided window, where to start drawing certain things
    // This way of doing it is somewhat not robust, but essentially our window ought to look like:
    //
    // ```
    // (0,0)                                                        (W-1,0)
    // o------------------------------------------------------------------o
    // |                                                                  |
    // | o-FlameGraph---------------------------------------------------o | <-- FlamegraphBorderHBegBoundary
    // | |                                                              | |
    // | |                                                              | |
    // | |                                                              | |
    // | |                                                              | |
    // | |                                                              | |
    // | |                                                              | |
    // | |                                                              | |
    // | |                                                              | |
    // | |                                                              | |
    // | |                                                              | |
    // | o--------------------------------------------------------------o | <-- FlamegraphBorderHEndBoundary
    // |                                                                  | <-- divider
    // | o-Info---------------------------------------------------------o |
    // | |                                                              | |
    // | |                                                              | |
    // | |                                                              | |
    // | |                                                              | |
    // | o--------------------------------------------------------------o |
    // |                                                                  |
    // o------------------------------------------------------------------o
    // (0,H-1)                                                    (W-1,H-1)
    //
    // ```

    // Divider w.r.t. the bottom, i.e. height - 1
    const DividerBottomOffsetY = 7;

    // The offset from edges (i.e. 0, width - 1)
    const FlamegraphWBegBoundary = 1;
    const FlamegraphWEndBoundary = 1;

    // The offset from edges (i.e. 0 and divider)
    const FlamegraphHBegBoundary = 1;
    const FlamegraphHEndBoundary = 1;

    // The offset from edges (i.e. 0, width - 1)
    const FlamegraphWBegInside = FlamegraphWBegBoundary + 1;
    const FlamegraphWEndInside = FlamegraphWEndBoundary + 1;

    // The offset from edges (i.e. 0 and divider)
    const FlamegraphHBegInside = FlamegraphHBegBoundary + 1;
    const FlamegraphHEndInside = FlamegraphHEndBoundary + 1;

    // The offset from edges (i.e. 0, width - 1)
    const InfoWBegBoundary = 1;
    const InfoWEndBoundary = 1;

    // The offset from edges (i.e. divider, height - 1)
    const InfoHBegBoundary = 1;
    const InfoHEndBoundary = 1;

    // The offset from edges (i.e. 0, width - 1)
    const InfoWBegInside = InfoWBegBoundary + 1;
    const InfoWEndInside = InfoWEndBoundary - 1;

    // The offset from edges (i.e. divider, height - 1)
    const InfoHBegInside = InfoHBegBoundary + 1;
    const InfoHEndInside = InfoHEndBoundary - 1;

    const FlamegraphAreaTitle = "Flamegraph";
    const InfoAreaTitle = "Info";

    flamegraphWindowBegBoundaryX: u16,
    flamegraphWindowBegBoundaryY: u16,
    flamegraphWindowEndBoundaryX: u16,
    flamegraphWindowEndBoundaryY: u16,
    flamegraphWindowBegInsideX: u16,
    flamegraphWindowBegInsideY: u16,
    flamegraphWindowEndInsideX: u16,
    flamegraphWindowEndInsideY: u16,

    infoWindowBegBoundaryX: u16,
    infoWindowBegBoundaryY: u16,
    infoWindowEndBoundaryX: u16,
    infoWindowEndBoundaryY: u16,
    infoWindowBegInsideX: u16,
    infoWindowBegInsideY: u16,
    infoWindowEndInsideX: u16,
    infoWindowEndInsideY: u16,

    pub fn init(win: vaxis.Window) !Canvas {
        std.debug.assert(win.x_off == 0);
        std.debug.assert(win.y_off == 0);

        if (win.height <= DividerBottomOffsetY + FlamegraphHBegBoundary) {
            return error.InsufficientHeight;
        }

        if (win.width <= FlamegraphWBegBoundary + FlamegraphWEndBoundary) {
            return error.InsufficientWidth;
        }

        // positions inclusive
        const windowBegX = 0;
        const windowEndX = win.width;
        const windowBegY = 0;
        const windowEndY = win.height;

        // divider
        // const dividerBegX =  windowBegX;
        // const dividerEndX =  windowEndX;
        const dividerBegY = windowEndY - DividerBottomOffsetY;
        // const dividerEndY =  windowEndY;

        return Canvas{
            .flamegraphWindowBegBoundaryX = windowBegX + FlamegraphWBegBoundary,
            .flamegraphWindowBegBoundaryY = windowBegY + FlamegraphHBegBoundary,
            .flamegraphWindowEndBoundaryX = windowEndX - FlamegraphWEndBoundary,
            .flamegraphWindowEndBoundaryY = dividerBegY - FlamegraphHEndBoundary,
            .flamegraphWindowBegInsideX = windowBegX + FlamegraphWBegInside,
            .flamegraphWindowBegInsideY = windowBegY + FlamegraphHBegInside,
            .flamegraphWindowEndInsideX = windowEndX - FlamegraphWEndInside,
            .flamegraphWindowEndInsideY = dividerBegY - FlamegraphHEndInside,
            .infoWindowBegBoundaryX = windowBegX + InfoWBegBoundary,
            .infoWindowBegBoundaryY = dividerBegY + InfoHBegBoundary,
            .infoWindowEndBoundaryX = windowEndX - InfoWBegBoundary,
            .infoWindowEndBoundaryY = windowEndY - InfoHEndBoundary,
            .infoWindowBegInsideX = windowBegX + InfoWBegInside,
            .infoWindowBegInsideY = dividerBegY + InfoHBegInside,
            .infoWindowEndInsideX = windowEndX - InfoWBegInside,
            .infoWindowEndInsideY = windowEndY - InfoHEndInside,
        };
    }
};

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
    textColor: vaxis.Color = .{ .index = 15 },
    rootColor: vaxis.Color = .{ .index = 1 },
    kernColor: vaxis.Color = .{ .index = 2 },
    userColor: vaxis.Color = .{ .index = 4 },

    // Pre-reseve a buffer and a slice to the hit count we optionally print on screen
    infoBufHitCount: [512]u8 = std.mem.zeroes([512]u8),
    infoSliceHitCount: ?[]u8 = null,

    // Pre-reseve a buffer and a slice to the symbol name we optionally print on screen
    infoBufSymbol: [512]u8 = std.mem.zeroes([512]u8),
    infoSliceSymbol: ?[]u8 = null,

    // Pre-reseve a buffer and a slice to the shared object name we optionally print on screen
    infoBufSharedObjectName: [512]u8 = std.mem.zeroes([512]u8),
    infoSliceSharedObjectName: ?[]u8 = null,

    // Owns an allocator, arguably better if unmanaged
    // TODO: make interface unmanaged
    allocator: std.mem.Allocator,

    // We want the interface to be able to dynamically swap symbols tries in order to allow for updates, likely
    // with some triple buffering setup
    // TODO: likely, we will have multiple threads. Thus, we want to have a mutex to guard the symboltrie.
    // TODO: eventually, we want to support the output of e.g. perf or collapsed stack traces.
    symbols: ?*SymbolTrie,

    // Bare-bones init
    pub fn init(allocator: std.mem.Allocator) !Interface {
        return Interface{
            .allocator = allocator,
            .symbols = null,
        };
    }

    // Hashing function for consistent randomization of colors, using Greg's original
    fn hashName(name: []const u8, reverse: bool) f32 {
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

    /// Colors using greg's original version, provides the classic "flames" for flamegraphs.
    /// TODO: We don't differentiate per nodes, does original flamegraphs not do this?
    fn getColorFromNameOriginal(self: Interface, symbolName: []const u8, node: SymbolTrie.TrieNode) vaxis.Color {
        _ = self;
        _ = node;

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

    /// Colors using OUR color approach, based on the users color scheme!
    fn getColorFromName(self: Interface, symbolName: []const u8, node: SymbolTrie.TrieNode) vaxis.Color {
        const v1 = 0.5 - hashName(symbolName, true);
        const v2 = 0.5 - hashName(symbolName, false);
        const v3 = v2;

        // TODO: spaghetti, refactor this so that baseColor is provided as an input argument
        const baseColor = switch (node.payload) {
            .kernel => self.kernColor,
            .user => self.userColor,
            .root => self.rootColor,
        };

        switch (baseColor) {
            .rgb => return vaxis.Color{
                .rgb = .{
                    // TODO: refactor using saturating adds, this code lookes like shit man
                    @as(u8, @intCast(@max(0, @min(255, @as(i16, @intFromFloat(120.0 * v3)) + @as(i16, @intCast(baseColor.rgb[0])))))),
                    @as(u8, @intCast(@max(0, @min(255, @as(i16, @intFromFloat(120.0 * v1)) + @as(i16, @intCast(baseColor.rgb[1])))))),
                    @as(u8, @intCast(@max(0, @min(255, @as(i16, @intFromFloat(120.0 * v2)) + @as(i16, @intCast(baseColor.rgb[2])))))),
                },
            },
            else => return baseColor,
        }
    }

    // Vaxis events we want to subscribe to
    const Event = union(enum) {
        // User IO
        key_press: vaxis.Key,
        mouse: vaxis.Mouse,

        // Resize
        winsize: vaxis.Winsize,

        // When we query the colors for the TUI
        color_report: vaxis.Color.Report,
    };

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

        // Configure
        try vx.queryTerminal(tty.writer(), 1 * std.time.ns_per_s);

        // Setup event loop
        var loop = vaxis.Loop(Event){ .tty = &tty, .vaxis = &vx };
        try loop.init();

        // Configure vaxis
        try vx.setMouseMode(tty.writer(), true);
        defer vx.setMouseMode(tty.writer(), false) catch @panic("couldn't unset mouse mode");

        // Enter
        try vx.enterAltScreen(tty.writer());
        defer vx.exitAltScreen(tty.writer()) catch @panic("couldn't exit alt screen");

        // Start measuring events
        try loop.start();
        defer loop.stop();

        // Somewhat arbitrarily I chose this color to show
        try vx.queryColor(tty.writer(), .{ .index = 1 });
        try vx.queryColor(tty.writer(), .{ .index = 2 });
        try vx.queryColor(tty.writer(), .{ .index = 4 });

        // Main loop
        var mouse: ?vaxis.Mouse = null;
        tui_loop: while (true) {
            var event = loop.nextEvent();

            event_loop: while (true) {
                // Handle events
                switch (event) {
                    .color_report => |c| {
                        // We query to do the fancy pants gradients!! Yes
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
                            },
                            else => {},
                        }
                    },
                    // Presses
                    .key_press => |key| {
                        // Quit conditions
                        if (key.matches('q', .{}) or key.matches('c', .{ .ctrl = true })) {
                            break :tui_loop;
                        }
                    },
                    // Our resize logic
                    .winsize => |winsize| {
                        try vx.resize(self.allocator, tty.writer(), winsize);
                    },
                    // Mouse
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

            var timer = try std.time.Timer.start();
            {
                self.infoSliceHitCount = null;
                self.infoSliceSymbol = null;
                self.infoSliceSharedObjectName = null;

                const win = vx.window();
                try self.draw(win, mouse);
                try vx.render(tty.writer());
            }

            const elapsed_ns = timer.read();
            std.log.info("Draw took: {}ms ({}ns)\n", .{ elapsed_ns / std.time.ns_per_ms, elapsed_ns });
        }
    }

    // TODO: define the minimum and maximum size (oom) for the window such that we bail out when we obtain it
    // TODO: fuzz interactions + sizes to prevent crashes?

    // Padding for the flamegraph, we plot it slightly offset. We define "inside" (inside the border) and "border"
    // which means where the border is exactly.
    const FlamegraphBorderWBegBoundary = 3;
    const FlamegraphBorderWBegInside = 4;
    const FlamegraphBorderWEndBoundary = 3;
    const FlamegraphBorderWEndInside = 4;
    const FlamegraphBorderHBeg = 2;
    const FlamegraphBorderHEnd = 10;

    // Info defined relative to flamegraph
    const InfoBorderWBeg = 3;
    const InfoBorderWEnd = 4;
    const InfoBorderHBeg = 2;
    const InfoBorderHEnd = 1;

    // Draw a border
    fn drawBorder(self: Interface, title: []const u8, window: vaxis.Window, x1: u16, y1: u16, x2: u16, y2: u16, color: vaxis.Color) void {
        const style = vaxis.Style{
            .fg = color,
            .bold = true,
        };

        // Corners
        window.writeCell(x1, y1, .{
            .char = .{ .grapheme = "╔" },
            .style = style,
        });
        window.writeCell(x2, y1, .{
            .char = .{ .grapheme = "╗" },
            .style = style,
        });

        // Verticals
        for ((y1 + 1)..y2) |y| {
            self.drawCellOverBackground(window, x1, @intCast(y), "║", style);
            self.drawCellOverBackground(window, x2, @intCast(y), "║", style);
        }

        // Corners
        window.writeCell(x1, y2, .{
            .char = .{ .grapheme = "╚" },
            .style = style,
        });
        window.writeCell(x2, y2, .{
            .char = .{ .grapheme = "╝" },
            .style = style,
        });

        // Horitontal
        for ((x1 + 1)..x2) |x| {
            self.drawCellOverBackground(window, @intCast(x), y1, "═", style);
            self.drawCellOverBackground(window, @intCast(x), y2, "═", style);
        }

        // Print
        _ = vaxis.Window.printSegment(window, vaxis.Cell.Segment{ .text = title, .style = style, .link = .{} }, .{
            .col_offset = x1 + 2,
            .row_offset = y1,
            .commit = true,
            .wrap = .none,
        });
    }

    fn drawInfo(self: Interface, window: vaxis.Window) void {
        if (self.infoSliceHitCount) |slice| {
            for (0..slice.len) |i| {
                self.drawCellOverBackground(
                    window,
                    FlamegraphBorderWBegBoundary + @as(u16, @intCast(i)),
                    window.height - FlamegraphBorderHEnd + 3,
                    (&slice[i])[0..1],
                    .{
                        .fg = self.textColor,
                        .bold = true,
                    },
                );
            }
        }

        if (self.infoSliceSymbol) |slice| {
            for (0..slice.len) |i| {
                self.drawCellOverBackground(
                    window,
                    FlamegraphBorderWBegBoundary + @as(u16, @intCast(i)),
                    window.height - FlamegraphBorderHEnd + 4,
                    (&slice[i])[0..1],
                    .{
                        .fg = self.textColor,
                        .bold = true,
                    },
                );
            }
        }

        if (self.infoSliceSharedObjectName) |slice| {
            for (0..slice.len) |i| {
                self.drawCellOverBackground(
                    window,
                    FlamegraphBorderWBegBoundary + @as(u16, @intCast(i)),
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
        win.clear();

        // Compute the canvas, will error if our window is too small
        const canvas = Canvas.init(win) catch return;

        // Draw the flamegraph box
        self.drawBorder("FlameGraph", win, canvas.flamegraphWindowBegBoundaryX, canvas.flamegraphWindowBegBoundaryY, //
            canvas.flamegraphWindowEndBoundaryX, canvas.flamegraphWindowEndBoundaryY, self.textColor);

        // Draw the info box
        self.drawBorder("NodeInfo", win, canvas.infoWindowBegBoundaryX, canvas.infoWindowBegBoundaryY, //
            canvas.infoWindowEndBoundaryX, canvas.infoWindowEndBoundaryY, self.textColor);

        // We may not have any symbols loaded, in which case return
        if (self.symbols) |symbols| {
            // Internal size exclusive of the border
            const flamegraphW = canvas.flamegraphWindowEndInsideX - canvas.flamegraphWindowBegInsideX + 1; 
            const flamegraphH = canvas.flamegraphWindowEndInsideY - canvas.flamegraphWindowBegInsideY + 1; 

            // Draw recursively, first node is the root node
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
                .currentX = canvas.flamegraphWindowBegInsideX,

                // Where to start drawing Y coord
                .currentY = canvas.flamegraphWindowEndInsideY,
            });

            self.drawInfo(win);
        } else {
            return;
        }
    }

    fn drawSymbol(
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
        const rawBegX = (context.offsetNormalized) * @as(f32, @floatFromInt(context.widthCells)) + //
            @as(f32, @floatFromInt(context.currentX));
        const rawEndX = (context.offsetNormalized + context.widthNormalized) * @as(f32, @floatFromInt(context.widthCells)) + //
            @as(f32, @floatFromInt(context.currentX));

        const begX: u16 = @intFromFloat(rawBegX);
        const endX: u16 = @intFromFloat(rawEndX);
        const len = endX - begX;

        // If we have no cell to draw, no sense going any deeper
        if (len == 0) return;
        if (mouse) |m| {
            if ((begX <= m.col and m.col < endX) and m.row == context.currentY) {
                switch (entry.payload) {
                    .kernel => |payload| {
                        self.infoSliceHitCount = try std.fmt.bufPrint(&self.infoBufHitCount, "hit count:     {}", .{entry.hitCount});
                        self.infoSliceSymbol = try std.fmt.bufPrint(&self.infoBufSymbol, "[user] symbol: {s}", .{payload.symbol});
                    },
                    .root => |payload| {
                        self.infoSliceHitCount = try std.fmt.bufPrint(&self.infoBufHitCount, "hit count:     {}", .{entry.hitCount});
                        self.infoSliceSymbol = try std.fmt.bufPrint(&self.infoBufSymbol, "[root] symbol: {s}", .{payload.symbol});
                    },
                    .user => |payload| {
                        self.infoSliceHitCount = try std.fmt.bufPrint(&self.infoBufHitCount, "hit count:     {}", .{entry.hitCount});
                        self.infoSliceSymbol = try std.fmt.bufPrint(&self.infoBufSymbol, "[kern] symbol: {s}", .{payload.symbol});
                        self.infoSliceSharedObjectName = try std.fmt.bufPrint(&self.infoBufSharedObjectName, "object:        {s}", .{payload.dll});
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
