const std = @import("std");
const Io = std.Io;

const flametui = @import("flametui");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    var arena = std.heap.ArenaAllocator.init(gpa.allocator());
    defer arena.deinit();

    var app = try @import("flametui").App.init(arena.allocator());
    defer app.free();
    try app.run(49, 1_000_000_000);
}

