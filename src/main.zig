const std = @import("std");
const Io = std.Io;

const flametui = @import("flametui");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    var arena = std.heap.ArenaAllocator.init(gpa.allocator());
    try flametui.run_profile(arena.allocator()) ;
}

