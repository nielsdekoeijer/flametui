const std = @import("std");
const Io = std.Io;

const flametui = @import("flametui");

pub fn main(init: std.process.Init) !void {
    try flametui.run_profile(init.io, init.arena.allocator()) ;
}

