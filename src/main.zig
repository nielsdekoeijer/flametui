const std = @import("std");
const flametui = @import("flametui");

// 1. Define defaults in a struct for clarity
const Config = struct {
    hz: usize = 49,
    duration_ms: u64 = 1000,

    pub fn usage(exe_name: []const u8) void {
        std.debug.print(
            \\Usage: {s} [options]
            \\
            \\Options:
            \\  --hz   <int>   Sampling frequency in Hertz (default: 49)
            \\  --time <int>   Profile duration in milliseconds (default: 1000)
            \\  --file <str>   Skip profiling, load from a collapsed stacktrace file instead
            \\  -h, --help     Print this help message
            \\
            \\
        , .{exe_name});
    }
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer {
        const deinit_status = gpa.deinit();
        if (deinit_status == .leak) {
            std.testing.expect(false) catch @panic("TEST FAIL");
        }
    }

    const underlying = gpa.allocator();
    var arena = std.heap.ArenaAllocator.init(underlying);
    defer arena.deinit();
    const allocator = arena.allocator();

    var config = Config{};

    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();

    const exe_name = args.next() orelse "flametui";

    var file: ?[]const u8 = null;
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--file")) {
            file = args.next() orelse {
                std.log.err("Missing value for --file", .{});
                Config.usage(exe_name);
                std.process.exit(1);
            };

            break;
        }

        if (std.mem.eql(u8, arg, "--hz")) {
            const val = args.next() orelse {
                std.log.err("Missing value for --hz", .{});
                Config.usage(exe_name);
                std.process.exit(1);
            };
            config.hz = std.fmt.parseInt(usize, val, 10) catch |err| {
                std.log.err("Invalid number for --hz: {s} ({})", .{ val, err });
                std.process.exit(1);
            };
        } else if (std.mem.eql(u8, arg, "--time")) {
            const val = args.next() orelse {
                std.log.err("Missing value for --time", .{});
                Config.usage(exe_name);
                std.process.exit(1);
            };
            config.duration_ms = std.fmt.parseInt(u64, val, 10) catch |err| {
                std.log.err("Invalid number for --time: {s} ({})", .{ val, err });
                std.process.exit(1);
            };
        } else if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            Config.usage(exe_name);
            std.process.exit(0);
        } else {
            std.log.err("Unknown argument: {s}", .{arg});
            Config.usage(exe_name);
            std.process.exit(1);
        }
    }

    if (file) |f| {
        var symboltrie = try flametui.SymbolTrie.init(allocator);
        defer symboltrie.free();

        var handle = try std.fs.cwd().openFile(f, .{});
        defer handle.close();

        var buffer: [4096]u8 = undefined;
        var reader = handle.reader(&buffer);
        try symboltrie.loadCollapsed(&reader.interface);

        var interface = try flametui.Interface.init(allocator);
        interface.populate(&symboltrie);

        try interface.start();
    } else {
        var app = try flametui.App.init(allocator);
        defer app.free();
        try app.run(config.hz, config.duration_ms * std.time.ns_per_ms);
    }
}
