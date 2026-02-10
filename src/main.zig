const std = @import("std");
const flametui = @import("flametui");

var verbose: bool = false;

pub const std_options: std.Options = .{
    .logFn = logHandle,
};

fn logHandle(
    comptime level: std.log.Level,
    comptime scope: @Type(.enum_literal),
    comptime format: []const u8,
    args: anytype,
) void {
    if (!verbose) return;
    std.log.defaultLog(level, scope, format, args);
}

const Command = enum {
    fixed,
    aggregate,
    ring,
    file,
};

const Config = struct {
    command: Command,
    hz: usize = 49,
    duration_ms: u64 = 1000,
    ring_slots: usize = 10,
    file_path: ?[]const u8 = null,

    pub fn usage(exe_name: []const u8, writer: *std.Io.Writer) !void {
        try writer.print(
            \\Usage: {s} [command] [options]
            \\
            \\Commands:
            \\  fixed        Run profiling for a fixed duration (default: 1000ms)
            \\  aggregate    Run profiling indefinitely, aggregating stack traces
            \\  ring         Run profiling with a sliding window ring buffer
            \\  file <path>  Load and visualize a collapsed stacktrace file
            \\
            \\Options (fixed):
            \\  --hz <int>   Sampling frequency in Hertz (default: 49)
            \\  --ms <int>   Profile duration in milliseconds (default: 1000)
            \\
            \\Options (aggregate):
            \\  --hz <int>   Sampling frequency in Hertz (default: 49)
            \\
            \\Options (ring):
            \\  --hz <int>   Sampling frequency in Hertz (default: 49)
            \\  --ms <int>   Size of ring slot in milliseconds (default: 50)
            \\  --n  <int>   Number of slots in ring buffer, minimum 4 (default: 10)
            \\
            \\General:
            \\  --verbose    Enable verbose logging
            \\  -h, --help   Print this help message
            \\
            \\
        , .{exe_name});
        try writer.flush();
    }
};

fn parseIntArg(comptime T: type, args: *std.process.ArgIterator, flag: []const u8, writer: *std.Io.Writer, exe_name: []const u8) T {
    const val = args.next() orelse {
        writer.print("Missing value for {s}\n", .{flag}) catch {};
        Config.usage(exe_name, writer) catch {};
        writer.flush() catch {};
        std.process.exit(1);
    };
    return std.fmt.parseInt(T, val, 10) catch |err| {
        writer.print("Invalid number for {s}: {s} ({})\n", .{ flag, val, err }) catch {};
        writer.flush() catch {};
        std.process.exit(1);
    };
}

fn exitWithMessage(writer: *std.Io.Writer, exe_name: []const u8, comptime fmt: []const u8, fmtargs: anytype) noreturn {
    writer.print(fmt, fmtargs) catch {};
    Config.usage(exe_name, writer) catch {};
    writer.flush() catch {};
    std.process.exit(1);
}

pub fn main() !void {
    var backend = std.heap.GeneralPurposeAllocator(.{}).init;
    const allocator = backend.allocator();

    var stderr_buf: [512]u8 = undefined;
    var stderr = std.fs.File.stderr().writer(&stderr_buf);

    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();

    const exe_name = args.next() orelse "flametui";

    const cmd_str = args.next() orelse {
        try Config.usage(exe_name, &stderr.interface);
        std.process.exit(1);
    };

    // Handle --help / -h as first argument
    if (std.mem.eql(u8, cmd_str, "--help") or std.mem.eql(u8, cmd_str, "-h")) {
        try Config.usage(exe_name, &stderr.interface);
        std.process.exit(0);
    }

    // Parse command
    const command: Command = if (std.mem.eql(u8, cmd_str, "fixed"))
        .fixed
    else if (std.mem.eql(u8, cmd_str, "aggregate"))
        .aggregate
    else if (std.mem.eql(u8, cmd_str, "ring"))
        .ring
    else if (std.mem.eql(u8, cmd_str, "file"))
        .file
    else {
        exitWithMessage(&stderr.interface, exe_name, "Unknown command: {s}\n", .{cmd_str});
    };

    var config = Config{ .command = command };

    // Parse remaining args
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--verbose")) {
            verbose = true;
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            try Config.usage(exe_name, &stderr.interface);
            std.process.exit(0);
        } else if (std.mem.eql(u8, arg, "--hz")) {
            config.hz = parseIntArg(usize, &args, "--hz", &stderr.interface, exe_name);
        } else if (std.mem.eql(u8, arg, "--ms")) {
            config.duration_ms = parseIntArg(u64, &args, "--ms", &stderr.interface, exe_name);
        } else if (std.mem.eql(u8, arg, "--n")) {
            config.ring_slots = parseIntArg(usize, &args, "--n", &stderr.interface, exe_name);
        } else if (!std.mem.startsWith(u8, arg, "-")) {
            // Positional argument — only valid for `file` command
            if (config.command == .file) {
                config.file_path = arg;
            } else {
                exitWithMessage(&stderr.interface, exe_name, "Unexpected argument: {s}\n", .{arg});
            }
        } else {
            exitWithMessage(&stderr.interface, exe_name, "Unknown option: {s}\n", .{arg});
        }
    }

    switch (config.command) {
        .fixed => {
            requireRoot(&stderr.interface, exe_name);

            var app = try flametui.App.init(allocator);
            defer app.free();

            const timeout_ns = @as(u64, config.duration_ms) * std.time.ns_per_ms;
            try app.runFixed(config.hz, timeout_ns);
        },
        .aggregate => {
            requireRoot(&stderr.interface, exe_name);

            var app = try flametui.App.init(allocator);
            defer app.free();

            try app.runAggregate(config.hz);
        },
        .ring => {
            requireRoot(&stderr.interface, exe_name);

            if (config.ring_slots < 4) {
                exitWithMessage(&stderr.interface, exe_name, "Ring buffer requires at least 4 slots, got {}\n", .{config.ring_slots});
            }

            var app = try flametui.App.init(allocator);
            defer app.free();

            const slot_ns = @as(u64, config.duration_ms) * std.time.ns_per_ms;
            try app.runRing(config.hz, slot_ns, config.ring_slots);
        },
        .file => {
            const path = config.file_path orelse {
                exitWithMessage(&stderr.interface, exe_name, "Missing file path for 'file' command\n", .{});
            };

            var handle = std.fs.cwd().openFile(path, .{}) catch |err| {
                stderr.interface.print("Could not open file '{s}': {}\n", .{ path, err }) catch {};
                stderr.interface.flush() catch {};
                std.process.exit(1);
            };
            defer handle.close();

            var buffer: [4096]u8 = undefined;
            var reader = handle.reader(&buffer);

            const symboltrie = try allocator.create(flametui.SymbolTrie);
            symboltrie.* = try flametui.SymbolTrie.initCollapsed(allocator, &reader.interface);
            defer symboltrie.free();
            defer allocator.destroy(symboltrie);

            var symbols = flametui.ThreadSafe(flametui.SymbolTrie).init(symboltrie);
            var interface = try flametui.Interface.init(allocator, &symbols);
            try interface.start();
        },
    }
}

fn requireRoot(writer: *std.Io.Writer, exe_name: []const u8) void {
    if (std.os.linux.geteuid() != 0) {
        exitWithMessage(writer, exe_name, "Insufficient permissions: requires root\n", .{});
    }
}
