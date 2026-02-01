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

const Config = struct {
    hz: usize = 49,
    duration_ms: u64 = 1000,

    pub fn usage(exe_name: []const u8, print: *std.Io.Writer) !void {
        try print.print(
            \\Usage: {s} [command] [options]
            \\
            \\Commands:
            \\  record       Run profiling
            \\  file <path>  Load a collapsed stacktrace file
            \\
            \\Options (record):
            \\  --hz <int>   Sampling frequency in Hertz (default: 49)
            \\  -ms <int>    Profile duration in milliseconds (default: 1000)
            \\
            \\General:
            \\  --verbose    Enable verbose logging
            \\  -h, --help   Print this help message
            \\
            \\
        , .{exe_name});

        try print.flush();
    }
};

pub fn main() !void {
    const memory_size = 256 * 1024 * 1024; 
    const backing_buffer = try std.heap.page_allocator.alloc(u8, memory_size);
    defer std.heap.page_allocator.free(backing_buffer);

    var fba = std.heap.FixedBufferAllocator.init(backing_buffer);
    const underlying = fba.allocator();

    var arena = std.heap.ArenaAllocator.init(underlying);
    defer arena.deinit();
    const allocator = arena.allocator();

    var stderrBuffer: [512]u8 = undefined;
    var stderrWriter = std.fs.File.stderr().writer(&stderrBuffer);

    var config = Config{};

    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();

    const exe_name = args.next() orelse "flametui";

    const cmd = args.next() orelse {
        try Config.usage(exe_name, &stderrWriter.interface);
        std.process.exit(1);
    };

    if (std.mem.eql(u8, cmd, "record")) {
        while (args.next()) |arg| {
            if (std.mem.eql(u8, arg, "--verbose")) {
                verbose = true;
            } else if (std.mem.eql(u8, arg, "--hz")) {
                const val = args.next() orelse {
                    try stderrWriter.interface.print("Missing value for --hz", .{});
                    try Config.usage(exe_name, &stderrWriter.interface);
                    try stderrWriter.interface.flush();
                    std.process.exit(1);
                };
                config.hz = std.fmt.parseInt(usize, val, 10) catch |err| {
                    try stderrWriter.interface.print("Invalid number for --hz: {s} ({})", .{ val, err });
                    try stderrWriter.interface.flush();
                    std.process.exit(1);
                };
            } else if (std.mem.eql(u8, arg, "-ms")) {
                const val = args.next() orelse {
                    try stderrWriter.interface.print("Missing value for -ms", .{});
                    try Config.usage(exe_name, &stderrWriter.interface);
                    try stderrWriter.interface.flush();
                    std.process.exit(1);
                };
                config.duration_ms = std.fmt.parseInt(u64, val, 10) catch |err| {
                    try stderrWriter.interface.print("Invalid number for -ms: {s} ({})", .{ val, err });
                    try stderrWriter.interface.flush();
                    std.process.exit(1);
                };
            } else {
                try stderrWriter.interface.print("Unknown argument: {s}", .{arg});
                try Config.usage(exe_name, &stderrWriter.interface);
                try stderrWriter.interface.flush();
                std.process.exit(1);
            }
        }

        if (std.os.linux.geteuid() != 0) {
            try stderrWriter.interface.print("Insufficient permissions: requires root to record\n", .{});
            try stderrWriter.interface.flush();
            std.process.exit(1);
        }

        var app = try flametui.App.init(allocator);
        defer app.free();
        try app.run(config.hz, config.duration_ms * std.time.ns_per_ms);
    } else if (std.mem.eql(u8, cmd, "file")) {
        var file: ?[]const u8 = null;
        while (args.next()) |arg| {
            if (std.mem.eql(u8, arg, "--verbose")) {
                verbose = true;
            } else if (!std.mem.startsWith(u8, arg, "-")) {
                file = arg;
            } else {
                try stderrWriter.interface.print("Unknown argument: {s}", .{arg});
                try Config.usage(exe_name, &stderrWriter.interface);
                try stderrWriter.interface.flush();
                std.process.exit(1);
            }
        }

        if (file) |f| {
            var handle = try std.fs.cwd().openFile(f, .{});
            defer handle.close();

            var buffer: [4096]u8 = undefined;
            var reader = handle.reader(&buffer);

            var symboltrie = try flametui.SymbolTrie.initCollapsed(allocator, &reader.interface);
            defer symboltrie.free();

            var interface = try flametui.Interface.init(allocator);
            interface.populate(&symboltrie);

            try interface.start();
        } else {
            try stderrWriter.interface.print("Missing file path", .{});
            try Config.usage(exe_name, &stderrWriter.interface);
            try stderrWriter.interface.flush();
            std.process.exit(1);
        }
    } else {
        try Config.usage(exe_name, &stderrWriter.interface);
        try stderrWriter.interface.flush();
        std.process.exit(0);
    }
}
