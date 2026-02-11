const std = @import("std");
const flametui = @import("flametui");

/// ===================================================================================================================
/// Logging
/// ===================================================================================================================
/// Pass our handle
pub const std_options: std.Options = .{
    .logFn = logHandle,
};

/// Global to parameterize the logging
var VerboseLogEnabled: bool = false;

/// Log function
fn logHandle(
    comptime level: std.log.Level,
    comptime scope: @Type(.enum_literal),
    comptime format: []const u8,
    args: anytype,
) void {
    if (!VerboseLogEnabled) return;
    std.log.defaultLog(level, scope, format, args);
}

/// ===================================================================================================================
/// Arguments
/// ===================================================================================================================
fn parseIntArg(comptime T: type, args: *std.process.ArgIterator, flag: []const u8, writer: *std.Io.Writer, exe_name: []const u8) T {
    const val = args.next() orelse {
        writer.print("Missing value for {s}\n", .{flag}) catch {};
        Options.usage(exe_name, writer) catch {};
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
    Options.usage(exe_name, writer) catch {};
    writer.flush() catch {};
    std.process.exit(1);
}

const Options = struct {
    general: GeneralOptions,
    command: CommandOptions,

    const Command = enum {
        fixed,
        aggregate,
        ring,
        file,
    };

    const CommandOptions = union(Command) {
        fixed: struct {
            hz: usize = 49,
            ms: u64 = 1000,
        },
        aggregate: struct {
            hz: usize = 49,
        },
        ring: struct {
            hz: usize = 49,
            ms: u64 = 50,
            n: u64 = 4,
        },
        file: struct {
            file_path: ?[]const u8 = null,
        },
    };

    const GeneralOptions = struct {
        verbose: bool = false,
        enable_idle: bool = false,
    };

    pub fn usage(exe_name: []const u8, writer: *std.Io.Writer) !void {
        try writer.print(
            \\Usage: {s} [command] [options]
            \\
            \\Commands:
            \\  fixed          Run profiling for a fixed duration (default: 1000ms)
            \\  aggregate      Run profiling indefinitely, aggregating stack traces
            \\  ring           Run profiling with a sliding window ring buffer
            \\  file           Load and visualize a collapsed stacktrace file
            \\
            \\Options (fixed)  :
            \\  --hz <int>     Sampling frequency in Hertz (default: 49)
            \\  --ms <int>     Profile duration in milliseconds (default: 1000)
            \\
            \\Options (aggregate):
            \\  --hz <int>     Sampling frequency in Hertz (default: 49)
            \\
            \\Options (ring):  
            \\  --hz <int>     Sampling frequency in Hertz (default: 49)
            \\  --ms <int>     Size of ring slot in milliseconds (default: 50)
            \\  --n  <int>     Number of slots in ring buffer, minimum 4 (default: 10)
            \\
            \\Options (path):  
            \\  --path <str>   Path to the collapsed stack trace file
            \\
            \\General:
            \\  --verbose      Enable verbose logging
            \\  --enable-idle  While measuring, filter out idle processes (i.e. pid 0)
            \\  -h, --help     Print this help message
            \\
            \\
        , .{exe_name});
        try writer.flush();
    }

    pub fn parse(allocator: std.mem.Allocator) Options {
        _ = allocator;

        var stderr_buf: [512]u8 = undefined;
        var stderr = std.fs.File.stderr().writer(&stderr_buf);
        const writer = &stderr.interface;

        var args = std.process.argsWithAllocator(std.heap.page_allocator) catch {
            writer.print("Failed to get process arguments\n", .{}) catch {};
            writer.flush() catch {};
            std.process.exit(1);
        };
        defer args.deinit();

        const exe_name = args.next() orelse "flametui";

        const cmd_str = args.next() orelse {
            Options.usage(exe_name, writer) catch {};
            std.process.exit(1);
        };

        if (std.mem.eql(u8, cmd_str, "--help") or std.mem.eql(u8, cmd_str, "-h")) {
            Options.usage(exe_name, writer) catch {};
            std.process.exit(0);
        }

        var general = GeneralOptions{};

        if (std.mem.eql(u8, cmd_str, "fixed")) {
            var opts: @TypeOf(@as(CommandOptions, .{ .fixed = .{} }).fixed) = .{};
            while (args.next()) |arg| {
                if (std.mem.eql(u8, arg, "--hz")) {
                    opts.hz = parseIntArg(usize, &args, "--hz", writer, exe_name);
                } else if (std.mem.eql(u8, arg, "--ms")) {
                    opts.ms = parseIntArg(u64, &args, "--ms", writer, exe_name);
                } else if (parseGeneralOption(arg, &args, &general, exe_name, writer)) {
                    // handled
                } else {
                    exitWithMessage(writer, exe_name, "Unknown option for 'fixed': {s}\n", .{arg});
                }
            }
            return .{ .general = general, .command = .{ .fixed = opts } };
        } else if (std.mem.eql(u8, cmd_str, "aggregate")) {
            var opts: @TypeOf(@as(CommandOptions, .{ .aggregate = .{} }).aggregate) = .{};
            while (args.next()) |arg| {
                if (std.mem.eql(u8, arg, "--hz")) {
                    opts.hz = parseIntArg(usize, &args, "--hz", writer, exe_name);
                } else if (parseGeneralOption(arg, &args, &general, exe_name, writer)) {
                    // handled
                } else {
                    exitWithMessage(writer, exe_name, "Unknown option for 'aggregate': {s}\n", .{arg});
                }
            }
            return .{ .general = general, .command = .{ .aggregate = opts } };
        } else if (std.mem.eql(u8, cmd_str, "ring")) {
            var opts: @TypeOf(@as(CommandOptions, .{ .ring = .{} }).ring) = .{};
            while (args.next()) |arg| {
                if (std.mem.eql(u8, arg, "--hz")) {
                    opts.hz = parseIntArg(usize, &args, "--hz", writer, exe_name);
                } else if (std.mem.eql(u8, arg, "--ms")) {
                    opts.ms = parseIntArg(u64, &args, "--ms", writer, exe_name);
                } else if (std.mem.eql(u8, arg, "--n")) {
                    opts.n = parseIntArg(u64, &args, "--n", writer, exe_name);
                    if (opts.n < 4) {
                        exitWithMessage(writer, exe_name, "Ring buffer requires at least 4 slots, got {}\n", .{opts.n});
                    }
                } else if (parseGeneralOption(arg, &args, &general, exe_name, writer)) {
                    // handled
                } else {
                    exitWithMessage(writer, exe_name, "Unknown option for 'ring': {s}\n", .{arg});
                }
            }
            return .{ .general = general, .command = .{ .ring = opts } };
        } else if (std.mem.eql(u8, cmd_str, "file")) {
            var opts: @TypeOf(@as(CommandOptions, .{ .file = .{} }).file) = .{};
            while (args.next()) |arg| {
                if (std.mem.eql(u8, arg, "--path")) {
                    opts.file_path = args.next() orelse {
                        exitWithMessage(writer, exe_name, "Missing value for --path\n", .{});
                    };
                } else if (parseGeneralOption(arg, &args, &general, exe_name, writer)) {
                    // handled
                } else if (!std.mem.startsWith(u8, arg, "-")) {
                    opts.file_path = arg;
                } else {
                    exitWithMessage(writer, exe_name, "Unknown option for 'file': {s}\n", .{arg});
                }
            }
            if (opts.file_path == null) {
                exitWithMessage(writer, exe_name, "Missing file path for 'file' command\n", .{});
            }
            return .{ .general = general, .command = .{ .file = opts } };
        } else {
            exitWithMessage(writer, exe_name, "Unknown command: {s}\n", .{cmd_str});
        }
    }

    fn parseGeneralOption(arg: []const u8, args: *std.process.ArgIterator, general: *GeneralOptions, exe_name: []const u8, writer: *std.Io.Writer) bool {
        _ = args;
        if (std.mem.eql(u8, arg, "--verbose")) {
            general.verbose = true;
            VerboseLogEnabled = true;
            return true;
        } else if (std.mem.eql(u8, arg, "--enable-idle")) {
            general.enable_idle = true;
            return true;
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            Options.usage(exe_name, writer) catch {};
            std.process.exit(0);
        }
        return false;
    }
};

pub fn main() !void {
    var backend = std.heap.GeneralPurposeAllocator(.{}).init;
    const allocator = backend.allocator();

    const opts = Options.parse(allocator);

    switch (opts.command) {
        .fixed => |fixed| {
            var stderr_buf: [512]u8 = undefined;
            var stderr = std.fs.File.stderr().writer(&stderr_buf);
            requireRoot(&stderr.interface, "flametui");

            var app = try flametui.App.init(allocator);
            defer app.free();

            if (opts.general.enable_idle) {
                app.profiler.globals.enable_idle = 1;
            } else {
                app.profiler.globals.enable_idle = 0;
            }

            const timeout_ns = fixed.ms * std.time.ns_per_ms;
            try app.runFixed(fixed.hz, timeout_ns);
        },
        .aggregate => |agg| {
            var stderr_buf: [512]u8 = undefined;
            var stderr = std.fs.File.stderr().writer(&stderr_buf);
            requireRoot(&stderr.interface, "flametui");

            var app = try flametui.App.init(allocator);
            defer app.free();

            if (opts.general.enable_idle) {
                app.profiler.globals.enable_idle = 1;
            } else {
                app.profiler.globals.enable_idle = 0;
            }

            try app.runAggregate(agg.hz);
        },
        .ring => |ring| {
            var stderr_buf: [512]u8 = undefined;
            var stderr = std.fs.File.stderr().writer(&stderr_buf);
            requireRoot(&stderr.interface, "flametui");

            var app = try flametui.App.init(allocator);
            defer app.free();

            if (opts.general.enable_idle) {
                app.profiler.globals.enable_idle = 1;
            } else {
                app.profiler.globals.enable_idle = 0;
            }

            const slot_ns = ring.ms * std.time.ns_per_ms;
            try app.runRing(ring.hz, slot_ns, ring.n);
        },
        .file => |file| {
            const path = file.file_path.?;

            var stderr_buf: [512]u8 = undefined;
            var stderr = std.fs.File.stderr().writer(&stderr_buf);

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
            defer symboltrie.deinit();
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
