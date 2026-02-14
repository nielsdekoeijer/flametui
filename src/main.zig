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
    if (!VerboseLogEnabled) {
        return;
    }

    std.log.defaultLog(level, scope, format, args);
}

/// ===================================================================================================================
/// Helper
/// ===================================================================================================================
fn requireRoot(writer: *std.Io.Writer, exe_name: []const u8) void {
    if (std.os.linux.geteuid() != 0) {
        Options.exitWithUsage(writer, exe_name, "Insufficient permissions: requires root\n", .{});
    }
}

fn configureProfiler(profiler: anytype, general: Options.GeneralOptions, pid: ?[]i32) void {
    profiler.globals.enable_idle = if (general.enable_idle) 1 else 0;

    if (pid) |p| {
        const len = @min(32, p.len);
        for (0..len) |i| {
            profiler.globals.pids[i] = @intCast(p[i]);
        }
        profiler.globals.pids_len = len;
    } else {
        profiler.globals.pids_len = 0;
    }
}

/// ===================================================================================================================
/// Arguments
/// ===================================================================================================================
const Options = struct {
    /// Shared options for all subcommands
    general: GeneralOptions,

    /// Options per command
    command: CommandOptions,

    /// Commands
    const Command = enum {
        fixed,
        aggregate,
        ring,
        file,
        stdin,
    };

    /// General options
    const GeneralOptions = struct {
        verbose: bool = false,
        enable_idle: bool = false,
    };

    /// Commands with args
    const CommandOptions = union(Command) {
        fixed: struct {
            hz: usize = 49,
            ms: u64 = 1000,
            pid: ?[]i32 = null,
            bins: usize = 1,

            pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
                if (self.pid) |pid| {
                    allocator.free(pid);
                }

                self.* = undefined;
            }
        },
        aggregate: struct {
            hz: usize = 49,
            pid: ?[]i32 = null,

            pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
                if (self.pid) |pid| {
                    allocator.free(pid);
                }

                self.* = undefined;
            }
        },
        ring: struct {
            hz: usize = 49,
            ms: u64 = 50,
            n: usize = 10,
            pid: ?[]i32 = null,

            pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
                if (self.pid) |pid| {
                    allocator.free(pid);
                }

                self.* = undefined;
            }
        },
        file: struct {
            file_path: ?[]const u8 = null,

            pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
                _ = self;
                _ = allocator;
            }
        },
        stdin: struct {
            pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
                _ = self;
                _ = allocator;
            }
        },
    };

    pub fn usage(exe_name: []const u8, writer: *std.Io.Writer) !void {
        try writer.print(
            \\Usage: {s} [command] [options]
            \\
            \\Commands:
            \\  fixed          Run profiling for a fixed duration 
            \\  aggregate      Run profiling indefinitely, aggregating stack traces
            \\  ring           Run profiling with a sliding window ring buffer
            \\  file           Load and visualize a collapsed stacktrace file
            \\
            \\Options (fixed): 
            \\  --hz   <int>    (optional) Sampling frequency in Hertz (default: 49)
            \\  --ms   <int>    (optional) Profile duration in milliseconds (default: 1000)
            \\  --bins <int>    (optional) Number of bins to split into (default: 1)
            \\  --pid  <int>    (optional) Process id we want to view (default: -1, all processes)
            \\
            \\Options (aggregate):
            \\  --hz   <int>    (optional) Sampling frequency in Hertz (default: 49)
            \\  --pid  <int>    (optional) Process id we want to view (default: -1, all processes)
            \\
            \\Options (ring):  
            \\  --hz   <int>    (optional) Sampling frequency in Hertz (default: 49)
            \\  --ms   <int>    (optional) Size of ring slot in milliseconds (default: 50)
            \\  --n    <int>    (optional) Number of slots in ring buffer, minimum 4 (default: 10)
            \\  --pid  <int>    (optional) Process id we want to view (default: -1, all processes)
            \\
            \\Options (path):  
            \\  --path <str>   (required) Path to the collapsed stack trace file
            \\
            \\General:
            \\  --verbose      (optional) Enable verbose logging
            \\  --enable-idle  (optional) While measuring, include idle processes (i.e. pid 0)
            \\  -h, --help     (optional) Print this help message
            \\
            \\
        , .{exe_name});

        try writer.flush();
    }

    // Helper that prints help and exits
    fn exitWithUsage(writer: *std.Io.Writer, exe_name: []const u8, comptime fmt: []const u8, fmtargs: anytype) noreturn {
        writer.print(fmt, fmtargs) catch {};
        Options.usage(exe_name, writer) catch {};
        writer.flush() catch {};
        std.process.exit(1);
    }

    /// Args
    fn parseIntArgOrExit(
        comptime T: type,
        args: *std.process.ArgIterator,
        flag: []const u8,
        writer: *std.Io.Writer,
        exe_name: []const u8,
    ) T {
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

    /// Args
    fn parseIntSliceArgOrExit(
        comptime T: type,
        allocator: std.mem.Allocator,
        args: *std.process.ArgIterator,
        flag: []const u8,
        writer: *std.Io.Writer,
        exe_name: []const u8,
    ) ![]T {
        const val = args.next() orelse {
            writer.print("Missing value for {s}\n", .{flag}) catch {};
            Options.usage(exe_name, writer) catch {};
            writer.flush() catch {};
            std.process.exit(1);
        };

        var tokens = std.mem.splitScalar(u8, val, ' ');
        var arraylist = std.ArrayListUnmanaged(T){};

        while (tokens.next()) |token| {
            const int = std.fmt.parseInt(T, token, 10) catch |err| {
                writer.print("Invalid number for {s}: {s} ({})\n", .{ flag, token, err }) catch {};
                writer.flush() catch {};
                std.process.exit(1);
            };

            arraylist.append(allocator, int) catch |err| {
                writer.print("Failed to parse integer list: {}\n", .{err}) catch {};
                writer.flush() catch {};
                std.process.exit(1);
            };
        }

        return try arraylist.toOwnedSlice(allocator);
    }

    /// Get arguments
    fn getArgumentsOrExit(writer: *std.Io.Writer) std.process.ArgIterator {
        return std.process.argsWithAllocator(std.heap.page_allocator) catch {
            writer.print("Failed to get process arguments\n", .{}) catch {};
            writer.flush() catch {};
            std.process.exit(1);
        };
    }

    pub fn parse(allocator: std.mem.Allocator, writer: *std.Io.Writer) !Options {
        var args = getArgumentsOrExit(writer);
        defer args.deinit();

        const exe_name = args.next() orelse "flametui";

        const cmd_str = blk: {
            const cmd_str = args.next();

            if (cmd_str == null) {
                if (!std.fs.File.stdin().isTty()) {
                    return .{ .general = .{}, .command = .{ .stdin = .{} } };
                }
                Options.usage(exe_name, writer) catch {};
                std.process.exit(1);
            }

            break :blk cmd_str.?;
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
                    opts.hz = parseIntArgOrExit(usize, &args, "--hz", writer, exe_name);
                } else if (std.mem.eql(u8, arg, "--ms")) {
                    opts.ms = parseIntArgOrExit(u64, &args, "--ms", writer, exe_name);
                } else if (std.mem.eql(u8, arg, "--bins")) {
                    opts.bins = parseIntArgOrExit(usize, &args, "--bins", writer, exe_name);
                } else if (std.mem.eql(u8, arg, "--pid")) {
                    opts.pid = try parseIntSliceArgOrExit(i32, allocator, &args, "--pid", writer, exe_name);
                } else if (parseGeneralOption(arg, &args, &general, exe_name, writer)) {
                    // handled
                } else {
                    exitWithUsage(writer, exe_name, "Unknown option for 'fixed': {s}\n", .{arg});
                }
            }
            return .{ .general = general, .command = .{ .fixed = opts } };
        } else if (std.mem.eql(u8, cmd_str, "aggregate")) {
            var opts: @TypeOf(@as(CommandOptions, .{ .aggregate = .{} }).aggregate) = .{};
            while (args.next()) |arg| {
                if (std.mem.eql(u8, arg, "--hz")) {
                    opts.hz = parseIntArgOrExit(usize, &args, "--hz", writer, exe_name);
                } else if (std.mem.eql(u8, arg, "--pid")) {
                    opts.pid = try parseIntSliceArgOrExit(i32, allocator, &args, "--pid", writer, exe_name);
                } else if (parseGeneralOption(arg, &args, &general, exe_name, writer)) {
                    // handled
                } else {
                    exitWithUsage(writer, exe_name, "Unknown option for 'aggregate': {s}\n", .{arg});
                }
            }
            return .{ .general = general, .command = .{ .aggregate = opts } };
        } else if (std.mem.eql(u8, cmd_str, "ring")) {
            var opts: @TypeOf(@as(CommandOptions, .{ .ring = .{} }).ring) = .{};
            while (args.next()) |arg| {
                if (std.mem.eql(u8, arg, "--hz")) {
                    opts.hz = parseIntArgOrExit(usize, &args, "--hz", writer, exe_name);
                } else if (std.mem.eql(u8, arg, "--ms")) {
                    opts.ms = parseIntArgOrExit(u64, &args, "--ms", writer, exe_name);
                } else if (std.mem.eql(u8, arg, "--pid")) {
                    opts.pid = try parseIntSliceArgOrExit(i32, allocator, &args, "--pid", writer, exe_name);
                } else if (std.mem.eql(u8, arg, "--n")) {
                    opts.n = parseIntArgOrExit(usize, &args, "--n", writer, exe_name);
                    if (opts.n < 4) {
                        exitWithUsage(writer, exe_name, "Ring buffer requires at least 4 slots, got {}\n", .{opts.n});
                    }
                } else if (parseGeneralOption(arg, &args, &general, exe_name, writer)) {
                    // handled
                } else {
                    exitWithUsage(writer, exe_name, "Unknown option for 'ring': {s}\n", .{arg});
                }
            }
            return .{ .general = general, .command = .{ .ring = opts } };
        } else if (std.mem.eql(u8, cmd_str, "file")) {
            var opts: @TypeOf(@as(CommandOptions, .{ .file = .{} }).file) = .{};
            while (args.next()) |arg| {
                if (std.mem.eql(u8, arg, "--path")) {
                    opts.file_path = args.next() orelse {
                        exitWithUsage(writer, exe_name, "Missing value for --path\n", .{});
                    };
                } else if (parseGeneralOption(arg, &args, &general, exe_name, writer)) {
                    // handled
                } else if (!std.mem.startsWith(u8, arg, "-")) {
                    opts.file_path = arg;
                } else {
                    exitWithUsage(writer, exe_name, "Unknown option for 'file': {s}\n", .{arg});
                }
            }
            if (opts.file_path == null) {
                exitWithUsage(writer, exe_name, "Missing file path for 'file' command\n", .{});
            }
            return .{ .general = general, .command = .{ .file = opts } };
        } else {
            exitWithUsage(writer, exe_name, "Unknown command: {s}\n", .{cmd_str});
        }
    }

    fn parseGeneralOption(
        arg: []const u8,
        args: *std.process.ArgIterator,
        general: *GeneralOptions,
        exe_name: []const u8,
        writer: *std.Io.Writer,
    ) bool {
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
    defer {
        const check = backend.deinit();
        if (check == .leak) {
            std.debug.print("Memory leak detected!\n", .{});
        }
    }
    const allocator = backend.allocator();

    var stderr_buf: [512]u8 = undefined;
    var stderr = std.fs.File.stderr().writer(&stderr_buf);
    const writer = &stderr.interface;

    var opts = try Options.parse(allocator, writer);
    defer {
        switch (opts.command) {
            inline else => |*command| command.deinit(allocator),
        }
    }

    switch (opts.command) {
        .fixed => |command| {
            requireRoot(writer, "flametui");

            var app = try flametui.FixedApp.init(allocator, command.bins);
            defer app.deinit();

            configureProfiler(app.app.profiler, opts.general, command.pid);

            try app.run(command.hz, command.ms * std.time.ns_per_ms);
        },
        .aggregate => |command| {
            requireRoot(writer, "flametui");

            var app = try flametui.AggregateApp.init(allocator);
            defer app.deinit();

            configureProfiler(app.app.profiler, opts.general, command.pid);

            try app.run(command.hz);
        },
        .ring => |command| {
            requireRoot(writer, "flametui");

            var app = try flametui.RingApp.init(allocator);
            defer app.deinit();

            configureProfiler(app.app.profiler, opts.general, command.pid);

            try app.run(command.hz, command.ms * std.time.ns_per_ms, command.n);
        },
        .file => |file| {
            const path = file.file_path orelse unreachable;

            var handle = std.fs.cwd().openFile(path, .{}) catch |err| {
                writer.print("Could not open file '{s}': {}\n", .{ path, err }) catch {};
                writer.flush() catch {};
                std.process.exit(1);
            };
            defer handle.close();

            // MAJOR ISSUE: if lines longer than 8192 -> we're fucked.
            // TODO: switch all readers to streaming where applicable
            var buffer: [8192]u8 = undefined;
            var reader = handle.reader(&buffer);

            try flametui.FileApp.run(allocator, &reader.interface);
        },
        .stdin => {
            // MAJOR ISSUE: if lines longer than 8192 -> we're fucked.
            // TODO: switch all readers to streaming where applicable
            var stdin_buf: [8192]u8 = undefined;
            var stdin = std.fs.File.stdin().reader(&stdin_buf);

            try flametui.StdinApp.run(allocator, &stdin.interface);
        },
    }
}
