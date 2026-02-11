const std = @import("std");

/// Generic thread-safe wrapper over a pointer of type T
pub fn ThreadSafe(comptime T: type) type {
    return struct {
        mutex: std.Thread.Mutex = .{},
        data: *T,

        const Self = @This();

        pub fn init(data: *T) Self {
            return .{ .data = data };
        }

        /// Acquire exclusive access to the data
        pub fn lock(self: *Self) *T {
            self.mutex.lock();
            return self.data;
        }

        /// Unlock self
        pub fn unlock(self: *Self) void {
            self.mutex.unlock();
        }

        /// Try to acquire the lock without blocking, returns null if the lock is already held.
        pub fn tryLock(self: *Self) ?*T {
            if (self.mutex.tryLock()) {
                return self.data;
            }
            return null;
        }
    };
}

test "ThreadSafe: concurrent increments maintain correctness" {
    const Context = struct {
        safe: *ThreadSafe(u32),
        iterations: u32,
    };

    var value: u32 = 0;
    var safe = ThreadSafe(u32).init(&value);

    const thread_count = 4;
    const iterations = 1000;

    var threads: [thread_count]std.Thread = undefined;

    for (&threads) |*thread| {
        thread.* = try std.Thread.spawn(.{}, struct {
            fn worker(ctx: Context) void {
                var i: u32 = 0;
                while (i < ctx.iterations) : (i += 1) {
                    const data = ctx.safe.lock();
                    defer ctx.safe.unlock();
                    data.* += 1;
                }
            }
        }.worker, .{Context{
            .safe = &safe,
            .iterations = iterations,
        }});
    }

    for (threads) |thread| {
        thread.join();
    }

    try std.testing.expectEqual(thread_count * iterations, value);
}
