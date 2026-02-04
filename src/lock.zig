const std = @import("std");

/// Generic thread-safe wrapper.
pub fn ThreadSafe(comptime T: type) type {
    return struct {
        mutex: std.Thread.Mutex = .{},
        data: *T,

        const Self = @This();

        pub fn init(data: *T) Self {
            return .{ .data = data };
        }

        pub fn lock(self: *Self) *T {
            self.mutex.lock();
            return self.data;
        }

        pub fn unlock(self: *Self) void {
            self.mutex.unlock();
        }
    };
}
