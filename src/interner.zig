const std = @import("std");

/// String interner for non-threadsafe string deduplication
pub const StringInternerUnmanaged = struct {
    backend: std.StringArrayHashMapUnmanaged(usize),

    pub fn init() StringInternerUnmanaged {
        return .{ .backend = .empty };
    }

    pub fn deinit(self: *StringInternerUnmanaged, allocator: std.mem.Allocator) void {
        var iter = self.backend.iterator();
        while (iter.next()) |entry| {
            allocator.free(entry.key_ptr.*);
        }

        self.backend.deinit(allocator);

        self.* = undefined;
    }

    /// Mimics the allocator interface for seemless integration
    pub fn dupe(self: *StringInternerUnmanaged, allocator: std.mem.Allocator, key: []const u8) ![]const u8 {
        if (self.backend.getPtr(key)) |result| {
            result.* += 1;
            return self.backend.getKey(key).?;
        } else {
            const string = try allocator.dupe(u8, key);
            errdefer allocator.free(string);

            try self.backend.put(allocator, string, 1);

            return string;
        }
    }

    /// Decrements the reference count. Note that no deallocation happens at this stage.
    pub fn free(self: *StringInternerUnmanaged, key: []const u8) void {
        if (self.backend.getPtr(key)) |ref_count| {
            ref_count.* -|= 1;
        }
    }
};

test "StringInternerUnmanaged deduplicates identical strings" {
    var interner = StringInternerUnmanaged.init();
    // If the interner misses anything, testing.allocator will detect the leak.
    defer interner.deinit(std.testing.allocator);

    // Simulate a temporary buffer from reading a file
    var temp_buf: [32]u8 = undefined;
    @memcpy(temp_buf[0..11], "/usr/lib/so");

    const str1 = try interner.dupe(std.testing.allocator, temp_buf[0..11]);
    const str2 = try interner.dupe(std.testing.allocator, temp_buf[0..11]);

    try std.testing.expect(str1.ptr == str2.ptr);

    try std.testing.expectEqual(@as(usize, 2), interner.backend.get("/usr/lib/so").?);
    
    try std.testing.expectEqual(@as(usize, 1), interner.backend.count());
}

test "StringInternerUnmanaged keeps distinct strings separate" {
    var interner = StringInternerUnmanaged.init();
    defer interner.deinit(std.testing.allocator);

    const str1 = try interner.dupe(std.testing.allocator, "foo");
    const str2 = try interner.dupe(std.testing.allocator, "bar");

    try std.testing.expect(str1.ptr != str2.ptr);
    
    try std.testing.expectEqual(@as(usize, 1), interner.backend.get("foo").?);
    try std.testing.expectEqual(@as(usize, 1), interner.backend.get("bar").?);
    try std.testing.expectEqual(@as(usize, 2), interner.backend.count());
}

test "StringInternerUnmanaged free decrements reference count" {
    var interner = StringInternerUnmanaged.init();
    defer interner.deinit(std.testing.allocator);

    const str = try interner.dupe(std.testing.allocator, "kernel_panic");
    _ = try interner.dupe(std.testing.allocator, "kernel_panic");
    
    try std.testing.expectEqual(@as(usize, 2), interner.backend.get("kernel_panic").?);

    interner.free(str);
    try std.testing.expectEqual(@as(usize, 1), interner.backend.get("kernel_panic").?);

    interner.free(str);
    try std.testing.expectEqual(@as(usize, 0), interner.backend.get("kernel_panic").?);

    interner.free(str);
    try std.testing.expectEqual(@as(usize, 0), interner.backend.get("kernel_panic").?);
}
