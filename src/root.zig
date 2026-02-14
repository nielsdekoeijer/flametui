pub const RingApp = @import("app.zig").RingApp;
pub const AggregateApp = @import("app.zig").AggregateApp;
pub const FixedApp = @import("app.zig").FixedApp;
pub const FileApp = @import("app.zig").FileApp;
pub const StdinApp = @import("app.zig").StdinApp;

test {
    const std = @import("std");
    std.testing.refAllDeclsRecursive(@import("bpf.zig"));
    std.testing.refAllDeclsRecursive(@import("kmap.zig"));
    std.testing.refAllDeclsRecursive(@import("lock.zig"));
    std.testing.refAllDeclsRecursive(@import("stacktrie.zig"));
    std.testing.refAllDeclsRecursive(@import("umap.zig"));
    std.testing.refAllDeclsRecursive(@import("sharedobject.zig"));
    std.testing.refAllDeclsRecursive(@import("symboltrie.zig"));
    std.testing.refAllDecls(@import("profile.zig"));
}
