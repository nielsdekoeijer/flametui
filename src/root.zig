pub const App = @import("app.zig").App;
pub const SymbolTrieList = @import("app.zig").SymbolTrieList;
pub const Interface = @import("tui.zig").Interface;
pub const SymbolTrie = @import("symboltrie.zig").SymbolTrie;
pub const ThreadSafe = @import("lock.zig").ThreadSafe;

const std = @import("std");

test {
    std.testing.refAllDeclsRecursive(@import("bpf.zig"));
    std.testing.refAllDeclsRecursive(@import("kmap.zig"));
    std.testing.refAllDeclsRecursive(@import("lock.zig"));
    std.testing.refAllDeclsRecursive(@import("stacktrie.zig"));
    std.testing.refAllDeclsRecursive(@import("umap.zig"));
    std.testing.refAllDeclsRecursive(@import("sharedobject.zig"));
    std.testing.refAllDeclsRecursive(@import("symboltrie.zig"));
    std.testing.refAllDecls(@import("profile.zig"));
}
