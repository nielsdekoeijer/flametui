const std = @import("std");

pub const Program = @import("profile_streaming");

/// ===================================================================================================================
/// Helpers
/// ===================================================================================================================
/// The event type from bpf
pub const EventTypeRaw = u64; 

/// Our parsed view over the raw data, note we dont clone for efficiencies sake
pub const EventType = struct {
    pid: u64,
    kips: []const u64,
    uips: []const u64,

    // We parse from a raw pointer
    pub fn init(raw: *const EventTypeRaw) EventType {
        const ev = @as([*]const u64, @ptrCast(raw));
        const us = ev[1] / 8;
        const ks = ev[2] / 8;

        const event = EventType{
            .pid = ev[0],
            .uips = ev[3 .. 3 + us],
            .kips = ev[3 + us .. 3 + us + ks],
        };

        return event;
    }
};

