//! Codec bindings for WebRTC audio and video.
//!
//! - Opus (RFC 6716) — mandatory audio codec (RFC 7874)
//! - VP8 — mandatory video codec (RFC 7742)

pub const opus = @import("opus.zig");
pub const vpx = @import("vpx.zig");

test {
    @import("std").testing.refAllDecls(@This());
}
