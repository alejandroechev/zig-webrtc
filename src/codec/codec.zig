//! Codec bindings for WebRTC audio and video.
//!
//! - Opus (RFC 6716) — mandatory audio codec (RFC 7874)
//! - VP8 — mandatory video codec (RFC 7742) — DISABLED: vpx.lib /GL incompatible with Zig LLD

pub const opus = @import("opus.zig");
// pub const vpx = @import("vpx.zig"); // TODO: rebuild libvpx without /GL

test {
    _ = opus;
}
