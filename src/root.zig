//! zig-webrtc: A WebRTC library for Zig
//! Built using structured RFC rules as specification.
//!
//! Protocol stack:
//!   STUN → TURN → ICE → SDP → DTLS → SRTP → RTP → SCTP → DataChannel → PeerConnection

pub const stun = @import("stun/stun.zig");
pub const turn = @import("turn/turn.zig");
pub const sdp = @import("sdp/sdp.zig");
pub const ice = @import("ice/ice.zig");
pub const dtls = @import("dtls/dtls.zig");
pub const srtp = @import("srtp/srtp.zig");
pub const rtp = @import("rtp/rtp.zig");
pub const sctp = @import("sctp/sctp.zig");
pub const datachannel = @import("datachannel/datachannel.zig");
pub const peer = @import("peer/peer.zig");
pub const transport = @import("transport/transport.zig");

test {
    // Run all module tests
    @import("std").testing.refAllDecls(@This());
}
