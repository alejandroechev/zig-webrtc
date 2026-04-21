const std = @import("std");

pub fn main() !void {
    std.debug.print("zig-webrtc v0.1.0-dev\n", .{});
    std.debug.print("Modules: stun, turn, sdp, ice, dtls, srtp, rtp, sctp, datachannel, peer\n", .{});
}
