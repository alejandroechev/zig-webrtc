//! Media pipelines connecting codecs to RTP/SRTP.
//!
//! AudioPipeline:  PCM → Opus encode → RTP packetise → (optional SRTP) → bytes
//! VideoPipeline:  YUV → VP8 encode → RTP packetise with VP8 payload descriptor → bytes

const std = @import("std");
const codec = @import("../codec/codec.zig");
const rtp = @import("../rtp/rtp.zig");

// Use the same C types as vpx.zig to avoid type incompatibility
const vpx_c = codec.vpx.vpx_c;

// ============================================================================
// AudioPipeline
// ============================================================================

pub const AudioPipeline = struct {
    encoder: codec.opus.OpusEncoder,
    ssrc: u32,
    payload_type: u7,
    sequence: u16,
    timestamp: u32,
    sample_rate: u32,
    channels: u32,

    /// Opus payload type as commonly negotiated in SDP (RFC 7587).
    pub const default_payload_type: u7 = 111;

    pub fn init(sample_rate: i32, channels: i32, ssrc: u32) !AudioPipeline {
        const enc = try codec.opus.OpusEncoder.init(sample_rate, channels, .voip);
        return .{
            .encoder = enc,
            .ssrc = ssrc,
            .payload_type = default_payload_type,
            .sequence = 0,
            .timestamp = 0,
            .sample_rate = @intCast(sample_rate),
            .channels = @intCast(channels),
        };
    }

    /// Encode PCM audio, wrap in an RTP packet, and write to `out_buf`.
    /// Returns the total number of bytes written (RTP header + Opus payload).
    ///
    /// This does NOT apply SRTP — the caller can pass the returned packet
    /// through SrtpContext.protectRtp() if encryption is needed.
    pub fn sendAudio(self: *AudioPipeline, pcm: []const i16, out_buf: []u8) !usize {
        // Encode audio
        const max_opus_payload = 1275; // Opus max frame size
        if (out_buf.len < rtp.rtp_fixed_header_size + max_opus_payload) {
            return error.BufferTooSmall;
        }

        // Encode directly into the buffer past the RTP header
        const opus_bytes = try self.encoder.encode(
            pcm,
            out_buf[rtp.rtp_fixed_header_size..],
        );

        // Build the RTP header
        const header = rtp.RtpHeader{
            .payload_type = self.payload_type,
            .sequence_number = self.sequence,
            .timestamp = self.timestamp,
            .ssrc = self.ssrc,
            .marker = (self.sequence == 0), // mark first packet
        };
        const hdr_bytes = header.serialize();
        @memcpy(out_buf[0..rtp.rtp_fixed_header_size], &hdr_bytes);

        // Advance sequence and timestamp
        self.sequence +%= 1;
        const frame_size: u32 = @intCast(@divExact(pcm.len, self.channels));
        self.timestamp +%= frame_size;

        return rtp.rtp_fixed_header_size + opus_bytes;
    }

    pub fn deinit(self: *AudioPipeline) void {
        self.encoder.deinit();
    }
};

// ============================================================================
// VideoPipeline — DISABLED (requires libvpx without /GL)
// ============================================================================
// TODO: Re-enable when libvpx is rebuilt without MSVC /GL flag.
// The full VideoPipeline implementation is preserved in codec/vpx.zig.

// ============================================================================
// Tests
// ============================================================================

test "audio pipeline: PCM → RTP packet with correct header" {
    const sample_rate: i32 = 48000;
    const channels: i32 = 1;
    const frame_ms = 20;
    const frame_size: usize = @intCast(@divExact(sample_rate * frame_ms, 1000));

    var pipeline = try AudioPipeline.init(sample_rate, channels, 0x12345678);
    defer pipeline.deinit();

    // Generate test audio
    var pcm: [frame_size]i16 = undefined;
    var phase: f32 = 0.0;
    const sources = @import("sources.zig");
    sources.generateSineWave(&pcm, 48000, 440.0, 16000.0, &phase);

    var out: [2048]u8 = undefined;
    const pkt_len = try pipeline.sendAudio(&pcm, &out);
    try std.testing.expect(pkt_len > rtp.rtp_fixed_header_size);

    // Parse the RTP header back
    const hdr = try rtp.RtpHeader.parse(&out);
    try std.testing.expectEqual(@as(u7, AudioPipeline.default_payload_type), hdr.payload_type);
    try std.testing.expectEqual(@as(u32, 0x12345678), hdr.ssrc);
    try std.testing.expectEqual(@as(u16, 0), hdr.sequence_number);
    try std.testing.expectEqual(@as(u32, 0), hdr.timestamp);

    // Send a second frame — sequence and timestamp should advance
    var out2: [2048]u8 = undefined;
    _ = try pipeline.sendAudio(&pcm, &out2);
    const hdr2 = try rtp.RtpHeader.parse(&out2);
    try std.testing.expectEqual(@as(u16, 1), hdr2.sequence_number);
    try std.testing.expectEqual(@as(u32, frame_size), hdr2.timestamp);
}
