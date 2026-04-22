//! Opus audio codec encoder/decoder bindings (RFC 6716)
//!
//! Wraps the libopus C API for encoding and decoding audio.
//! Opus is the mandatory-to-implement audio codec for WebRTC (RFC 7874).

const std = @import("std");

const c = @cImport({
    @cInclude("opus/opus.h");
});

// ============================================================================
// Application modes (re-exported for convenience)
// ============================================================================

pub const Application = enum(c_int) {
    voip = c.OPUS_APPLICATION_VOIP,
    audio = c.OPUS_APPLICATION_AUDIO,
    restricted_lowdelay = c.OPUS_APPLICATION_RESTRICTED_LOWDELAY,
};

// ============================================================================
// Errors
// ============================================================================

pub const OpusError = error{
    OpusInitFailed,
    OpusEncodeFailed,
    OpusDecodeFailed,
};

// ============================================================================
// OpusEncoder
// ============================================================================

pub const OpusEncoder = struct {
    encoder: *c.OpusEncoder,
    sample_rate: i32,
    channels: i32,

    /// Create an Opus encoder.
    /// `sample_rate` must be one of 8000, 12000, 16000, 24000, 48000.
    /// `channels` must be 1 (mono) or 2 (stereo).
    pub fn init(sample_rate: i32, channels: i32, application: Application) OpusError!OpusEncoder {
        var err: c_int = 0;
        const enc = c.opus_encoder_create(sample_rate, channels, @intFromEnum(application), &err);
        if (err != c.OPUS_OK or enc == null) return error.OpusInitFailed;
        return .{
            .encoder = enc.?,
            .sample_rate = sample_rate,
            .channels = channels,
        };
    }

    /// Encode PCM samples to Opus. Returns the number of bytes written to `out`.
    /// `pcm` length must be `frame_size * channels` where frame_size corresponds
    /// to 2.5, 5, 10, 20, 40, or 60 ms at the configured sample rate.
    pub fn encode(self: *OpusEncoder, pcm: []const i16, out: []u8) OpusError!usize {
        const frame_size: c_int = @intCast(@divExact(pcm.len, @as(usize, @intCast(self.channels))));
        const ret = c.opus_encode(
            self.encoder,
            pcm.ptr,
            frame_size,
            out.ptr,
            @intCast(out.len),
        );
        if (ret < 0) return error.OpusEncodeFailed;
        return @intCast(ret);
    }

    pub fn deinit(self: *OpusEncoder) void {
        c.opus_encoder_destroy(self.encoder);
    }
};

// ============================================================================
// OpusDecoder
// ============================================================================

pub const OpusDecoder = struct {
    decoder: *c.OpusDecoder,
    sample_rate: i32,
    channels: i32,

    /// Create an Opus decoder.
    pub fn init(sample_rate: i32, channels: i32) OpusError!OpusDecoder {
        var err: c_int = 0;
        const dec = c.opus_decoder_create(sample_rate, channels, &err);
        if (err != c.OPUS_OK or dec == null) return error.OpusInitFailed;
        return .{
            .decoder = dec.?,
            .sample_rate = sample_rate,
            .channels = channels,
        };
    }

    /// Decode an Opus packet to PCM samples. Returns the number of decoded
    /// samples *per channel* written into `pcm_out`.
    /// Pass `data = null` for packet loss concealment (PLC).
    pub fn decode(self: *OpusDecoder, data: ?[]const u8, pcm_out: []i16, fec: bool) OpusError!usize {
        const data_ptr: ?[*]const u8 = if (data) |d| d.ptr else null;
        const data_len: c_int = if (data) |d| @intCast(d.len) else 0;
        const max_frame_size: c_int = @intCast(@divExact(pcm_out.len, @as(usize, @intCast(self.channels))));
        const ret = c.opus_decode(
            self.decoder,
            data_ptr,
            data_len,
            pcm_out.ptr,
            max_frame_size,
            if (fec) @as(c_int, 1) else @as(c_int, 0),
        );
        if (ret < 0) return error.OpusDecodeFailed;
        return @intCast(ret);
    }

    pub fn deinit(self: *OpusDecoder) void {
        c.opus_decoder_destroy(self.decoder);
    }
};

// ============================================================================
// Tests
// ============================================================================

test "opus encode/decode roundtrip" {
    const sample_rate: i32 = 48000;
    const channels: i32 = 1;
    const frame_ms = 20;
    const frame_size: usize = @intCast(@divExact(sample_rate * frame_ms, 1000));

    // Create encoder and decoder
    var enc = try OpusEncoder.init(sample_rate, channels, .voip);
    defer enc.deinit();
    var dec = try OpusDecoder.init(sample_rate, channels);
    defer dec.deinit();

    // Generate a 440 Hz sine wave (one frame)
    var pcm_in: [frame_size]i16 = undefined;
    const freq: f32 = 440.0;
    const sr_f: f32 = @floatFromInt(sample_rate);
    for (0..frame_size) |i| {
        const t: f32 = @as(f32, @floatFromInt(i)) / sr_f;
        pcm_in[i] = @intFromFloat(16000.0 * @sin(2.0 * std.math.pi * freq * t));
    }

    // Encode
    var encoded: [4000]u8 = undefined;
    const enc_len = try enc.encode(&pcm_in, &encoded);
    try std.testing.expect(enc_len > 0);
    try std.testing.expect(enc_len < 4000);

    // Decode
    var pcm_out: [frame_size]i16 = undefined;
    const dec_samples = try dec.decode(encoded[0..enc_len], &pcm_out, false);
    try std.testing.expectEqual(frame_size, dec_samples);

    // Verify output has non-trivial content (not all zeros)
    var sum: i64 = 0;
    for (pcm_out[0..dec_samples]) |s| {
        if (s < 0) {
            sum += @as(i64, -@as(i32, s));
        } else {
            sum += @as(i64, s);
        }
    }
    try std.testing.expect(sum > 0);
}
