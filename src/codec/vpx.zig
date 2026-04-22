//! VP8 video codec encoder/decoder bindings
//!
//! Wraps the libvpx C API for VP8 encoding and decoding.
//! VP8 is a mandatory-to-implement video codec for WebRTC (RFC 7742).

const std = @import("std");

const c = @cImport({
    @cInclude("vpx/vpx_encoder.h");
    @cInclude("vpx/vpx_decoder.h");
    @cInclude("vpx/vp8cx.h");
    @cInclude("vpx/vp8dx.h");
});

// Re-export the vpx C namespace so other modules share the same types
pub const vpx_c = c;
pub const vpx_image_t = c.vpx_image_t;
pub const VPX_IMG_FMT_I420 = c.VPX_IMG_FMT_I420;
pub const VPX_CODEC_CX_FRAME_PKT = c.VPX_CODEC_CX_FRAME_PKT;
pub const VPX_EFLAG_FORCE_KF = c.VPX_EFLAG_FORCE_KF;

// ============================================================================
// Errors
// ============================================================================

pub const VpxError = error{
    VpxConfigFailed,
    VpxInitFailed,
    VpxEncodeFailed,
    VpxDecodeFailed,
    VpxImageAllocFailed,
};

// ============================================================================
// EncodedFrame — a single encoded frame retrieved from the encoder
// ============================================================================

pub const EncodedFrame = struct {
    data: []const u8,
    pts: i64,
    is_keyframe: bool,
};

// ============================================================================
// Vp8Encoder
// ============================================================================

pub const Vp8Encoder = struct {
    codec: c.vpx_codec_ctx_t,
    cfg: c.vpx_codec_enc_cfg_t,
    width: u32,
    height: u32,

    /// Initialise a VP8 encoder.
    /// `bitrate_kbps` is the target bitrate in kilobits per second.
    pub fn init(width: u32, height: u32, bitrate_kbps: u32, fps: u32) VpxError!Vp8Encoder {
        var cfg: c.vpx_codec_enc_cfg_t = undefined;
        if (c.vpx_codec_enc_config_default(c.vpx_codec_vp8_cx(), &cfg, 0) != c.VPX_CODEC_OK) {
            return error.VpxConfigFailed;
        }

        cfg.g_w = width;
        cfg.g_h = height;
        cfg.rc_target_bitrate = bitrate_kbps;
        cfg.g_timebase.num = 1;
        cfg.g_timebase.den = @intCast(fps);
        cfg.g_error_resilient = c.VPX_ERROR_RESILIENT_DEFAULT;
        cfg.g_lag_in_frames = 0; // realtime
        cfg.rc_end_usage = c.VPX_CBR;

        var codec: c.vpx_codec_ctx_t = undefined;
        if (c.vpx_codec_enc_init_ver(
            &codec,
            c.vpx_codec_vp8_cx(),
            &cfg,
            0,
            c.VPX_ENCODER_ABI_VERSION,
        ) != c.VPX_CODEC_OK) {
            return error.VpxInitFailed;
        }

        return .{
            .codec = codec,
            .cfg = cfg,
            .width = width,
            .height = height,
        };
    }

    /// Encode one YUV420 frame. Returns a list of encoded packets.
    /// The returned slices point into codec-internal memory and are only
    /// valid until the next call to `encode` or `deinit`.
    pub fn encode(self: *Vp8Encoder, img: *c.vpx_image_t, pts: i64, flags: c_uint) VpxError!EncodeIterator {
        const flags_cast: c.vpx_enc_frame_flags_t = @bitCast(@as(c_long, @intCast(flags)));
        if (c.vpx_codec_encode(&self.codec, img, pts, 1, flags_cast, c.VPX_DL_REALTIME) != c.VPX_CODEC_OK) {
            return error.VpxEncodeFailed;
        }
        return .{ .ctx = &self.codec, .iter = null };
    }

    /// Flush the encoder (pass null image to get remaining packets).
    pub fn flush(self: *Vp8Encoder) VpxError!EncodeIterator {
        if (c.vpx_codec_encode(&self.codec, null, 0, 1, 0, c.VPX_DL_REALTIME) != c.VPX_CODEC_OK) {
            return error.VpxEncodeFailed;
        }
        return .{ .ctx = &self.codec, .iter = null };
    }

    pub fn deinit(self: *Vp8Encoder) void {
        _ = c.vpx_codec_destroy(&self.codec);
    }
};

/// Iterator over encoded packets from the VP8 encoder.
pub const EncodeIterator = struct {
    ctx: *c.vpx_codec_ctx_t,
    iter: c.vpx_codec_iter_t,

    /// Get the next encoded frame, or null if no more packets.
    pub fn next(self: *EncodeIterator) ?EncodedFrame {
        while (true) {
            const pkt = c.vpx_codec_get_cx_data(self.ctx, &self.iter);
            if (pkt == null) return null;
            if (pkt.*.kind == c.VPX_CODEC_CX_FRAME_PKT) {
                const frame_data = pkt.*.data.frame;
                const buf_ptr: [*]const u8 = @ptrCast(frame_data.buf);
                return .{
                    .data = buf_ptr[0..frame_data.sz],
                    .pts = frame_data.pts,
                    .is_keyframe = (frame_data.flags & c.VPX_FRAME_IS_KEY) != 0,
                };
            }
            // skip non-frame packets
        }
    }
};

// ============================================================================
// Vp8Decoder
// ============================================================================

pub const Vp8Decoder = struct {
    codec: c.vpx_codec_ctx_t,

    pub fn init() VpxError!Vp8Decoder {
        var codec: c.vpx_codec_ctx_t = undefined;
        if (c.vpx_codec_dec_init_ver(
            &codec,
            c.vpx_codec_vp8_dx(),
            null,
            0,
            c.VPX_DECODER_ABI_VERSION,
        ) != c.VPX_CODEC_OK) {
            return error.VpxInitFailed;
        }
        return .{ .codec = codec };
    }

    /// Decode a compressed VP8 frame. Returns an iterator over decoded images.
    /// The returned images point into codec-internal memory and are only
    /// valid until the next `decode` or `deinit` call.
    pub fn decode(self: *Vp8Decoder, data: []const u8) VpxError!DecodeIterator {
        if (c.vpx_codec_decode(&self.codec, data.ptr, @intCast(data.len), null, 0) != c.VPX_CODEC_OK) {
            return error.VpxDecodeFailed;
        }
        return .{ .ctx = &self.codec, .iter = null };
    }

    pub fn deinit(self: *Vp8Decoder) void {
        _ = c.vpx_codec_destroy(&self.codec);
    }
};

/// Iterator over decoded frames from the VP8 decoder.
pub const DecodeIterator = struct {
    ctx: *c.vpx_codec_ctx_t,
    iter: c.vpx_codec_iter_t,

    /// Get the next decoded image, or null if no more frames.
    pub fn next(self: *DecodeIterator) ?*c.vpx_image_t {
        return c.vpx_codec_get_frame(self.ctx, &self.iter);
    }
};

// ============================================================================
// Image helpers
// ============================================================================

/// Allocate a VPX image in I420 format into a caller-provided struct.
pub fn initImage(img: *c.vpx_image_t, width: u32, height: u32) VpxError!void {
    if (c.vpx_img_alloc(img, c.VPX_IMG_FMT_I420, width, height, 16) == null) {
        return error.VpxImageAllocFailed;
    }
}

/// Free a VPX image.
pub fn freeImage(img: *c.vpx_image_t) void {
    c.vpx_img_free(img);
}

// ============================================================================
// Tests
// ============================================================================

test "vp8 encode/decode roundtrip" {
    const width: u32 = 320;
    const height: u32 = 240;

    var enc = try Vp8Encoder.init(width, height, 256, 30);
    defer enc.deinit();

    var dec = try Vp8Decoder.init();
    defer dec.deinit();

    // Allocate and fill a test image (solid green in I420)
    var img: c.vpx_image_t = undefined;
    try initImage(&img, width, height);
    defer freeImage(&img);

    // Y=149, U=43, V=21 is approximately green in YUV
    const y_size = width * height;
    const uv_size = (width / 2) * (height / 2);
    const y_plane: [*]u8 = img.planes[0];
    const u_plane: [*]u8 = img.planes[1];
    const v_plane: [*]u8 = img.planes[2];
    @memset(y_plane[0..y_size], 149);
    @memset(u_plane[0..uv_size], 43);
    @memset(v_plane[0..uv_size], 21);

    // Encode with keyframe flag
    var iter = try enc.encode(&img, 0, c.VPX_EFLAG_FORCE_KF);
    const frame = iter.next();
    try std.testing.expect(frame != null);

    const encoded = frame.?.data;
    try std.testing.expect(encoded.len > 0);
    try std.testing.expect(frame.?.is_keyframe);

    // Decode
    var dec_iter = try dec.decode(encoded);
    const decoded_img = dec_iter.next();
    try std.testing.expect(decoded_img != null);
    try std.testing.expectEqual(width, decoded_img.?.d_w);
    try std.testing.expectEqual(height, decoded_img.?.d_h);
}
