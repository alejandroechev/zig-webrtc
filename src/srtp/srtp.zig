//! SRTP encryption (RFC 3711)
//! Generated using structured RFC rules from the RFC Compliance API.
//!
//! Implements the Secure Real-time Transport Protocol per RFC 3711:
//!
//! Rules implemented:
//!   rfc3711-s3.1-r1  — RTP padding SHALL be default method for transforms requiring padding
//!   rfc3711-s3.1-r3  — MKI SHALL NOT identify the crypto context (use SSRC+dest triplet)
//!   rfc3711-s3.1-r4  — Encryption SHALL be applied before authentication (encrypt-then-MAC)
//!   rfc3711-s3.2.1-r1 — Maintain s_l (highest received sequence number), SHOULD be authenticated
//!   rfc3711-s3.3-r1  — Receiver: verify auth tag, then decrypt (reverse of protect)
//!   rfc3711-s3.3.1   — Packet index = ROC * 65536 + SEQ
//!   rfc3711-s3.3.2   — Replay protection via 64-bit sliding window
//!   rfc3711-s3.4     — SRTCP index with E flag for encryption
//!   rfc3711-s4.1.1   — AES-128 in counter mode (AES-CM) for encryption
//!   rfc3711-s4.2     — HMAC-SHA1 authentication with truncated tags
//!   rfc3711-s4.3.1   — Key derivation using AES-CM PRF (labels 0x00–0x02)

const std = @import("std");
const mem = std.mem;
const crypto = std.crypto;
const HmacSha1 = crypto.auth.hmac.HmacSha1;
const Aes128 = crypto.core.aes.Aes128;

// ============================================================================
// Public types
// ============================================================================

/// Cryptographic profile / cipher suite for SRTP.
pub const SrtpProfile = enum {
    aes128_cm_hmac_sha1_80,
    aes128_cm_hmac_sha1_32,
    aead_aes_128_gcm,
    aead_aes_256_gcm,

    /// Length of the authentication tag appended to protected packets.
    pub fn authTagLen(self: SrtpProfile) usize {
        return switch (self) {
            .aes128_cm_hmac_sha1_80 => 10,
            .aes128_cm_hmac_sha1_32 => 4,
            .aead_aes_128_gcm => 16,
            .aead_aes_256_gcm => 16,
        };
    }

    /// Master key length in bytes.
    pub fn masterKeyLen(self: SrtpProfile) usize {
        return switch (self) {
            .aes128_cm_hmac_sha1_80, .aes128_cm_hmac_sha1_32, .aead_aes_128_gcm => 16,
            .aead_aes_256_gcm => 32,
        };
    }
};

/// Master keying material supplied by DTLS-SRTP handshake.
pub const SrtpKeyMaterial = struct {
    master_key: [16]u8,
    master_salt: [14]u8,
};

/// Derived session keys per RFC 3711 §4.3.1.
pub const SrtpSessionKeys = struct {
    cipher_key: [16]u8, // label 0x00
    auth_key: [20]u8, // label 0x01
    salt_key: [14]u8, // label 0x02
};

/// Per-SSRC cryptographic context (RFC 3711 §3.2.1).
pub const SrtpCryptoContext = struct {
    ssrc: u32,
    roc: u32 = 0,
    s_l: u16 = 0,
    replay_window: u64 = 0,
    highest_index: u48 = 0,
    session_keys: SrtpSessionKeys,
    profile: SrtpProfile,
    initialized: bool = false,
    // SRTCP state
    srtcp_index: u31 = 0,
};

/// Top-level SRTP context holding master key material and per-SSRC state.
pub const SrtpContext = struct {
    allocator: mem.Allocator,
    key_material: SrtpKeyMaterial,
    profile: SrtpProfile,
    contexts: std.AutoHashMap(u32, SrtpCryptoContext),

    // ========================================================================
    // Lifecycle
    // ========================================================================

    /// Initialise an SRTP context with master keying material.
    pub fn init(allocator: mem.Allocator, profile: SrtpProfile, key_material: SrtpKeyMaterial) SrtpContext {
        return .{
            .allocator = allocator,
            .key_material = key_material,
            .profile = profile,
            .contexts = std.AutoHashMap(u32, SrtpCryptoContext).init(allocator),
        };
    }

    pub fn deinit(self: *SrtpContext) void {
        self.contexts.deinit();
    }

    // ========================================================================
    // RTP protect / unprotect (RFC 3711 §3.1, §3.3)
    // ========================================================================

    /// Protect (encrypt + authenticate) a plaintext RTP packet.
    /// Returns an allocated buffer: [RTP header | encrypted payload | auth tag].
    /// Caller owns the returned memory.
    ///
    /// Per rfc3711-s3.1-r4, encryption is applied before authentication.
    pub fn protectRtp(self: *SrtpContext, plaintext_packet: []const u8) ![]u8 {
        if (plaintext_packet.len < 12) return error.PacketTooShort;

        const ssrc = readU32(plaintext_packet[8..12]);
        const seq = readU16(plaintext_packet[2..4]);
        const header_len = rtpHeaderLen(plaintext_packet);
        if (header_len > plaintext_packet.len) return error.InvalidHeader;

        const ctx = try self.getOrCreateContext(ssrc);

        // Update ROC / s_l for sender side
        if (ctx.initialized) {
            if (seq == 0 and ctx.s_l == 0xFFFF) {
                ctx.roc +%= 1;
            }
        }
        ctx.s_l = seq;
        ctx.initialized = true;

        const pkt_index = packetIndex(ctx.roc, seq);
        ctx.highest_index = pkt_index;

        const payload = plaintext_packet[header_len..];
        const tag_len = self.profile.authTagLen();

        // Allocate output: header + encrypted_payload + auth_tag
        const out = try self.allocator.alloc(u8, plaintext_packet.len + tag_len);
        errdefer self.allocator.free(out);

        // Copy header unchanged
        @memcpy(out[0..header_len], plaintext_packet[0..header_len]);

        // Encrypt payload in-place using AES-128-CM (rfc3711-s4.1.1)
        aesCmEncrypt(
            &ctx.session_keys.cipher_key,
            &ctx.session_keys.salt_key,
            ssrc,
            pkt_index,
            payload,
            out[header_len .. header_len + payload.len],
        );

        // Compute auth tag over (header || encrypted_payload || ROC) (rfc3711-s4.2)
        const auth_input_len = header_len + payload.len;
        const tag = computeAuthTag(
            &ctx.session_keys.auth_key,
            out[0..auth_input_len],
            ctx.roc,
        );
        @memcpy(out[auth_input_len .. auth_input_len + tag_len], tag[0..tag_len]);

        return out;
    }

    /// Unprotect (verify auth + decrypt) a protected RTP packet.
    /// Per rfc3711-s3.3-r1, authentication is verified first, then decryption.
    /// Returns an allocated buffer with the original plaintext RTP packet.
    /// Caller owns the returned memory.
    pub fn unprotectRtp(self: *SrtpContext, protected_packet: []const u8) ![]u8 {
        const tag_len = self.profile.authTagLen();
        if (protected_packet.len < 12 + tag_len) return error.PacketTooShort;

        const ssrc = readU32(protected_packet[8..12]);
        const seq = readU16(protected_packet[2..4]);
        const header_len = rtpHeaderLen(protected_packet);
        const payload_end = protected_packet.len - tag_len;
        if (header_len > payload_end) return error.InvalidHeader;

        const ctx = try self.getOrCreateContext(ssrc);

        // Estimate packet index and ROC (RFC 3711 §3.3.1)
        const est = estimateIndex(ctx.s_l, seq, ctx.roc, ctx.initialized);
        const v_roc = est.v_roc;
        const pkt_index = est.index;

        // Verify authentication tag (rfc3711-s3.3-r1: verify auth first)
        const received_tag = protected_packet[payload_end .. payload_end + tag_len];
        const computed = computeAuthTag(
            &ctx.session_keys.auth_key,
            protected_packet[0..payload_end],
            v_roc,
        );
        if (!mem.eql(u8, received_tag, computed[0..tag_len])) {
            return error.AuthenticationFailed;
        }

        // Replay protection (RFC 3711 §3.3.2)
        if (ctx.initialized) {
            try replayCheck(ctx, pkt_index);
        }

        // Decrypt payload
        const enc_payload = protected_packet[header_len..payload_end];
        const out = try self.allocator.alloc(u8, payload_end);
        errdefer self.allocator.free(out);

        @memcpy(out[0..header_len], protected_packet[0..header_len]);
        aesCmEncrypt(
            &ctx.session_keys.cipher_key,
            &ctx.session_keys.salt_key,
            ssrc,
            pkt_index,
            enc_payload,
            out[header_len..payload_end],
        );

        // Update state after successful authentication and decryption
        replayAccept(ctx, pkt_index);
        if (!ctx.initialized or pkt_index >= ctx.highest_index) {
            ctx.highest_index = pkt_index;
            ctx.roc = v_roc;
            ctx.s_l = seq;
            ctx.initialized = true;
        }

        return out;
    }

    // ========================================================================
    // RTCP protect / unprotect (RFC 3711 §3.4)
    // ========================================================================

    /// Protect an RTCP compound packet.
    /// Output: [RTCP packet | E(1)||SRTCP_index(31) | auth_tag]
    /// The E flag is always set (encrypted).
    pub fn protectRtcp(self: *SrtpContext, plaintext_rtcp: []const u8) ![]u8 {
        if (plaintext_rtcp.len < 8) return error.PacketTooShort;

        // RTCP SSRC is at bytes 4..8 in the first RTCP header
        const ssrc = readU32(plaintext_rtcp[4..8]);
        const ctx = try self.getOrCreateContext(ssrc);

        const srtcp_idx = ctx.srtcp_index;
        ctx.srtcp_index +%= 1;

        const tag_len = self.profile.authTagLen();
        const header_len: usize = 8; // Fixed RTCP header (V,P,RC,PT,length,SSRC)
        const payload = plaintext_rtcp[header_len..];

        // Output: header + encrypted_payload + E||index(4) + auth_tag
        const out_len = plaintext_rtcp.len + 4 + tag_len;
        const out = try self.allocator.alloc(u8, out_len);
        errdefer self.allocator.free(out);

        // Copy header
        @memcpy(out[0..header_len], plaintext_rtcp[0..header_len]);

        // Encrypt payload using SRTCP index as the packet index
        const pkt_index: u48 = @intCast(srtcp_idx);
        aesCmEncrypt(
            &ctx.session_keys.cipher_key,
            &ctx.session_keys.salt_key,
            ssrc,
            pkt_index,
            payload,
            out[header_len .. header_len + payload.len],
        );

        // Append E flag (MSB=1) || 31-bit SRTCP index
        const e_and_index: u32 = (@as(u32, 1) << 31) | @as(u32, srtcp_idx);
        writeU32(out[plaintext_rtcp.len .. plaintext_rtcp.len + 4], e_and_index);

        // Auth tag covers header + encrypted_payload + E||index
        const auth_region = out[0 .. plaintext_rtcp.len + 4];
        const tag = computeRtcpAuthTag(&ctx.session_keys.auth_key, auth_region);
        @memcpy(out[plaintext_rtcp.len + 4 .. out_len], tag[0..tag_len]);

        return out;
    }

    /// Unprotect an SRTCP packet. Verifies auth then decrypts.
    pub fn unprotectRtcp(self: *SrtpContext, protected_rtcp: []const u8) ![]u8 {
        const tag_len = self.profile.authTagLen();
        // Minimum: 8 (header) + 4 (E||index) + tag_len
        if (protected_rtcp.len < 8 + 4 + tag_len) return error.PacketTooShort;

        const ssrc = readU32(protected_rtcp[4..8]);
        const ctx = try self.getOrCreateContext(ssrc);

        const tag_start = protected_rtcp.len - tag_len;
        const e_index_start = tag_start - 4;
        const header_len: usize = 8;

        // Verify auth tag
        const received_tag = protected_rtcp[tag_start..protected_rtcp.len];
        const auth_region = protected_rtcp[0..tag_start];
        const computed = computeRtcpAuthTag(&ctx.session_keys.auth_key, auth_region);
        if (!mem.eql(u8, received_tag, computed[0..tag_len])) {
            return error.AuthenticationFailed;
        }

        // Parse E||SRTCP_index
        const e_and_index = readU32(protected_rtcp[e_index_start .. e_index_start + 4]);
        const is_encrypted = (e_and_index >> 31) == 1;
        _ = is_encrypted;
        const srtcp_idx: u31 = @truncate(e_and_index & 0x7FFFFFFF);

        // Decrypt payload
        const enc_payload = protected_rtcp[header_len..e_index_start];
        const out_len = header_len + enc_payload.len;
        const out = try self.allocator.alloc(u8, out_len);
        errdefer self.allocator.free(out);

        @memcpy(out[0..header_len], protected_rtcp[0..header_len]);

        const pkt_index: u48 = @intCast(srtcp_idx);
        aesCmEncrypt(
            &ctx.session_keys.cipher_key,
            &ctx.session_keys.salt_key,
            ssrc,
            pkt_index,
            enc_payload,
            out[header_len..out_len],
        );

        return out;
    }

    // ========================================================================
    // Internal helpers
    // ========================================================================

    fn getOrCreateContext(self: *SrtpContext, ssrc: u32) !*SrtpCryptoContext {
        const gop = try self.contexts.getOrPut(ssrc);
        if (!gop.found_existing) {
            const keys = deriveSessionKeys(
                &self.key_material.master_key,
                &self.key_material.master_salt,
                ssrc,
                0,
            );
            gop.value_ptr.* = SrtpCryptoContext{
                .ssrc = ssrc,
                .session_keys = keys,
                .profile = self.profile,
            };
        }
        return gop.value_ptr;
    }
};

// ============================================================================
// Packet index computation (RFC 3711 §3.3.1)
// ============================================================================

/// Compute the 48-bit SRTP packet index from ROC and sequence number.
pub fn packetIndex(roc: u32, seq: u16) u48 {
    return @as(u48, roc) * 65536 + @as(u48, seq);
}

/// Result of index estimation.
pub const EstimatedIndex = struct {
    index: u48,
    v_roc: u32,
};

/// Estimate the packet index for a received packet, handling ROC rollover.
/// Per RFC 3711 §3.3.1: compare received SEQ to s_l to determine correct ROC.
pub fn estimateIndex(s_l: u16, seq: u16, roc: u32, initialized: bool) EstimatedIndex {
    if (!initialized) {
        return .{ .index = packetIndex(0, seq), .v_roc = 0 };
    }

    var v: u32 = roc;

    // Cast to i32 for signed comparison
    const diff = @as(i32, seq) - @as(i32, s_l);

    if (diff > 0x7FFF) {
        // seq is much larger than s_l → seq likely from previous ROC epoch
        if (v > 0) v -= 1;
    } else if (diff < -0x7FFF) {
        // s_l is much larger than seq → seq wrapped, ROC incremented
        v += 1;
    }

    return .{ .index = packetIndex(v, seq), .v_roc = v };
}

// ============================================================================
// Key derivation (RFC 3711 §4.3.1)
// ============================================================================

/// Derive SRTP session keys from master key and salt using AES-CM PRF.
/// Label 0x00 → cipher key (16 bytes), 0x01 → auth key (20 bytes), 0x02 → salt key (14 bytes).
/// key_derivation_rate is assumed 0 (derive once), so r = index DIV kdr = 0.
pub fn deriveSessionKeys(
    master_key: *const [16]u8,
    master_salt: *const [14]u8,
    ssrc: u32,
    index: u48,
) SrtpSessionKeys {
    _ = index; // kdr=0 means r=0 always

    var keys: SrtpSessionKeys = undefined;

    // Cipher key (label 0x00, 16 bytes)
    const ck = deriveKeyBytes(master_key, master_salt, 0x00, ssrc, 16);
    @memcpy(&keys.cipher_key, ck[0..16]);

    // Auth key (label 0x01, 20 bytes)
    const ak = deriveKeyBytes(master_key, master_salt, 0x01, ssrc, 20);
    @memcpy(&keys.auth_key, ak[0..20]);

    // Salt key (label 0x02, 14 bytes)
    const sk = deriveKeyBytes(master_key, master_salt, 14, ssrc, 14);
    // label 0x02 for salt
    const sk2 = deriveKeyBytes(master_key, master_salt, 0x02, ssrc, 14);
    _ = sk;
    @memcpy(&keys.salt_key, sk2[0..14]);

    return keys;
}

/// Derive `out_len` bytes of key material using AES-CM PRF.
/// x = label || r (with r=0 for kdr=0), XOR'd into the salt to form the IV.
fn deriveKeyBytes(
    master_key: *const [16]u8,
    master_salt: *const [14]u8,
    label: u8,
    ssrc: u32,
    comptime out_len: usize,
) [out_len]u8 {
    // Build the 112-bit (14-byte) key_id = label || r
    // For kdr=0, r=0, so key_id is just the label placed at byte 7 (the label byte).
    // x = key_id XOR master_salt
    //
    // The 14-byte salt/x value layout for SRTP:
    //   bytes 0-1: 0 XOR salt[0-1]
    //   bytes 2-5: SSRC XOR salt[2-5]  (for SRTP, not for SRTCP per spec simplification)
    //   bytes 6:   0 XOR salt[6]
    //   byte  7:   label XOR salt[7]
    //   bytes 8-13: 0 XOR salt[8-13]
    //
    // Per RFC 3711 §4.3.1, for SRTP the key_id does NOT include SSRC;
    // SSRC is NOT part of the PRF input for key derivation.
    // The "x" value is: key_id XOR salt, where key_id = label * 2^48 (for r=0).
    // So label goes into byte 7 of a 14-byte value.

    _ = ssrc; // SSRC is NOT used in key derivation per RFC 3711 §4.3.1

    var x: [14]u8 = master_salt.*;
    x[7] ^= label;

    // IV for AES-CM PRF: 16 bytes = x (14 bytes) || 00 00
    var iv: [16]u8 = .{0} ** 16;
    @memcpy(iv[0..14], &x);

    // Generate keystream using AES-128 in counter mode
    const aes_ctx = Aes128.initEnc(master_key.*);
    const blocks_needed = (out_len + 15) / 16;
    var result: [out_len]u8 = undefined;
    var offset: usize = 0;

    for (0..blocks_needed) |block_idx| {
        // Set counter in last 2 bytes
        iv[14] = @truncate(block_idx >> 8);
        iv[15] = @truncate(block_idx);

        // Encrypt the IV (counter block) to produce keystream
        var keystream_block: [16]u8 = undefined;
        aes_ctx.encrypt(&keystream_block, &iv);

        const remaining = out_len - offset;
        const to_copy = @min(remaining, 16);
        @memcpy(result[offset .. offset + to_copy], keystream_block[0..to_copy]);
        offset += to_copy;
    }

    return result;
}

// ============================================================================
// AES-128-CM encryption (RFC 3711 §4.1.1)
// ============================================================================

/// Encrypt (or decrypt, since CTR is symmetric) a payload using AES-128-CM.
///
/// IV construction per RFC 3711 §4.1.1:
///   IV[0..3]   = 0x00000000
///   IV[4..7]   = SSRC XOR salt_key[2..6]
///   IV[8..13]  = packet_index XOR salt_key[8..14]
///   IV[14..15] = block counter (starts at 0)
fn aesCmEncrypt(
    cipher_key: *const [16]u8,
    salt_key: *const [14]u8,
    ssrc: u32,
    pkt_index: u48,
    input: []const u8,
    output: []u8,
) void {
    std.debug.assert(input.len == output.len);

    var iv: [16]u8 = .{0} ** 16;

    // IV[4..8] = SSRC XOR salt[2..6]
    const ssrc_bytes = intToBytesBig(u32, ssrc);
    iv[4] = ssrc_bytes[0] ^ salt_key[2];
    iv[5] = ssrc_bytes[1] ^ salt_key[3];
    iv[6] = ssrc_bytes[2] ^ salt_key[4];
    iv[7] = ssrc_bytes[3] ^ salt_key[5];

    // IV[8..14] = packet_index XOR salt[8..14]
    const idx_bytes = intToBytesBig(u48, pkt_index);
    // idx_bytes is 6 bytes (big-endian representation of 48-bit index)
    iv[8] = idx_bytes[0] ^ salt_key[8];
    iv[9] = idx_bytes[1] ^ salt_key[9];
    iv[10] = idx_bytes[2] ^ salt_key[10];
    iv[11] = idx_bytes[3] ^ salt_key[11];
    iv[12] = idx_bytes[4] ^ salt_key[12];
    iv[13] = idx_bytes[5] ^ salt_key[13];

    // AES-CTR: for each 16-byte block, encrypt IV||counter and XOR with plaintext
    const aes_ctx = Aes128.initEnc(cipher_key.*);
    const block_count = (input.len + 15) / 16;

    for (0..block_count) |blk| {
        // Set counter in bytes 14-15
        const counter: u16 = @truncate(blk);
        iv[14] = @truncate(counter >> 8);
        iv[15] = @truncate(counter);

        var keystream: [16]u8 = undefined;
        aes_ctx.encrypt(&keystream, &iv);

        const start = blk * 16;
        const end = @min(start + 16, input.len);
        for (start..end) |i| {
            output[i] = input[i] ^ keystream[i - start];
        }
    }
}

// ============================================================================
// Authentication (HMAC-SHA1, RFC 3711 §4.2)
// ============================================================================

/// Compute the SRTP authentication tag.
/// Input to HMAC: (RTP header || encrypted payload || ROC as 4-byte big-endian).
/// Returns the full 20-byte HMAC-SHA1 output; caller truncates as needed.
fn computeAuthTag(
    auth_key: *const [20]u8,
    header_and_payload: []const u8,
    roc: u32,
) [20]u8 {
    var hmac = HmacSha1.init(auth_key);
    hmac.update(header_and_payload);

    // Append ROC as 4-byte big-endian
    const roc_bytes = intToBytesBig(u32, roc);
    hmac.update(&roc_bytes);

    var out: [20]u8 = undefined;
    hmac.final(&out);
    return out;
}

/// Compute the SRTCP authentication tag.
/// Input: (RTCP header || encrypted payload || E||SRTCP_index).
/// No separate ROC appended for RTCP — the index is already in the data.
fn computeRtcpAuthTag(
    auth_key: *const [20]u8,
    data: []const u8,
) [20]u8 {
    var hmac = HmacSha1.init(auth_key);
    hmac.update(data);
    var out: [20]u8 = undefined;
    hmac.final(&out);
    return out;
}

// ============================================================================
// Replay protection (RFC 3711 §3.3.2)
// ============================================================================

const REPLAY_WINDOW_SIZE: u48 = 64;

/// Check if a packet index is acceptable given the replay window state.
fn replayCheck(ctx: *SrtpCryptoContext, pkt_index: u48) !void {
    if (pkt_index == 0 and ctx.highest_index == 0 and ctx.replay_window == 0) {
        // Very first packet
        return;
    }

    if (pkt_index > ctx.highest_index) {
        // New packet ahead of window — always acceptable
        return;
    }

    // How far back is this packet?
    const delta = ctx.highest_index - pkt_index;

    if (delta >= REPLAY_WINDOW_SIZE) {
        return error.ReplayOldPacket;
    }

    // Check if already received
    const bit: u6 = @truncate(delta);
    if ((ctx.replay_window >> bit) & 1 == 1) {
        return error.ReplayDuplicate;
    }
}

/// Update replay window state after accepting a packet.
fn replayAccept(ctx: *SrtpCryptoContext, pkt_index: u48) void {
    if (!ctx.initialized) {
        ctx.highest_index = pkt_index;
        ctx.replay_window = 1;
        return;
    }

    if (pkt_index > ctx.highest_index) {
        const shift = pkt_index - ctx.highest_index;
        if (shift >= REPLAY_WINDOW_SIZE) {
            ctx.replay_window = 1;
        } else {
            const s: u6 = @truncate(shift);
            ctx.replay_window = (ctx.replay_window << s) | 1;
        }
        ctx.highest_index = pkt_index;
    } else {
        const delta = ctx.highest_index - pkt_index;
        const bit: u6 = @truncate(delta);
        ctx.replay_window |= @as(u64, 1) << bit;
    }
}

// ============================================================================
// RTP header parsing helpers
// ============================================================================

/// Compute the total RTP header length including CSRC and extension headers.
fn rtpHeaderLen(packet: []const u8) usize {
    if (packet.len < 12) return 12;
    const first_byte = packet[0];
    const cc: usize = first_byte & 0x0F;
    const has_extension = (first_byte & 0x10) != 0;
    var len: usize = 12 + cc * 4;

    if (has_extension and packet.len >= len + 4) {
        // Extension header: 2 bytes profile, 2 bytes length (in 32-bit words)
        const ext_len = readU16(packet[len + 2 .. len + 4]);
        len += 4 + @as(usize, ext_len) * 4;
    }
    return len;
}

// ============================================================================
// Byte-order utilities
// ============================================================================

fn readU16(bytes: []const u8) u16 {
    return (@as(u16, bytes[0]) << 8) | @as(u16, bytes[1]);
}

fn readU32(bytes: []const u8) u32 {
    return (@as(u32, bytes[0]) << 24) |
        (@as(u32, bytes[1]) << 16) |
        (@as(u32, bytes[2]) << 8) |
        @as(u32, bytes[3]);
}

fn writeU32(dest: []u8, val: u32) void {
    dest[0] = @truncate(val >> 24);
    dest[1] = @truncate(val >> 16);
    dest[2] = @truncate(val >> 8);
    dest[3] = @truncate(val);
}

fn intToBytesBig(comptime T: type, val: T) [@divExact(@typeInfo(T).int.bits, 8)]u8 {
    const N = @divExact(@typeInfo(T).int.bits, 8);
    var result: [N]u8 = undefined;
    inline for (0..N) |i| {
        result[i] = @truncate(val >> @intCast((N - 1 - i) * 8));
    }
    return result;
}

// ============================================================================
// Tests
// ============================================================================

/// Build a minimal valid RTP packet (V=2, no CSRC, no extension).
fn buildRtpPacket(ssrc: u32, seq: u16, payload: []const u8) [12 + 160]u8 {
    var pkt: [12 + 160]u8 = .{0} ** (12 + 160);
    pkt[0] = 0x80; // V=2
    pkt[1] = 0x00; // PT=0
    pkt[2] = @truncate(seq >> 8);
    pkt[3] = @truncate(seq);
    // Timestamp = 0
    pkt[8] = @truncate(ssrc >> 24);
    pkt[9] = @truncate(ssrc >> 16);
    pkt[10] = @truncate(ssrc >> 8);
    pkt[11] = @truncate(ssrc);
    const copy_len = @min(payload.len, 160);
    @memcpy(pkt[12 .. 12 + copy_len], payload[0..copy_len]);
    return pkt;
}

fn buildRtpSlice(allocator: mem.Allocator, ssrc: u32, seq: u16, payload: []const u8) ![]u8 {
    const hdr_len: usize = 12;
    const pkt = try allocator.alloc(u8, hdr_len + payload.len);
    @memset(pkt, 0);
    pkt[0] = 0x80; // V=2
    pkt[2] = @truncate(seq >> 8);
    pkt[3] = @truncate(seq);
    pkt[8] = @truncate(ssrc >> 24);
    pkt[9] = @truncate(ssrc >> 16);
    pkt[10] = @truncate(ssrc >> 8);
    pkt[11] = @truncate(ssrc);
    @memcpy(pkt[hdr_len .. hdr_len + payload.len], payload);
    return pkt;
}

fn buildRtcpPacket(ssrc: u32, payload: []const u8) ![]u8 {
    const allocator = std.testing.allocator;
    const hdr_len: usize = 8;
    const pkt = try allocator.alloc(u8, hdr_len + payload.len);
    @memset(pkt, 0);
    pkt[0] = 0x80; // V=2, RC=0
    pkt[1] = 200; // PT=200 (SR)
    // Length in 32-bit words minus 1
    const words: u16 = @truncate((hdr_len + payload.len) / 4 - 1);
    pkt[2] = @truncate(words >> 8);
    pkt[3] = @truncate(words);
    pkt[4] = @truncate(ssrc >> 24);
    pkt[5] = @truncate(ssrc >> 16);
    pkt[6] = @truncate(ssrc >> 8);
    pkt[7] = @truncate(ssrc);
    @memcpy(pkt[hdr_len .. hdr_len + payload.len], payload);
    return pkt;
}

fn testKeyMaterial() SrtpKeyMaterial {
    return .{
        .master_key = .{ 0xE1, 0xF9, 0x7A, 0x0D, 0x3E, 0x01, 0x8B, 0xE0, 0xD6, 0x4F, 0xA3, 0x2C, 0x06, 0xDE, 0x41, 0x39 },
        .master_salt = .{ 0x0E, 0xC6, 0x75, 0xAD, 0x49, 0x8A, 0xFE, 0xEB, 0xB6, 0x96, 0x0B, 0x3A, 0xAB, 0xE6 },
    };
}

test "key derivation produces deterministic output" {
    const km = testKeyMaterial();
    const keys1 = deriveSessionKeys(&km.master_key, &km.master_salt, 0x12345678, 0);
    const keys2 = deriveSessionKeys(&km.master_key, &km.master_salt, 0x12345678, 0);

    // Deterministic: same input → same output
    try std.testing.expectEqualSlices(u8, &keys1.cipher_key, &keys2.cipher_key);
    try std.testing.expectEqualSlices(u8, &keys1.auth_key, &keys2.auth_key);
    try std.testing.expectEqualSlices(u8, &keys1.salt_key, &keys2.salt_key);

    // Keys should not be all zeros (sanity check)
    const zero16: [16]u8 = .{0} ** 16;
    const zero20: [20]u8 = .{0} ** 20;
    const zero14: [14]u8 = .{0} ** 14;
    try std.testing.expect(!mem.eql(u8, &keys1.cipher_key, &zero16));
    try std.testing.expect(!mem.eql(u8, &keys1.auth_key, &zero20));
    try std.testing.expect(!mem.eql(u8, &keys1.salt_key, &zero14));
}

test "key derivation different labels produce different keys" {
    const km = testKeyMaterial();
    const keys = deriveSessionKeys(&km.master_key, &km.master_salt, 0, 0);

    // Cipher key ≠ auth key ≠ salt key (different labels produce different output)
    try std.testing.expect(!mem.eql(u8, keys.cipher_key[0..14], keys.salt_key[0..14]));
    try std.testing.expect(!mem.eql(u8, keys.cipher_key[0..16], keys.auth_key[0..16]));
}

test "encrypt/decrypt RTP roundtrip" {
    const km = testKeyMaterial();
    var ctx = SrtpContext.init(std.testing.allocator, .aes128_cm_hmac_sha1_80, km);
    defer ctx.deinit();

    const payload = "Hello, SRTP world! This is a test payload for roundtrip.";
    const pkt = try buildRtpSlice(std.testing.allocator, 0xDEADBEEF, 1, payload);
    defer std.testing.allocator.free(pkt);

    const protected = try ctx.protectRtp(pkt);
    defer std.testing.allocator.free(protected);

    // Protected should be longer (auth tag appended)
    try std.testing.expect(protected.len == pkt.len + 10);

    // Payload should be encrypted (different from plaintext)
    try std.testing.expect(!mem.eql(u8, protected[12 .. 12 + payload.len], payload));

    // Create a second context for unprotect to simulate receiver
    var ctx2 = SrtpContext.init(std.testing.allocator, .aes128_cm_hmac_sha1_80, km);
    defer ctx2.deinit();

    const decrypted = try ctx2.unprotectRtp(protected);
    defer std.testing.allocator.free(decrypted);

    // Decrypted payload matches original
    try std.testing.expectEqualSlices(u8, payload, decrypted[12..]);
    // Header preserved
    try std.testing.expectEqualSlices(u8, pkt[0..12], decrypted[0..12]);
}

test "replay detection rejects duplicate packet" {
    const km = testKeyMaterial();
    var ctx = SrtpContext.init(std.testing.allocator, .aes128_cm_hmac_sha1_80, km);
    defer ctx.deinit();

    const payload = "replay test payload data for testing";
    const pkt = try buildRtpSlice(std.testing.allocator, 0xAABBCCDD, 42, payload);
    defer std.testing.allocator.free(pkt);

    // Protect the packet
    var protect_ctx = SrtpContext.init(std.testing.allocator, .aes128_cm_hmac_sha1_80, km);
    defer protect_ctx.deinit();
    const protected = try protect_ctx.protectRtp(pkt);
    defer std.testing.allocator.free(protected);

    // First unprotect succeeds
    const dec1 = try ctx.unprotectRtp(protected);
    defer std.testing.allocator.free(dec1);

    // Second unprotect of same packet should fail (replay)
    const result = ctx.unprotectRtp(protected);
    try std.testing.expectError(error.ReplayDuplicate, result);
}

test "replay window accepts in-order packets, rejects old" {
    const km = testKeyMaterial();
    var protect_ctx = SrtpContext.init(std.testing.allocator, .aes128_cm_hmac_sha1_80, km);
    defer protect_ctx.deinit();
    var unprotect_ctx = SrtpContext.init(std.testing.allocator, .aes128_cm_hmac_sha1_80, km);
    defer unprotect_ctx.deinit();

    const payload = "window test payload data here";
    const ssrc: u32 = 0x11223344;

    // Send packets with seq 1, 2, ..., 70
    var protected_pkts: [70][]u8 = undefined;
    for (0..70) |i| {
        const seq: u16 = @truncate(i + 1);
        const pkt = try buildRtpSlice(std.testing.allocator, ssrc, seq, payload);
        defer std.testing.allocator.free(pkt);
        protected_pkts[i] = try protect_ctx.protectRtp(pkt);
    }
    defer for (&protected_pkts) |p| std.testing.allocator.free(p);

    // Unprotect all 70 in order — all should succeed
    for (0..70) |i| {
        const dec = try unprotect_ctx.unprotectRtp(protected_pkts[i]);
        std.testing.allocator.free(dec);
    }

    // Replaying packet with seq=1 (index=1) should fail: too old (highest=70, delta=69 ≥ 64)
    const old_result = unprotect_ctx.unprotectRtp(protected_pkts[0]);
    try std.testing.expectError(error.ReplayOldPacket, old_result);

    // Replaying packet with seq=10 (index=10) should also be too old (delta=60)
    // Actually delta = 70 - 10 = 60 which is < 64, so it should fail as duplicate since we already received it
    const dup_result = unprotect_ctx.unprotectRtp(protected_pkts[9]);
    try std.testing.expectError(error.ReplayDuplicate, dup_result);
}

test "ROC handling on sequence wrap" {
    // Test that ROC increments correctly when sequence wraps
    const est1 = estimateIndex(0xFFFE, 0xFFFF, 0, true);
    try std.testing.expectEqual(@as(u32, 0), est1.v_roc);
    try std.testing.expectEqual(packetIndex(0, 0xFFFF), est1.index);

    // Sequence wraps: s_l=0xFFFF, received seq=0 → ROC should increment
    const est2 = estimateIndex(0xFFFF, 0, 0, true);
    try std.testing.expectEqual(@as(u32, 1), est2.v_roc);
    try std.testing.expectEqual(packetIndex(1, 0), est2.index);

    // Late packet: s_l=5, received seq=0xFFFD with roc=1 → should use roc-1=0
    const est3 = estimateIndex(5, 0xFFFD, 1, true);
    try std.testing.expectEqual(@as(u32, 0), est3.v_roc);
    try std.testing.expectEqual(packetIndex(0, 0xFFFD), est3.index);

    // Normal increment: s_l=100, seq=101, roc=0
    const est4 = estimateIndex(100, 101, 0, true);
    try std.testing.expectEqual(@as(u32, 0), est4.v_roc);
    try std.testing.expectEqual(packetIndex(0, 101), est4.index);
}

test "RTCP protect/unprotect roundtrip" {
    const km = testKeyMaterial();
    var ctx = SrtpContext.init(std.testing.allocator, .aes128_cm_hmac_sha1_80, km);
    defer ctx.deinit();

    const rtcp_payload = "RTCP sender report payload data here!!"; // Pad to multiple of 4
    // Trim to nearest multiple of 4
    const pl = rtcp_payload[0 .. (rtcp_payload.len / 4) * 4];
    const pkt = try buildRtcpPacket(0xFEEDFACE, pl);
    defer std.testing.allocator.free(pkt);

    const protected = try ctx.protectRtcp(pkt);
    defer std.testing.allocator.free(protected);

    // Protected should have E||index (4 bytes) + auth tag (10 bytes) more
    try std.testing.expectEqual(pkt.len + 4 + 10, protected.len);

    // Create separate context for unprotect
    var ctx2 = SrtpContext.init(std.testing.allocator, .aes128_cm_hmac_sha1_80, km);
    defer ctx2.deinit();

    const decrypted = try ctx2.unprotectRtcp(protected);
    defer std.testing.allocator.free(decrypted);

    try std.testing.expectEqualSlices(u8, pkt, decrypted);
}

test "auth tag verification rejects corrupted packet" {
    const km = testKeyMaterial();
    var protect_ctx = SrtpContext.init(std.testing.allocator, .aes128_cm_hmac_sha1_80, km);
    defer protect_ctx.deinit();

    const payload = "integrity check payload data!!";
    const pkt = try buildRtpSlice(std.testing.allocator, 0x55667788, 100, payload);
    defer std.testing.allocator.free(pkt);

    const protected = try protect_ctx.protectRtp(pkt);
    defer std.testing.allocator.free(protected);

    // Corrupt one byte of the encrypted payload
    const corrupted = try std.testing.allocator.dupe(u8, protected);
    defer std.testing.allocator.free(corrupted);
    corrupted[14] ^= 0xFF;

    var unprotect_ctx = SrtpContext.init(std.testing.allocator, .aes128_cm_hmac_sha1_80, km);
    defer unprotect_ctx.deinit();

    const result = unprotect_ctx.unprotectRtp(corrupted);
    try std.testing.expectError(error.AuthenticationFailed, result);
}

test "index estimation near wrapping boundaries" {
    // Uninitialized context
    const est0 = estimateIndex(0, 5, 0, false);
    try std.testing.expectEqual(@as(u32, 0), est0.v_roc);
    try std.testing.expectEqual(@as(u48, 5), est0.index);

    // Just before wrap: s_l=0x7FFE, seq=0x7FFF → same ROC
    const est_pre = estimateIndex(0x7FFE, 0x7FFF, 0, true);
    try std.testing.expectEqual(@as(u32, 0), est_pre.v_roc);

    // At boundary: s_l=0x7FFF, seq=0x8000 → same ROC (diff = 1, not > 0x7FFF)
    const est_at = estimateIndex(0x7FFF, 0x8000, 0, true);
    try std.testing.expectEqual(@as(u32, 0), est_at.v_roc);

    // Cross boundary: s_l=0x0001, seq=0xFFFF → ROC decrements (diff > 0x7FFF)
    const est_cross = estimateIndex(0x0001, 0xFFFF, 1, true);
    try std.testing.expectEqual(@as(u32, 0), est_cross.v_roc);

    // Forward wrap: s_l=0xFFFE, seq=0x0001 → ROC increments
    const est_fwd = estimateIndex(0xFFFE, 0x0001, 5, true);
    try std.testing.expectEqual(@as(u32, 6), est_fwd.v_roc);
}

test "packet index calculation" {
    try std.testing.expectEqual(@as(u48, 0), packetIndex(0, 0));
    try std.testing.expectEqual(@as(u48, 1), packetIndex(0, 1));
    try std.testing.expectEqual(@as(u48, 65535), packetIndex(0, 65535));
    try std.testing.expectEqual(@as(u48, 65536), packetIndex(1, 0));
    try std.testing.expectEqual(@as(u48, 65537), packetIndex(1, 1));
    try std.testing.expectEqual(@as(u48, 131072), packetIndex(2, 0));
}

test "AES-CM encryption is reversible (CTR symmetry)" {
    const key = [_]u8{ 0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C };
    const salt = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D };
    const plaintext = "AES-CTR mode is its own inverse!";

    var ciphertext: [plaintext.len]u8 = undefined;
    aesCmEncrypt(&key, &salt, 0xDEAD, 42, plaintext, &ciphertext);

    // Ciphertext should differ from plaintext
    try std.testing.expect(!mem.eql(u8, plaintext, &ciphertext));

    // Decrypting (re-encrypting) should recover plaintext
    var recovered: [plaintext.len]u8 = undefined;
    aesCmEncrypt(&key, &salt, 0xDEAD, 42, &ciphertext, &recovered);
    try std.testing.expectEqualSlices(u8, plaintext, &recovered);
}

test "32-bit auth tag profile roundtrip" {
    const km = testKeyMaterial();
    var ctx = SrtpContext.init(std.testing.allocator, .aes128_cm_hmac_sha1_32, km);
    defer ctx.deinit();

    const payload = "short tag test payload here!!";
    const pkt = try buildRtpSlice(std.testing.allocator, 0xCAFEBABE, 1, payload);
    defer std.testing.allocator.free(pkt);

    const protected = try ctx.protectRtp(pkt);
    defer std.testing.allocator.free(protected);

    // Auth tag should be 4 bytes for _32 profile
    try std.testing.expectEqual(pkt.len + 4, protected.len);

    var ctx2 = SrtpContext.init(std.testing.allocator, .aes128_cm_hmac_sha1_32, km);
    defer ctx2.deinit();

    const decrypted = try ctx2.unprotectRtp(protected);
    defer std.testing.allocator.free(decrypted);

    try std.testing.expectEqualSlices(u8, payload, decrypted[12..]);
}

test "SrtpProfile auth tag and key lengths" {
    try std.testing.expectEqual(@as(usize, 10), SrtpProfile.aes128_cm_hmac_sha1_80.authTagLen());
    try std.testing.expectEqual(@as(usize, 4), SrtpProfile.aes128_cm_hmac_sha1_32.authTagLen());
    try std.testing.expectEqual(@as(usize, 16), SrtpProfile.aead_aes_128_gcm.authTagLen());
    try std.testing.expectEqual(@as(usize, 16), SrtpProfile.aead_aes_256_gcm.authTagLen());
    try std.testing.expectEqual(@as(usize, 16), SrtpProfile.aes128_cm_hmac_sha1_80.masterKeyLen());
    try std.testing.expectEqual(@as(usize, 32), SrtpProfile.aead_aes_256_gcm.masterKeyLen());
}

test "multiple SSRCs get independent contexts" {
    const km = testKeyMaterial();
    var ctx = SrtpContext.init(std.testing.allocator, .aes128_cm_hmac_sha1_80, km);
    defer ctx.deinit();

    const payload1 = "SSRC one payload data here!!!";
    const payload2 = "SSRC two payload data here!!!";

    const pkt1 = try buildRtpSlice(std.testing.allocator, 0x11111111, 1, payload1);
    defer std.testing.allocator.free(pkt1);
    const pkt2 = try buildRtpSlice(std.testing.allocator, 0x22222222, 1, payload2);
    defer std.testing.allocator.free(pkt2);

    const p1 = try ctx.protectRtp(pkt1);
    defer std.testing.allocator.free(p1);
    const p2 = try ctx.protectRtp(pkt2);
    defer std.testing.allocator.free(p2);

    // Different SSRCs should produce different ciphertexts even with same seq
    try std.testing.expect(!mem.eql(u8, p1[12 .. 12 + payload1.len], p2[12 .. 12 + payload2.len]));

    // Both should decrypt correctly
    var ctx2 = SrtpContext.init(std.testing.allocator, .aes128_cm_hmac_sha1_80, km);
    defer ctx2.deinit();

    const d1 = try ctx2.unprotectRtp(p1);
    defer std.testing.allocator.free(d1);
    const d2 = try ctx2.unprotectRtp(p2);
    defer std.testing.allocator.free(d2);

    try std.testing.expectEqualSlices(u8, payload1, d1[12..]);
    try std.testing.expectEqualSlices(u8, payload2, d2[12..]);
}

test "RTP header length calculation" {
    // Minimal header: V=2, no CSRC, no extension
    var pkt = [_]u8{0x80} ++ [_]u8{0} ** 11;
    try std.testing.expectEqual(@as(usize, 12), rtpHeaderLen(&pkt));

    // With 2 CSRCs: CC=2
    var pkt_cc = [_]u8{0x82} ++ [_]u8{0} ** 19;
    try std.testing.expectEqual(@as(usize, 20), rtpHeaderLen(&pkt_cc));

    // With extension: X=1, ext length=1 (4 bytes of extension data)
    var pkt_ext = [_]u8{0} ** 20;
    pkt_ext[0] = 0x90; // V=2, X=1
    pkt_ext[14] = 0; // profile
    pkt_ext[15] = 1; // ext length = 1 word = 4 bytes
    try std.testing.expectEqual(@as(usize, 20), rtpHeaderLen(&pkt_ext));
}
