//! MESSAGE-INTEGRITY and FINGERPRINT (RFC 5389 §15.4, §15.5)
//! Generated from structured RFC 5389 rules via RFC Compliance API grounding layer.

const std = @import("std");
const HmacSha1 = std.crypto.auth.hmac.HmacSha1;
const Crc32 = std.hash.crc.Crc32IsoHdlc;

/// XOR constant for FINGERPRINT (RFC 5389 §15.5)
pub const fingerprint_xor: u32 = 0x5354554e;

/// Compute HMAC-SHA1 MESSAGE-INTEGRITY (RFC 5389 §15.4)
///
/// The HMAC is computed over the STUN message up to (but not including)
/// the MESSAGE-INTEGRITY attribute itself. The message length field in the
/// header must be temporarily adjusted to include the MESSAGE-INTEGRITY
/// attribute (24 bytes: 4-byte attr header + 20-byte HMAC) but exclude
/// any attributes after it (rfc5389-s15.4-r3).
pub fn computeMessageIntegrity(message_prefix: []const u8, key: []const u8) [20]u8 {
    var mac: [20]u8 = undefined;
    var hmac = HmacSha1.init(key);
    hmac.update(message_prefix);
    hmac.final(&mac);
    return mac;
}

/// Validate MESSAGE-INTEGRITY on a parsed message (rfc5389-s15.4-r1)
/// Returns true if the HMAC matches.
pub fn validateMessageIntegrity(raw_message: []const u8, integrity_offset: usize, key: []const u8) bool {
    // The integrity attribute starts at integrity_offset
    // We need to: adjust header length to point to end of MESSAGE-INTEGRITY,
    // then HMAC everything before the attribute
    if (integrity_offset + 4 + 20 > raw_message.len) return false;

    // Get expected HMAC from the attribute value
    const expected = raw_message[integrity_offset + 4 ..][0..20];

    // Build the data to HMAC: header (with adjusted length) + everything up to MESSAGE-INTEGRITY attr
    var buf: [65536]u8 = undefined;
    if (integrity_offset > buf.len - 20) return false;

    // Copy header
    @memcpy(buf[0..20], raw_message[0..20]);

    // Adjust length: should be (integrity_offset - 20) + 24 = integrity_offset + 4
    // This includes attrs up to and including MESSAGE-INTEGRITY but nothing after
    const adjusted_length: u16 = @intCast(integrity_offset - 20 + 24);
    std.mem.writeInt(u16, buf[2..4], adjusted_length, .big);

    // Copy attributes up to the MESSAGE-INTEGRITY attribute
    if (integrity_offset > 20) {
        @memcpy(buf[20..integrity_offset], raw_message[20..integrity_offset]);
    }

    const computed = computeMessageIntegrity(buf[0..integrity_offset], key);
    return std.mem.eql(u8, &computed, expected);
}

/// Compute CRC32 FINGERPRINT (RFC 5389 §15.5)
/// The value is CRC-32 of the STUN message up to (but not including) the
/// FINGERPRINT attribute, XORed with 0x5354554e.
pub fn computeFingerprint(message_prefix: []const u8) u32 {
    return Crc32.hash(message_prefix) ^ fingerprint_xor;
}

/// Validate FINGERPRINT on a raw message (rfc5389-s15.5-r2)
/// The fingerprint attribute must be the last attribute.
pub fn validateFingerprint(raw_message: []const u8, fingerprint_offset: usize) bool {
    if (fingerprint_offset + 8 > raw_message.len) return false;

    // Read expected fingerprint value from the attribute
    const expected = std.mem.readInt(u32, raw_message[fingerprint_offset + 4 ..][0..4], .big);

    // Adjust header length to include up to and including FINGERPRINT
    var buf: [65536]u8 = undefined;
    if (fingerprint_offset > buf.len) return false;

    // Copy header with adjusted length
    @memcpy(buf[0..20], raw_message[0..20]);
    const adjusted_length: u16 = @intCast(fingerprint_offset - 20 + 8);
    std.mem.writeInt(u16, buf[2..4], adjusted_length, .big);

    // Copy all attributes up to FINGERPRINT
    if (fingerprint_offset > 20) {
        @memcpy(buf[20..fingerprint_offset], raw_message[20..fingerprint_offset]);
    }

    const computed = computeFingerprint(buf[0..fingerprint_offset]);
    return computed == expected;
}
