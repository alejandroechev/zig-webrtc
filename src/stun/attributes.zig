//! STUN attribute types and parsing (RFC 5389 §15)
//! Generated from structured RFC 5389 rules via RFC Compliance API grounding layer.

const std = @import("std");

/// STUN attribute types (RFC 5389 §18.2)
/// 0x0000-0x7FFF: comprehension-required
/// 0x8000-0xFFFF: comprehension-optional
pub const AttributeType = enum(u16) {
    mapped_address = 0x0001,
    username = 0x0006,
    message_integrity = 0x0008,
    error_code = 0x0009,
    unknown_attributes = 0x000A,
    realm = 0x0014,
    nonce = 0x0015,
    xor_mapped_address = 0x0020,
    software = 0x8022,
    alternate_server = 0x8023,
    fingerprint = 0x8028,
    _, // allow unknown attributes per RFC 5389 §18.2

    /// Returns true if this attribute is comprehension-required (rfc5389-s18-r1)
    pub fn isComprehensionRequired(self: AttributeType) bool {
        return @intFromEnum(self) < 0x8000;
    }
};

/// STUN attribute header: 16-bit type + 16-bit length (rfc5389-s15-r1)
pub const AttributeHeader = extern struct {
    attr_type: u16, // big-endian
    length: u16, // big-endian, value length before padding (rfc5389-s15-r3)
};

/// Parsed STUN attribute
pub const Attribute = struct {
    attr_type: AttributeType,
    value: []const u8,

    /// Parse XOR-MAPPED-ADDRESS (RFC 5389 §15.2)
    /// Port is XORed with magic cookie upper 16 bits.
    /// IPv4 address is XORed with magic cookie.
    /// IPv6 address is XORed with magic cookie + transaction ID.
    pub fn parseXorMappedAddress(self: *const Attribute, transaction_id: [12]u8) !Address {
        if (self.value.len < 4) return error.InvalidAttribute;
        // Byte 0: reserved (rfc5389-s15.1-r2)
        const family = self.value[1];
        const xored_port = std.mem.readInt(u16, self.value[2..4], .big);
        const magic_upper: u16 = 0x2112; // upper 16 bits of magic cookie
        const port = xored_port ^ magic_upper;

        if (family == 0x01) {
            // IPv4 (rfc5389-s15.1-r1: 32 bits)
            if (self.value.len < 8) return error.InvalidAttribute;
            const magic_cookie_bytes = [4]u8{ 0x21, 0x12, 0xA4, 0x42 };
            var addr: [4]u8 = undefined;
            for (0..4) |i| {
                addr[i] = self.value[4 + i] ^ magic_cookie_bytes[i];
            }
            return Address{
                .family = .ipv4,
                .port = port,
                .addr = .{ .ipv4 = addr },
            };
        } else if (family == 0x02) {
            // IPv6 (rfc5389-s15.1-r1: 128 bits)
            if (self.value.len < 20) return error.InvalidAttribute;
            const magic_cookie_bytes = [4]u8{ 0x21, 0x12, 0xA4, 0x42 };
            // XOR with magic cookie (4 bytes) + transaction ID (12 bytes) = 16 bytes
            var xor_key: [16]u8 = undefined;
            @memcpy(xor_key[0..4], &magic_cookie_bytes);
            @memcpy(xor_key[4..16], &transaction_id);

            var addr: [16]u8 = undefined;
            for (0..16) |i| {
                addr[i] = self.value[4 + i] ^ xor_key[i];
            }
            return Address{
                .family = .ipv6,
                .port = port,
                .addr = .{ .ipv6 = addr },
            };
        } else {
            return error.UnsupportedAddressFamily;
        }
    }

    /// Parse MAPPED-ADDRESS (RFC 5389 §15.1)
    pub fn parseMappedAddress(self: *const Attribute) !Address {
        if (self.value.len < 4) return error.InvalidAttribute;
        // Byte 0: reserved (rfc5389-s15.1-r2: set to 0 when encoding, ignore when decoding)
        const family = self.value[1];
        const port = std.mem.readInt(u16, self.value[2..4], .big);

        if (family == 0x01) {
            if (self.value.len < 8) return error.InvalidAttribute;
            return Address{
                .family = .ipv4,
                .port = port,
                .addr = .{ .ipv4 = self.value[4..8].* },
            };
        } else if (family == 0x02) {
            if (self.value.len < 20) return error.InvalidAttribute;
            return Address{
                .family = .ipv6,
                .port = port,
                .addr = .{ .ipv6 = self.value[4..20].* },
            };
        } else {
            return error.UnsupportedAddressFamily;
        }
    }

    /// Parse ERROR-CODE (RFC 5389 §15.6)
    /// Class (3-6) and Number (0-99) encode the error code.
    pub fn parseErrorCode(self: *const Attribute) !ErrorCode {
        if (self.value.len < 4) return error.InvalidAttribute;
        // Bytes 0-1: reserved (rfc5389-s15.6-r2: ignore reserved bits)
        const class_byte = self.value[2] & 0x07; // bits 0-2 of byte 2
        const number = self.value[3];
        // rfc5389-s15.6-r3: class must be 3-6
        if (class_byte < 3 or class_byte > 6) return error.InvalidErrorClass;
        // rfc5389-s15.6-r4: number must be 0-99
        if (number > 99) return error.InvalidErrorNumber;
        const code = @as(u16, class_byte) * 100 + @as(u16, number);
        const reason = if (self.value.len > 4) self.value[4..] else &[_]u8{};
        return ErrorCode{
            .code = code,
            .reason = reason,
        };
    }

    /// Encode MAPPED-ADDRESS attribute value
    pub fn encodeMappedAddress(allocator: std.mem.Allocator, addr: Address) ![]u8 {
        const len: usize = switch (addr.family) {
            .ipv4 => 8,
            .ipv6 => 20,
        };
        const buf = try allocator.alloc(u8, len);
        buf[0] = 0; // reserved
        buf[1] = switch (addr.family) {
            .ipv4 => 0x01,
            .ipv6 => 0x02,
        };
        std.mem.writeInt(u16, buf[2..4], addr.port, .big);
        switch (addr.family) {
            .ipv4 => @memcpy(buf[4..8], &addr.addr.ipv4),
            .ipv6 => @memcpy(buf[4..20], &addr.addr.ipv6),
        }
        return buf;
    }

    /// Encode XOR-MAPPED-ADDRESS attribute value
    pub fn encodeXorMappedAddress(allocator: std.mem.Allocator, addr: Address, transaction_id: [12]u8) ![]u8 {
        const len: usize = switch (addr.family) {
            .ipv4 => 8,
            .ipv6 => 20,
        };
        const buf = try allocator.alloc(u8, len);
        buf[0] = 0; // reserved
        buf[1] = switch (addr.family) {
            .ipv4 => 0x01,
            .ipv6 => 0x02,
        };
        const magic_upper: u16 = 0x2112;
        std.mem.writeInt(u16, buf[2..4], addr.port ^ magic_upper, .big);

        const magic_cookie_bytes = [4]u8{ 0x21, 0x12, 0xA4, 0x42 };
        switch (addr.family) {
            .ipv4 => {
                for (0..4) |i| {
                    buf[4 + i] = addr.addr.ipv4[i] ^ magic_cookie_bytes[i];
                }
            },
            .ipv6 => {
                var xor_key: [16]u8 = undefined;
                @memcpy(xor_key[0..4], &magic_cookie_bytes);
                @memcpy(xor_key[4..16], &transaction_id);
                for (0..16) |i| {
                    buf[4 + i] = addr.addr.ipv6[i] ^ xor_key[i];
                }
            },
        }
        return buf;
    }

    /// Encode ERROR-CODE attribute value (rfc5389-s15.6)
    pub fn encodeErrorCode(allocator: std.mem.Allocator, err: ErrorCode) ![]u8 {
        const class_val: u8 = @intCast(err.code / 100);
        const number: u8 = @intCast(err.code % 100);
        const buf = try allocator.alloc(u8, 4 + err.reason.len);
        buf[0] = 0; // reserved
        buf[1] = 0; // reserved
        buf[2] = class_val;
        buf[3] = number;
        @memcpy(buf[4..], err.reason);
        return buf;
    }
};

/// Network address (IPv4 or IPv6)
pub const Address = struct {
    family: AddressFamily,
    port: u16,
    addr: AddressValue,
};

pub const AddressFamily = enum { ipv4, ipv6 };

pub const AddressValue = union(AddressFamily) {
    ipv4: [4]u8,
    ipv6: [16]u8,
};

/// STUN error code (rfc5389-s15.6)
pub const ErrorCode = struct {
    code: u16, // 300-699
    reason: []const u8,
};
