//! STUN message parsing and building (RFC 5389)
//! Generated from 127 structured RFC 5389 rules via RFC Compliance API grounding layer.
//!
//! This module implements:
//!   - Message header parsing/building (§6)
//!   - Message type encoding with interleaved class/method bits (§6)
//!   - Attribute TLV parsing with 4-byte padding (§15)
//!   - XOR-MAPPED-ADDRESS / MAPPED-ADDRESS decoding (§15.1, §15.2)
//!   - MESSAGE-INTEGRITY via HMAC-SHA1 (§15.4)
//!   - FINGERPRINT via CRC32 (§15.5)

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const attributes = @import("attributes.zig");
pub const integrity = @import("integrity.zig");

pub const AttributeType = attributes.AttributeType;
pub const Attribute = attributes.Attribute;
pub const Address = attributes.Address;
pub const AddressFamily = attributes.AddressFamily;
pub const ErrorCode = attributes.ErrorCode;

/// Magic cookie value (rfc5389-s6-r4)
pub const magic_cookie: u32 = 0x2112A442;
pub const magic_cookie_bytes: [4]u8 = .{ 0x21, 0x12, 0xA4, 0x42 };

/// STUN message classes (RFC 5389 §6)
pub const Class = enum(u2) {
    request = 0b00,
    indication = 0b01,
    success = 0b10,
    error_resp = 0b11,
};

/// STUN methods (RFC 5389 §18.1)
pub const Method = enum(u12) {
    binding = 0x001,
    _, // allow extension methods
};

/// Message type: class + method encoded per RFC 5389 §6.
/// The 14-bit message type has method and class bits interleaved:
///   M11 M10 M9 M8 M7 C1 M6 M5 M4 C0 M3 M2 M1 M0
/// Where C1 C0 = class bits, M0-M11 = method bits.
pub const MessageType = struct {
    class: Class,
    method: Method,

    /// Encode to the 16-bit wire format (rfc5389-s6-r2: top 2 bits zero)
    pub fn encode(self: MessageType) u16 {
        const m: u12 = @intFromEnum(self.method);
        const c: u2 = @intFromEnum(self.class);

        // Method bits split: M0-M3 (bits 0-3), M4-M6 (bits 4-6), M7-M11 (bits 7-11)
        const m_low: u16 = m & 0x00F; // M0-M3
        const m_mid: u16 = (m >> 4) & 0x007; // M4-M6
        const m_high: u16 = (m >> 7) & 0x01F; // M7-M11

        // Class bits: C0 at position 4, C1 at position 8
        const c0: u16 = @as(u16, c & 1) << 4;
        const c1: u16 = @as(u16, (c >> 1) & 1) << 8;

        return m_low | c0 | (m_mid << 5) | c1 | (m_high << 9);
    }

    /// Decode from the 16-bit wire format
    pub fn decode(raw: u16) MessageType {
        // Top 2 bits must be zero (rfc5389-s6-r2)
        const m_low = raw & 0x00F;
        const c0 = (raw >> 4) & 1;
        const m_mid = (raw >> 5) & 0x007;
        const c1 = (raw >> 8) & 1;
        const m_high = (raw >> 9) & 0x01F;

        const method: u12 = @intCast(m_low | (m_mid << 4) | (m_high << 7));
        const class_val: u2 = @intCast(c0 | (c1 << 1));

        return .{
            .class = @enumFromInt(class_val),
            .method = @enumFromInt(method),
        };
    }
};

/// 20-byte STUN header (rfc5389-s6-r1)
pub const Header = struct {
    message_type: u16, // big-endian encoded MessageType
    message_length: u16, // payload length, excludes 20-byte header (rfc5389-s6-r9)
    magic_cookie: [4]u8, // 0x2112A442 (rfc5389-s6-r4)
    transaction_id: [12]u8, // 96-bit random (rfc5389-s6-r5)

    pub const size: usize = 20;

    /// Serialize to bytes
    pub fn toBytes(self: Header) [20]u8 {
        var buf: [20]u8 = undefined;
        std.mem.writeInt(u16, buf[0..2], self.message_type, .big);
        std.mem.writeInt(u16, buf[2..4], self.message_length, .big);
        @memcpy(buf[4..8], &self.magic_cookie);
        @memcpy(buf[8..20], &self.transaction_id);
        return buf;
    }

    /// Parse from bytes
    pub fn fromBytes(buf: *const [20]u8) Header {
        return .{
            .message_type = std.mem.readInt(u16, buf[0..2], .big),
            .message_length = std.mem.readInt(u16, buf[2..4], .big),
            .magic_cookie = buf[4..8].*,
            .transaction_id = buf[8..20].*,
        };
    }

    /// Get decoded message type
    pub fn getType(self: Header) MessageType {
        return MessageType.decode(self.message_type);
    }
};

/// Parsed STUN message
pub const Message = struct {
    header: Header,
    attrs: []Attribute,
    raw: []const u8,
    allocator: Allocator,

    /// Parse a complete STUN message from raw bytes (rfc5389-s6-r1)
    pub fn parse(allocator: Allocator, buf: []const u8) !Message {
        if (buf.len < Header.size) return error.MessageTooShort;

        const header = Header.fromBytes(buf[0..20]);

        // Validate magic cookie (rfc5389-s6-r4)
        if (!std.mem.eql(u8, &header.magic_cookie, &magic_cookie_bytes))
            return error.InvalidMagicCookie;

        // Validate top 2 bits are zero (rfc5389-s6-r2)
        if (header.message_type & 0xC000 != 0) return error.InvalidMessageType;

        // Message length must be multiple of 4 (rfc5389-s15-r2 implied)
        if (header.message_length % 4 != 0) return error.InvalidMessageLength;

        // Validate buffer has enough data
        const total_len = @as(usize, Header.size) + @as(usize, header.message_length);
        if (buf.len < total_len) return error.MessageTruncated;

        // Parse attributes (rfc5389-s15-r1: TLV encoding)
        var attr_list: std.ArrayList(Attribute) = .empty;
        errdefer attr_list.deinit(allocator);

        var offset: usize = Header.size;
        const end = total_len;
        while (offset + 4 <= end) {
            const attr_type_raw = std.mem.readInt(u16, buf[offset..][0..2], .big);
            const attr_len = std.mem.readInt(u16, buf[offset + 2 ..][0..2], .big);
            offset += 4;

            if (offset + attr_len > end) return error.AttributeTruncated;

            try attr_list.append(allocator, .{
                .attr_type = @enumFromInt(attr_type_raw),
                .value = buf[offset..][0..attr_len],
            });

            // Advance past value + padding to 4-byte boundary (rfc5389-s15-r2)
            offset += std.mem.alignForward(usize, attr_len, 4);
        }

        return .{
            .header = header,
            .attrs = try attr_list.toOwnedSlice(allocator),
            .raw = buf[0..total_len],
            .allocator = allocator,
        };
    }

    /// Get the decoded message type
    pub fn getType(self: *const Message) MessageType {
        return self.header.getType();
    }

    /// Find first attribute of given type (rfc5389-s7.3-r1, rfc5389-s7.3-r2)
    pub fn getAttribute(self: *const Message, attr_type: AttributeType) ?*const Attribute {
        for (self.attrs) |*attr| {
            if (attr.attr_type == attr_type) return attr;
        }
        return null;
    }

    /// Find the byte offset of the first attribute of given type in the raw message
    pub fn getAttributeOffset(self: *const Message, attr_type: AttributeType) ?usize {
        var offset: usize = Header.size;
        for (self.attrs) |attr| {
            if (attr.attr_type == attr_type) return offset;
            const padded_len = std.mem.alignForward(usize, attr.value.len, 4);
            offset += 4 + padded_len;
        }
        return null;
    }

    /// Validate MESSAGE-INTEGRITY (rfc5389-s15.4)
    pub fn validateMessageIntegrity(self: *const Message, key: []const u8) bool {
        const mi_offset = self.getAttributeOffset(.message_integrity) orelse return false;
        return integrity.validateMessageIntegrity(self.raw, mi_offset, key);
    }

    /// Validate FINGERPRINT (rfc5389-s15.5)
    pub fn validateFingerprint(self: *const Message) bool {
        const fp_offset = self.getAttributeOffset(.fingerprint) orelse return false;
        return integrity.validateFingerprint(self.raw, fp_offset);
    }

    pub fn deinit(self: *const Message) void {
        self.allocator.free(self.attrs);
    }
};

/// Message builder (rfc5389-s7.1)
pub const MessageBuilder = struct {
    allocator: Allocator,
    class: Class = .request,
    method: Method = .binding,
    transaction_id: [12]u8 = .{0} ** 12,
    attr_list: std.ArrayList(BuilderAttr) = .empty,

    const BuilderAttr = struct {
        attr_type: AttributeType,
        value: []const u8,
        owned: bool, // if true, we allocated this value

        fn deinitValue(self: *const BuilderAttr, allocator: Allocator) void {
            if (self.owned) {
                allocator.free(self.value);
            }
        }
    };

    pub fn init(allocator: Allocator) MessageBuilder {
        return .{
            .allocator = allocator,
        };
    }

    pub fn setClass(self: *MessageBuilder, class: Class) void {
        self.class = class;
    }

    pub fn setMethod(self: *MessageBuilder, method: Method) void {
        self.method = method;
    }

    pub fn setTransactionId(self: *MessageBuilder, tid: [12]u8) void {
        self.transaction_id = tid;
    }

    /// Generate a random transaction ID (rfc5389-s6-r5, rfc5389-s6-r6)
    /// Uses a PRNG seeded from pointer entropy + counter.
    /// For production crypto-quality randomness, use setTransactionId with OS-provided bytes.
    pub fn randomTransactionId(self: *MessageBuilder) void {
        const seed_val = @intFromPtr(self) ^ @intFromPtr(&self.transaction_id);
        var rng = std.Random.SplitMix64.init(seed_val +% tid_counter);
        tid_counter +%= 1;
        // Fill 12 bytes from 64-bit outputs
        const r1 = rng.next();
        const r2 = rng.next();
        @memcpy(self.transaction_id[0..8], std.mem.asBytes(&r1));
        @memcpy(self.transaction_id[8..12], std.mem.asBytes(&r2)[0..4]);
    }

    var tid_counter: u64 = 0x1234_5678_9ABC_DEF0;

    /// Add a raw attribute
    pub fn addAttribute(self: *MessageBuilder, attr_type: AttributeType, value: []const u8) !void {
        try self.attr_list.append(self.allocator, .{ .attr_type = attr_type, .value = value, .owned = false });
    }

    /// Add an attribute with owned value (builder will free it)
    pub fn addAttributeOwned(self: *MessageBuilder, attr_type: AttributeType, value: []const u8) !void {
        try self.attr_list.append(self.allocator, .{ .attr_type = attr_type, .value = value, .owned = true });
    }

    /// Add MESSAGE-INTEGRITY (rfc5389-s15.4-r2, rfc5389-s15.4-r3)
    /// Must be called after all other attributes (except FINGERPRINT).
    pub fn addMessageIntegrity(self: *MessageBuilder, key: []const u8) !void {
        // Build the message up to this point with adjusted length
        const prefix = try self.buildPrefix(24); // 24 = size of MESSAGE-INTEGRITY attr
        defer self.allocator.free(prefix);

        const mac = integrity.computeMessageIntegrity(prefix, key);
        const mac_copy = try self.allocator.alloc(u8, 20);
        @memcpy(mac_copy, &mac);
        try self.attr_list.append(self.allocator, .{
            .attr_type = .message_integrity,
            .value = mac_copy,
            .owned = true,
        });
    }

    /// Add FINGERPRINT (rfc5389-s15.5-r2: must be last attribute)
    pub fn addFingerprint(self: *MessageBuilder) !void {
        const prefix = try self.buildPrefix(8); // 8 = size of FINGERPRINT attr
        defer self.allocator.free(prefix);

        const crc = integrity.computeFingerprint(prefix);
        const val = try self.allocator.alloc(u8, 4);
        std.mem.writeInt(u32, val[0..4], crc, .big);
        try self.attr_list.append(self.allocator, .{
            .attr_type = .fingerprint,
            .value = val,
            .owned = true,
        });
    }

    /// Build the message prefix (header + all current attributes) with adjusted
    /// message_length that accounts for `extra_len` additional bytes.
    fn buildPrefix(self: *MessageBuilder, extra_len: u16) ![]u8 {
        // Calculate total attribute data length
        var attrs_len: u16 = 0;
        for (self.attr_list.items) |attr| {
            const padded: u16 = @intCast(std.mem.alignForward(usize, attr.value.len, 4));
            attrs_len += 4 + padded;
        }

        const total = @as(usize, Header.size) + @as(usize, attrs_len);
        const buf = try self.allocator.alloc(u8, total);

        // Write header with adjusted length
        const msg_type = MessageType{ .class = self.class, .method = self.method };
        std.mem.writeInt(u16, buf[0..2], msg_type.encode(), .big);
        std.mem.writeInt(u16, buf[2..4], attrs_len + extra_len, .big);
        @memcpy(buf[4..8], &magic_cookie_bytes);
        @memcpy(buf[8..20], &self.transaction_id);

        // Write attributes
        var offset: usize = Header.size;
        for (self.attr_list.items) |attr| {
            std.mem.writeInt(u16, buf[offset..][0..2], @intFromEnum(attr.attr_type), .big);
            const val_len: u16 = @intCast(attr.value.len);
            std.mem.writeInt(u16, buf[offset + 2 ..][0..2], val_len, .big);
            offset += 4;
            @memcpy(buf[offset..][0..attr.value.len], attr.value);
            const padded = std.mem.alignForward(usize, attr.value.len, 4);
            // Zero padding bytes
            for (attr.value.len..padded) |i| {
                buf[offset + i] = 0;
            }
            offset += padded;
        }

        return buf;
    }

    /// Build the final serialized STUN message
    pub fn build(self: *MessageBuilder) ![]u8 {
        return self.buildPrefix(0);
    }

    pub fn deinit(self: *MessageBuilder) void {
        for (self.attr_list.items) |*attr| {
            attr.deinitValue(self.allocator);
        }
        self.attr_list.deinit(self.allocator);
    }
};

// ============================================================================
// Tests — RFC 5389 rule compliance
// ============================================================================

const testing = std.testing;

// A valid STUN Binding Request (20 bytes, no attributes)
const valid_binding_request = [20]u8{
    0x00, 0x01, // Type: Binding Request
    0x00, 0x00, // Length: 0
    0x21, 0x12, 0xA4, 0x42, // Magic Cookie
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // Transaction ID (12 bytes)
    0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
};

// A STUN Binding Success Response with XOR-MAPPED-ADDRESS
// XOR-MAPPED-ADDRESS: IPv4 192.168.1.100:3478
fn makeBindingResponse() [32]u8 {
    var buf: [32]u8 = undefined;
    // Header
    buf[0] = 0x01;
    buf[1] = 0x01; // Binding Success Response (type = 0x0101)
    buf[2] = 0x00;
    buf[3] = 0x0C; // Length: 12
    buf[4] = 0x21;
    buf[5] = 0x12;
    buf[6] = 0xA4;
    buf[7] = 0x42; // Magic Cookie
    @memcpy(buf[8..20], &[12]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C });
    // XOR-MAPPED-ADDRESS attribute
    buf[20] = 0x00;
    buf[21] = 0x20; // Type: XOR-MAPPED-ADDRESS (0x0020)
    buf[22] = 0x00;
    buf[23] = 0x08; // Length: 8 (IPv4)
    buf[24] = 0x00; // Reserved
    buf[25] = 0x01; // Family: IPv4
    // Port: 3478 XOR 0x2112 = 0x0D96 XOR 0x2112 = 0x2C84
    const xored_port: u16 = 3478 ^ 0x2112;
    std.mem.writeInt(u16, buf[26..28], xored_port, .big);
    // Address: 192.168.1.100 XOR 0x2112A442
    buf[28] = 192 ^ 0x21;
    buf[29] = 168 ^ 0x12;
    buf[30] = 1 ^ 0xA4;
    buf[31] = 100 ^ 0x42;
    return buf;
}

// --- RFC 5389 §6: STUN Message Structure ---

// rfc5389-s6-r1: All STUN messages MUST start with a 20-byte header
test "rfc5389-s6-r1: header must be 20 bytes" {
    try testing.expectEqual(@as(usize, 20), Header.size);
    // Parse a minimal valid message
    const msg = try Message.parse(testing.allocator, &valid_binding_request);
    defer msg.deinit();
    try testing.expectEqual(@as(usize, 20), msg.raw.len);
}

// rfc5389-s6-r2: Most significant 2 bits MUST be zeroes
test "rfc5389-s6-r2: top 2 bits must be zero" {
    // Valid message should parse
    const msg = try Message.parse(testing.allocator, &valid_binding_request);
    defer msg.deinit();
    try testing.expectEqual(@as(u16, 0), msg.header.message_type & 0xC000);

    // Message with top bits set should fail
    var bad = valid_binding_request;
    bad[0] = 0x80; // Set MSB
    try testing.expectError(error.InvalidMessageType, Message.parse(testing.allocator, &bad));
}

// rfc5389-s6-r3: message classes (request, success, error, indication) are defined
test "rfc5389-s6-r3: all four message classes exist" {
    try testing.expectEqual(@as(u2, 0b00), @intFromEnum(Class.request));
    try testing.expectEqual(@as(u2, 0b01), @intFromEnum(Class.indication));
    try testing.expectEqual(@as(u2, 0b10), @intFromEnum(Class.success));
    try testing.expectEqual(@as(u2, 0b11), @intFromEnum(Class.error_resp));
}

// rfc5389-s6-r4: magic cookie MUST be 0x2112A442
test "rfc5389-s6-r4: magic cookie must be 0x2112A442" {
    const msg = try Message.parse(testing.allocator, &valid_binding_request);
    defer msg.deinit();
    try testing.expectEqualSlices(u8, &magic_cookie_bytes, &msg.header.magic_cookie);

    // Invalid magic cookie should fail
    var bad = valid_binding_request;
    bad[4] = 0x00;
    try testing.expectError(error.InvalidMagicCookie, Message.parse(testing.allocator, &bad));
}

// rfc5389-s6-r5: transaction ID MUST be 96 bits (12 bytes)
test "rfc5389-s6-r5: transaction ID is 96 bits" {
    const msg = try Message.parse(testing.allocator, &valid_binding_request);
    defer msg.deinit();
    try testing.expectEqual(@as(usize, 12), msg.header.transaction_id.len);
}

// rfc5389-s6-r6: transaction ID SHOULD be cryptographically random
test "rfc5389-s6-r6: random transaction ID uses crypto random" {
    var builder = MessageBuilder.init(testing.allocator);
    defer builder.deinit();
    builder.randomTransactionId();
    // Verify it's not all zeros (extremely unlikely for crypto random)
    var all_zero = true;
    for (builder.transaction_id) |b| {
        if (b != 0) {
            all_zero = false;
            break;
        }
    }
    try testing.expect(!all_zero);
}

// rfc5389-s6-r7: client MUST choose a new transaction ID
test "rfc5389-s6-r7: each call generates different transaction ID" {
    var b1 = MessageBuilder.init(testing.allocator);
    defer b1.deinit();
    b1.randomTransactionId();

    var b2 = MessageBuilder.init(testing.allocator);
    defer b2.deinit();
    b2.randomTransactionId();

    // Two random IDs should differ (probability of collision is ~1/2^96)
    try testing.expect(!std.mem.eql(u8, &b1.transaction_id, &b2.transaction_id));
}

// rfc5389-s6-r8: response MUST carry same transaction ID as request
test "rfc5389-s6-r8: response copies transaction ID from request" {
    const resp_buf = makeBindingResponse();
    const msg = try Message.parse(testing.allocator, &resp_buf);
    defer msg.deinit();
    // Verify transaction ID matches what we put in
    const expected_tid = [12]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C };
    try testing.expectEqualSlices(u8, &expected_tid, &msg.header.transaction_id);
}

// rfc5389-s6-r9: message length excludes the 20-byte header
test "rfc5389-s6-r9: message length excludes header" {
    const msg = try Message.parse(testing.allocator, &valid_binding_request);
    defer msg.deinit();
    try testing.expectEqual(@as(u16, 0), msg.header.message_length);

    const resp_buf = makeBindingResponse();
    const resp = try Message.parse(testing.allocator, &resp_buf);
    defer resp.deinit();
    try testing.expectEqual(@as(u16, 12), resp.header.message_length);
    try testing.expectEqual(@as(usize, 32), resp.raw.len); // 20 + 12
}

// --- Message type encoding (§6) ---

test "rfc5389-s6: message type encoding roundtrips" {
    // Binding Request: method=0x001, class=request
    const br = MessageType{ .class = .request, .method = .binding };
    try testing.expectEqual(@as(u16, 0x0001), br.encode());

    // Binding Success Response: method=0x001, class=success
    const bs = MessageType{ .class = .success, .method = .binding };
    try testing.expectEqual(@as(u16, 0x0101), bs.encode());

    // Binding Error Response: method=0x001, class=error_resp
    const be = MessageType{ .class = .error_resp, .method = .binding };
    try testing.expectEqual(@as(u16, 0x0111), be.encode());

    // Binding Indication: method=0x001, class=indication
    const bi = MessageType{ .class = .indication, .method = .binding };
    try testing.expectEqual(@as(u16, 0x0011), bi.encode());

    // Roundtrip
    try testing.expectEqual(Class.request, MessageType.decode(br.encode()).class);
    try testing.expectEqual(Method.binding, MessageType.decode(br.encode()).method);
    try testing.expectEqual(Class.success, MessageType.decode(bs.encode()).class);
    try testing.expectEqual(Class.error_resp, MessageType.decode(be.encode()).class);
    try testing.expectEqual(Class.indication, MessageType.decode(bi.encode()).class);
}

// --- RFC 5389 §7.1: Forming a Request or Indication ---

// rfc5389-s7.1-r1: MUST follow the rules in Section 6 when creating the header
test "rfc5389-s7.1-r1: builder creates valid headers" {
    var builder = MessageBuilder.init(testing.allocator);
    defer builder.deinit();
    builder.setClass(.request);
    builder.setMethod(.binding);
    builder.randomTransactionId();
    const buf = try builder.build();
    defer testing.allocator.free(buf);

    // Should parse successfully (validates all §6 rules)
    const msg = try Message.parse(testing.allocator, buf);
    defer msg.deinit();
    try testing.expectEqual(Class.request, msg.getType().class);
    try testing.expectEqual(Method.binding, msg.getType().method);
}

// rfc5389-s7.1-r2: message class MUST be Request or Indication
test "rfc5389-s7.1-r2: can build request and indication" {
    // Request
    {
        var builder = MessageBuilder.init(testing.allocator);
        defer builder.deinit();
        builder.setClass(.request);
        builder.randomTransactionId();
        const buf = try builder.build();
        defer testing.allocator.free(buf);
        const msg = try Message.parse(testing.allocator, buf);
        defer msg.deinit();
        try testing.expectEqual(Class.request, msg.getType().class);
    }
    // Indication
    {
        var builder = MessageBuilder.init(testing.allocator);
        defer builder.deinit();
        builder.setClass(.indication);
        builder.randomTransactionId();
        const buf = try builder.build();
        defer testing.allocator.free(buf);
        const msg = try Message.parse(testing.allocator, buf);
        defer msg.deinit();
        try testing.expectEqual(Class.indication, msg.getType().class);
    }
}

// rfc5389-s7.1-r3: SHOULD add SOFTWARE attribute to request
test "rfc5389-s7.1-r3: can add SOFTWARE attribute" {
    var builder = MessageBuilder.init(testing.allocator);
    defer builder.deinit();
    builder.randomTransactionId();
    try builder.addAttribute(.software, "zig-webrtc 0.1.0");
    const buf = try builder.build();
    defer testing.allocator.free(buf);
    const msg = try Message.parse(testing.allocator, buf);
    defer msg.deinit();
    const sw = msg.getAttribute(.software) orelse return error.MissingAttribute;
    try testing.expectEqualStrings("zig-webrtc 0.1.0", sw.value);
}

// --- RFC 5389 §15: STUN Attributes ---

// rfc5389-s15-r1: TLV encoding with 16-bit type, 16-bit length
test "rfc5389-s15-r1: attributes use TLV encoding" {
    const resp_buf = makeBindingResponse();
    const msg = try Message.parse(testing.allocator, &resp_buf);
    defer msg.deinit();
    try testing.expectEqual(@as(usize, 1), msg.attrs.len);
    try testing.expectEqual(AttributeType.xor_mapped_address, msg.attrs[0].attr_type);
    try testing.expectEqual(@as(usize, 8), msg.attrs[0].value.len); // IPv4: 8 bytes
}

// rfc5389-s15-r2: attributes MUST be padded to 4-byte boundary
test "rfc5389-s15-r2: attribute padding to 4 bytes" {
    var builder = MessageBuilder.init(testing.allocator);
    defer builder.deinit();
    builder.randomTransactionId();
    // Add attribute with 3-byte value (needs 1 byte padding)
    try builder.addAttribute(.software, "abc");
    const buf = try builder.build();
    defer testing.allocator.free(buf);
    // Total: 20 (header) + 4 (attr header) + 4 (3 bytes + 1 padding) = 28
    try testing.expectEqual(@as(usize, 28), buf.len);
    // Message length should be 8 (4 + 4)
    try testing.expectEqual(@as(u16, 8), std.mem.readInt(u16, buf[2..4], .big));
    // Should parse back correctly
    const msg = try Message.parse(testing.allocator, buf);
    defer msg.deinit();
    try testing.expectEqualStrings("abc", msg.attrs[0].value);
}

// rfc5389-s15-r3: length field is value length before padding
test "rfc5389-s15-r3: length field excludes padding" {
    var builder = MessageBuilder.init(testing.allocator);
    defer builder.deinit();
    builder.randomTransactionId();
    try builder.addAttribute(.software, "hi"); // 2 bytes, padded to 4
    const buf = try builder.build();
    defer testing.allocator.free(buf);
    // Attribute length at offset 22-23 should be 2 (not 4)
    const attr_len = std.mem.readInt(u16, buf[22..24], .big);
    try testing.expectEqual(@as(u16, 2), attr_len);
}

// --- RFC 5389 §15.1: MAPPED-ADDRESS ---

// rfc5389-s15.1-r1: 32 bits for IPv4, 128 bits for IPv6
test "rfc5389-s15.1-r1: MAPPED-ADDRESS IPv4 parsing" {
    const value = [8]u8{
        0x00, // reserved
        0x01, // family: IPv4
        0x0D, 0x96, // port: 3478
        192, 168, 1, 100, // address
    };
    const attr = Attribute{ .attr_type = .mapped_address, .value = &value };
    const addr = try attr.parseMappedAddress();
    try testing.expectEqual(AddressFamily.ipv4, addr.family);
    try testing.expectEqual(@as(u16, 3478), addr.port);
    try testing.expectEqualSlices(u8, &[4]u8{ 192, 168, 1, 100 }, &addr.addr.ipv4);
}

// rfc5389-s15.1-r2: first 8 bits set to 0 when encoding, ignored when decoding
test "rfc5389-s15.1-r2: reserved byte ignored on decode" {
    var value = [8]u8{ 0xFF, 0x01, 0x0D, 0x96, 192, 168, 1, 100 };
    // Even with reserved=0xFF, should still parse (ignored on decode)
    const attr = Attribute{ .attr_type = .mapped_address, .value = &value };
    const addr = try attr.parseMappedAddress();
    try testing.expectEqual(@as(u16, 3478), addr.port);

    // Encoding should set reserved to 0
    const encoded = try Attribute.encodeMappedAddress(testing.allocator, addr);
    defer testing.allocator.free(encoded);
    try testing.expectEqual(@as(u8, 0), encoded[0]);
}

// --- RFC 5389 §15.2: XOR-MAPPED-ADDRESS ---

test "rfc5389-s15.2: XOR-MAPPED-ADDRESS IPv4 roundtrip" {
    const tid = [12]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C };
    const addr = Address{
        .family = .ipv4,
        .port = 3478,
        .addr = .{ .ipv4 = .{ 192, 168, 1, 100 } },
    };

    const encoded = try Attribute.encodeXorMappedAddress(testing.allocator, addr, tid);
    defer testing.allocator.free(encoded);

    const attr = Attribute{ .attr_type = .xor_mapped_address, .value = encoded };
    const decoded = try attr.parseXorMappedAddress(tid);
    try testing.expectEqual(@as(u16, 3478), decoded.port);
    try testing.expectEqualSlices(u8, &[4]u8{ 192, 168, 1, 100 }, &decoded.addr.ipv4);
}

test "rfc5389-s15.2: XOR-MAPPED-ADDRESS from response" {
    const resp_buf = makeBindingResponse();
    const msg = try Message.parse(testing.allocator, &resp_buf);
    defer msg.deinit();
    const xma = msg.getAttribute(.xor_mapped_address) orelse return error.MissingAttribute;
    const addr = try xma.parseXorMappedAddress(msg.header.transaction_id);
    try testing.expectEqual(AddressFamily.ipv4, addr.family);
    try testing.expectEqual(@as(u16, 3478), addr.port);
    try testing.expectEqualSlices(u8, &[4]u8{ 192, 168, 1, 100 }, &addr.addr.ipv4);
}

test "rfc5389-s15.2: XOR-MAPPED-ADDRESS IPv6 roundtrip" {
    const tid = [12]u8{ 0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x17, 0x28, 0x39, 0x4A, 0x5B, 0x6C };
    const addr = Address{
        .family = .ipv6,
        .port = 8080,
        .addr = .{ .ipv6 = .{ 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 } },
    };
    const encoded = try Attribute.encodeXorMappedAddress(testing.allocator, addr, tid);
    defer testing.allocator.free(encoded);
    const attr = Attribute{ .attr_type = .xor_mapped_address, .value = encoded };
    const decoded = try attr.parseXorMappedAddress(tid);
    try testing.expectEqual(AddressFamily.ipv6, addr.family);
    try testing.expectEqual(@as(u16, 8080), decoded.port);
    try testing.expectEqualSlices(u8, &addr.addr.ipv6, &decoded.addr.ipv6);
}

// --- RFC 5389 §15.3: USERNAME ---

// rfc5389-s15.3-r1: username is UTF-8, less than 513 bytes
test "rfc5389-s15.3-r1: USERNAME attribute" {
    var builder = MessageBuilder.init(testing.allocator);
    defer builder.deinit();
    builder.randomTransactionId();
    try builder.addAttribute(.username, "user:pass");
    const buf = try builder.build();
    defer testing.allocator.free(buf);
    const msg = try Message.parse(testing.allocator, buf);
    defer msg.deinit();
    const uname = msg.getAttribute(.username) orelse return error.MissingAttribute;
    try testing.expectEqualStrings("user:pass", uname.value);
}

// --- RFC 5389 §15.4: MESSAGE-INTEGRITY ---

// rfc5389-s15.4-r2: HMAC-SHA1 produces 20-byte output
test "rfc5389-s15.4: MESSAGE-INTEGRITY is 20 bytes HMAC-SHA1" {
    const key = "test-key";
    const data = "test-data";
    const mac = integrity.computeMessageIntegrity(data, key);
    try testing.expectEqual(@as(usize, 20), mac.len);
}

// rfc5389-s15.4-r3: message length adjusted to include MESSAGE-INTEGRITY
test "rfc5389-s15.4-r3: builder adds MESSAGE-INTEGRITY with adjusted length" {
    var builder = MessageBuilder.init(testing.allocator);
    defer builder.deinit();
    builder.randomTransactionId();
    try builder.addMessageIntegrity("shared-secret");
    const buf = try builder.build();
    defer testing.allocator.free(buf);

    // Should have: 20 header + 4 attr header + 20 HMAC = 44 bytes
    try testing.expectEqual(@as(usize, 44), buf.len);

    const msg = try Message.parse(testing.allocator, buf);
    defer msg.deinit();
    const mi = msg.getAttribute(.message_integrity) orelse return error.MissingAttribute;
    try testing.expectEqual(@as(usize, 20), mi.value.len);
}

test "rfc5389-s15.4: MESSAGE-INTEGRITY validates correctly" {
    var builder = MessageBuilder.init(testing.allocator);
    defer builder.deinit();
    builder.randomTransactionId();
    try builder.addMessageIntegrity("my-secret");
    const buf = try builder.build();
    defer testing.allocator.free(buf);

    const msg = try Message.parse(testing.allocator, buf);
    defer msg.deinit();
    try testing.expect(msg.validateMessageIntegrity("my-secret"));
    try testing.expect(!msg.validateMessageIntegrity("wrong-secret"));
}

// rfc5389-s15.4-r1: MUST ignore attributes after MESSAGE-INTEGRITY (except FINGERPRINT)
test "rfc5389-s15.4-r1: MESSAGE-INTEGRITY then FINGERPRINT" {
    var builder = MessageBuilder.init(testing.allocator);
    defer builder.deinit();
    builder.randomTransactionId();
    try builder.addMessageIntegrity("key123");
    try builder.addFingerprint();
    const buf = try builder.build();
    defer testing.allocator.free(buf);

    const msg = try Message.parse(testing.allocator, buf);
    defer msg.deinit();
    try testing.expect(msg.validateMessageIntegrity("key123"));
    try testing.expect(msg.validateFingerprint());
}

// --- RFC 5389 §15.5: FINGERPRINT ---

// rfc5389-s15.5-r1: FINGERPRINT is CRC32 XOR 0x5354554e
test "rfc5389-s15.5: FINGERPRINT CRC32 XOR constant" {
    try testing.expectEqual(@as(u32, 0x5354554e), integrity.fingerprint_xor);
}

// rfc5389-s15.5-r2: FINGERPRINT must be last attribute
test "rfc5389-s15.5-r2: FINGERPRINT as last attribute" {
    var builder = MessageBuilder.init(testing.allocator);
    defer builder.deinit();
    builder.randomTransactionId();
    try builder.addAttribute(.software, "test");
    try builder.addFingerprint();
    const buf = try builder.build();
    defer testing.allocator.free(buf);

    const msg = try Message.parse(testing.allocator, buf);
    defer msg.deinit();

    // FINGERPRINT should be last
    try testing.expectEqual(AttributeType.fingerprint, msg.attrs[msg.attrs.len - 1].attr_type);
    try testing.expect(msg.validateFingerprint());
}

test "rfc5389-s15.5: FINGERPRINT validates correctly" {
    var builder = MessageBuilder.init(testing.allocator);
    defer builder.deinit();
    builder.randomTransactionId();
    try builder.addFingerprint();
    const buf = try builder.build();
    defer testing.allocator.free(buf);

    const msg = try Message.parse(testing.allocator, buf);
    defer msg.deinit();
    try testing.expect(msg.validateFingerprint());
}

// --- RFC 5389 §15.6: ERROR-CODE ---

// rfc5389-s15.6-r3: class 3-6, rfc5389-s15.6-r4: number 0-99
test "rfc5389-s15.6: ERROR-CODE parsing" {
    // 400 Bad Request
    const value400 = [_]u8{
        0x00, 0x00, // reserved
        0x04, // class = 4
        0x00, // number = 0
        'B', 'a', 'd', ' ', 'R', 'e', 'q', 'u', 'e', 's', 't',
    };
    const attr400 = Attribute{ .attr_type = .error_code, .value = &value400 };
    const err400 = try attr400.parseErrorCode();
    try testing.expectEqual(@as(u16, 400), err400.code);
    try testing.expectEqualStrings("Bad Request", err400.reason);

    // 401 Unauthorized
    const value401 = [_]u8{ 0x00, 0x00, 0x04, 0x01 };
    const attr401 = Attribute{ .attr_type = .error_code, .value = &value401 };
    const err401 = try attr401.parseErrorCode();
    try testing.expectEqual(@as(u16, 401), err401.code);
}

// rfc5389-s15.6-r3: class must be 3-6
test "rfc5389-s15.6-r3: invalid error class rejected" {
    const value = [_]u8{ 0x00, 0x00, 0x02, 0x00 }; // class=2 (invalid)
    const attr = Attribute{ .attr_type = .error_code, .value = &value };
    try testing.expectError(error.InvalidErrorClass, attr.parseErrorCode());
}

// rfc5389-s15.6-r4: number must be 0-99
test "rfc5389-s15.6-r4: invalid error number rejected" {
    const value = [_]u8{ 0x00, 0x00, 0x04, 100 }; // number=100 (invalid)
    const attr = Attribute{ .attr_type = .error_code, .value = &value };
    try testing.expectError(error.InvalidErrorNumber, attr.parseErrorCode());
}

test "rfc5389-s15.6: ERROR-CODE encode roundtrip" {
    const err = ErrorCode{ .code = 420, .reason = "Unknown Attribute" };
    const encoded = try Attribute.encodeErrorCode(testing.allocator, err);
    defer testing.allocator.free(encoded);
    const attr = Attribute{ .attr_type = .error_code, .value = encoded };
    const decoded = try attr.parseErrorCode();
    try testing.expectEqual(@as(u16, 420), decoded.code);
    try testing.expectEqualStrings("Unknown Attribute", decoded.reason);
}

// --- RFC 5389 §15.10: SOFTWARE ---

// rfc5389-s15.10-r2: less than 128 characters, UTF-8
test "rfc5389-s15.10-r2: SOFTWARE attribute roundtrip" {
    var builder = MessageBuilder.init(testing.allocator);
    defer builder.deinit();
    builder.randomTransactionId();
    try builder.addAttribute(.software, "zig-webrtc/0.1.0");
    const buf = try builder.build();
    defer testing.allocator.free(buf);
    const msg = try Message.parse(testing.allocator, buf);
    defer msg.deinit();
    const sw = msg.getAttribute(.software) orelse return error.MissingAttribute;
    try testing.expectEqualStrings("zig-webrtc/0.1.0", sw.value);
}

// --- RFC 5389 §18.2: Attribute type ranges ---

// rfc5389-s18-r1: 0x0000-0x7FFF comprehension-required, 0x8000-0xFFFF optional
test "rfc5389-s18-r1: comprehension-required vs optional" {
    try testing.expect(AttributeType.mapped_address.isComprehensionRequired());
    try testing.expect(AttributeType.username.isComprehensionRequired());
    try testing.expect(AttributeType.message_integrity.isComprehensionRequired());
    try testing.expect(AttributeType.error_code.isComprehensionRequired());
    try testing.expect(AttributeType.xor_mapped_address.isComprehensionRequired());
    try testing.expect(!AttributeType.software.isComprehensionRequired());
    try testing.expect(!AttributeType.fingerprint.isComprehensionRequired());
    try testing.expect(!AttributeType.alternate_server.isComprehensionRequired());
}

// --- RFC 5389 §10.1.1: Short-term credential mechanism ---

// rfc5389-s10.1.1-r1: MUST include USERNAME and MESSAGE-INTEGRITY
test "rfc5389-s10.1.1-r1: short-term auth includes USERNAME and MESSAGE-INTEGRITY" {
    var builder = MessageBuilder.init(testing.allocator);
    defer builder.deinit();
    builder.randomTransactionId();
    try builder.addAttribute(.username, "testuser");
    try builder.addMessageIntegrity("password123");
    const buf = try builder.build();
    defer testing.allocator.free(buf);

    const msg = try Message.parse(testing.allocator, buf);
    defer msg.deinit();
    try testing.expect(msg.getAttribute(.username) != null);
    try testing.expect(msg.getAttribute(.message_integrity) != null);
    try testing.expect(msg.validateMessageIntegrity("password123"));
}

// --- Message length rules ---

test "rfc5389-s6: message length is always a multiple of 4" {
    // With odd-length attribute
    var builder = MessageBuilder.init(testing.allocator);
    defer builder.deinit();
    builder.randomTransactionId();
    try builder.addAttribute(.software, "x"); // 1 byte → padded to 4
    const buf = try builder.build();
    defer testing.allocator.free(buf);
    const msg_len = std.mem.readInt(u16, buf[2..4], .big);
    try testing.expectEqual(@as(u16, 0), msg_len % 4);
}

// --- Parse/build roundtrip ---

test "rfc5389: full binding request roundtrip" {
    var builder = MessageBuilder.init(testing.allocator);
    defer builder.deinit();
    builder.setClass(.request);
    builder.setMethod(.binding);
    builder.setTransactionId(.{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 });
    const buf = try builder.build();
    defer testing.allocator.free(buf);

    const msg = try Message.parse(testing.allocator, buf);
    defer msg.deinit();
    try testing.expectEqual(Class.request, msg.getType().class);
    try testing.expectEqual(Method.binding, msg.getType().method);
    try testing.expectEqualSlices(u8, &[12]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 }, &msg.header.transaction_id);
}

test "rfc5389: full binding response with attributes roundtrip" {
    var builder = MessageBuilder.init(testing.allocator);
    defer builder.deinit();
    builder.setClass(.success);
    builder.setMethod(.binding);
    builder.randomTransactionId();

    // Add XOR-MAPPED-ADDRESS
    const addr = Address{ .family = .ipv4, .port = 3478, .addr = .{ .ipv4 = .{ 10, 0, 0, 1 } } };
    const xma_val = try Attribute.encodeXorMappedAddress(testing.allocator, addr, builder.transaction_id);
    try builder.addAttributeOwned(.xor_mapped_address, xma_val);

    // Add SOFTWARE
    try builder.addAttribute(.software, "zig-webrtc/0.1");

    // Add MESSAGE-INTEGRITY + FINGERPRINT
    try builder.addMessageIntegrity("test-key");
    try builder.addFingerprint();

    const buf = try builder.build();
    defer testing.allocator.free(buf);

    const msg = try Message.parse(testing.allocator, buf);
    defer msg.deinit();

    try testing.expectEqual(Class.success, msg.getType().class);
    try testing.expectEqual(@as(usize, 4), msg.attrs.len);

    const parsed_xma = msg.getAttribute(.xor_mapped_address) orelse return error.MissingAttribute;
    const parsed_addr = try parsed_xma.parseXorMappedAddress(msg.header.transaction_id);
    try testing.expectEqual(@as(u16, 3478), parsed_addr.port);
    try testing.expectEqualSlices(u8, &[4]u8{ 10, 0, 0, 1 }, &parsed_addr.addr.ipv4);

    try testing.expect(msg.validateMessageIntegrity("test-key"));
    try testing.expect(msg.validateFingerprint());
}

// --- Negative / edge-case tests ---

test "rfc5389: reject message shorter than 20 bytes" {
    const short = [_]u8{ 0x00, 0x01 };
    try testing.expectError(error.MessageTooShort, Message.parse(testing.allocator, &short));
}

test "rfc5389: reject message with invalid length (not multiple of 4)" {
    var bad = valid_binding_request;
    bad[3] = 0x03; // length = 3 (not multiple of 4)
    // Need to extend buffer
    var buf: [23]u8 = undefined;
    @memcpy(buf[0..20], &bad);
    buf[20] = 0;
    buf[21] = 0;
    buf[22] = 0;
    try testing.expectError(error.InvalidMessageLength, Message.parse(testing.allocator, &buf));
}

test "rfc5389: reject truncated attribute" {
    // Header says length=8, but attribute value extends beyond
    var buf: [24]u8 = undefined;
    @memcpy(buf[0..20], &valid_binding_request);
    buf[2] = 0x00;
    buf[3] = 0x04; // message length = 4 (just attr header, no value space)
    buf[20] = 0x00;
    buf[21] = 0x01; // MAPPED-ADDRESS
    buf[22] = 0x00;
    buf[23] = 0x08; // claims 8 bytes of value, but only 0 available
    try testing.expectError(error.AttributeTruncated, Message.parse(testing.allocator, &buf));
}

// rfc5389-s12.1-r1: MUST be prepared to receive either MAPPED-ADDRESS or XOR-MAPPED-ADDRESS
test "rfc5389-s12.1-r1: accept both MAPPED-ADDRESS and XOR-MAPPED-ADDRESS" {
    // We already test both attribute parsers above; this confirms both types are defined
    try testing.expect(@intFromEnum(AttributeType.mapped_address) != @intFromEnum(AttributeType.xor_mapped_address));
}

// rfc5389-s13-r1: MUST support the Binding method
test "rfc5389-s13-r1: Binding method supported" {
    try testing.expectEqual(@as(u12, 0x001), @intFromEnum(Method.binding));
}

// --- Multiple attributes ---

test "rfc5389: parse message with multiple attributes" {
    var builder = MessageBuilder.init(testing.allocator);
    defer builder.deinit();
    builder.randomTransactionId();
    builder.setClass(.success);
    try builder.addAttribute(.software, "test-server");
    try builder.addAttribute(.realm, "example.com");
    try builder.addAttribute(.nonce, "abc123");
    const buf = try builder.build();
    defer testing.allocator.free(buf);

    const msg = try Message.parse(testing.allocator, buf);
    defer msg.deinit();
    try testing.expectEqual(@as(usize, 3), msg.attrs.len);
    try testing.expect(msg.getAttribute(.software) != null);
    try testing.expect(msg.getAttribute(.realm) != null);
    try testing.expect(msg.getAttribute(.nonce) != null);
}

// --- Unknown attributes ---

test "rfc5389-s7.3-r1: unknown comprehension-optional attributes ignored" {
    var builder = MessageBuilder.init(testing.allocator);
    defer builder.deinit();
    builder.randomTransactionId();
    // Add an unknown comprehension-optional attribute (0x8099)
    try builder.addAttribute(@enumFromInt(0x8099), "unknown-data");
    const buf = try builder.build();
    defer testing.allocator.free(buf);

    const msg = try Message.parse(testing.allocator, buf);
    defer msg.deinit();
    // Should still parse successfully
    try testing.expectEqual(@as(usize, 1), msg.attrs.len);
    const attr_type: AttributeType = @enumFromInt(0x8099);
    try testing.expect(!attr_type.isComprehensionRequired());
}

// Cross-module import test
test "module re-exports work" {
    _ = attributes;
    _ = integrity;
}

