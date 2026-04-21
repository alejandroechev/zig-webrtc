//! TURN relay client (RFC 8656)
//! Generated from 144 structured RFC 8656 rules via RFC Compliance API grounding layer.
//!
//! This module implements:
//!   - TURN-specific STUN methods: Allocate, Refresh, Send, Data, CreatePermission, ChannelBind (§5-§12)
//!   - TURN-specific STUN attributes: CHANNEL-NUMBER, LIFETIME, XOR-PEER-ADDRESS, DATA, etc. (§18)
//!   - ChannelData message framing (4-byte header, not STUN) (§12.5)
//!   - TURN client state machine: allocation, permissions, channel bindings (§6-§12)
//!   - Message building helpers for all TURN request types
//!
//! Key RFC 8656 MUST rules implemented:
//!   - rfc8656-s7.1-r4:  Allocate MUST include REQUESTED-TRANSPORT
//!   - rfc8656-s8-r1:    Client MUST refresh before lifetime expires
//!   - rfc8656-s10.1-r1: CreatePermission MUST include XOR-PEER-ADDRESS
//!   - rfc8656-s10.1-r4: XOR-PEER-ADDRESS MUST match allocation address family
//!   - rfc8656-s12-r1:   Channel binding MUST comply with demux scheme (0x4000-0x7FFF)
//!   - rfc8656-s12.5-r2: ChannelData over TCP MUST be padded to 4-byte boundary
//!   - rfc8656-s9-r1:    Permission lifetime MUST be 300 seconds

const std = @import("std");
const Allocator = std.mem.Allocator;
const stun = @import("../stun/stun.zig");

// ============================================================================
// TURN Methods (RFC 8656 §18.1) — extend STUN method space
// ============================================================================

/// TURN-specific STUN methods (RFC 8656 §18.1)
/// These are used as the method field in STUN MessageType.
pub const TurnMethod = enum(u12) {
    allocate = 0x003,
    refresh = 0x004,
    send = 0x006, // indication only
    data = 0x007, // indication only
    create_permission = 0x008,
    channel_bind = 0x009,
};

// ============================================================================
// TURN Attributes (RFC 8656 §18.2)
// ============================================================================

/// TURN-specific STUN attribute types (RFC 8656 §18.2)
pub const TurnAttributeType = enum(u16) {
    channel_number = 0x000C,
    lifetime = 0x000D,
    xor_peer_address = 0x0012,
    data = 0x0013,
    xor_relayed_address = 0x0016,
    requested_transport = 0x0019,
    dont_fragment = 0x001A,
    requested_address_family = 0x0017,
    additional_address_family = 0x8011,
    address_error_code = 0x8012,
    icmp = 0x8004,
    even_port = 0x0018,
    reservation_token = 0x0022,
};

/// IANA protocol numbers for REQUESTED-TRANSPORT
pub const Transport = struct {
    pub const udp: u8 = 17;
    pub const tcp: u8 = 6;
};

/// Default allocation lifetime in seconds (rfc8656-s7.2-r15: max 3600)
pub const default_lifetime: u32 = 600;

/// Permission lifetime in seconds (rfc8656-s9-r1: MUST be 300)
pub const permission_lifetime: u32 = 300;

/// Channel number valid range (rfc8656-s12-r1: 0x4000-0x7FFF)
pub const channel_min: u16 = 0x4000;
pub const channel_max: u16 = 0x7FFF;

/// Maximum PMTU assumption for IPv6 (rfc8656-s3.7-r1: MUST assume 1280)
pub const ipv6_pmtu: u16 = 1280;

// ============================================================================
// Allocate Response
// ============================================================================

/// Parsed Allocate success response fields
pub const AllocateResponse = struct {
    relayed_address: stun.Address,
    mapped_address: stun.Address,
    lifetime: u32,
};

// ============================================================================
// Channel Data Message (RFC 8656 §12.5 — NOT a STUN message)
// ============================================================================

/// ChannelData message: 4-byte header (channel number + length) + data.
/// First 2 bytes = channel number (0x4000-0x7FFF), next 2 bytes = data length.
/// This is NOT a STUN message — it uses a separate framing format.
pub const ChannelMessage = struct {
    channel: u16,
    data: []const u8,

    pub const header_size: usize = 4;

    /// Validate that a channel number is in the valid range (rfc8656-s12-r1)
    pub fn isValidChannel(ch: u16) bool {
        return ch >= channel_min and ch <= channel_max;
    }

    /// Parse a ChannelData message from raw bytes.
    /// Format: [channel:u16be][length:u16be][data:length bytes]
    pub fn parse(buf: []const u8) !ChannelMessage {
        if (buf.len < header_size) return error.MessageTooShort;

        const ch = std.mem.readInt(u16, buf[0..2], .big);
        const length = std.mem.readInt(u16, buf[2..4], .big);

        if (!isValidChannel(ch)) return error.InvalidChannelNumber;
        if (buf.len < header_size + length) return error.MessageTruncated;

        return .{
            .channel = ch,
            .data = buf[header_size..][0..length],
        };
    }

    /// Serialize a ChannelData message into a buffer.
    /// Returns the number of bytes written.
    pub fn serialize(self: *const ChannelMessage, buf: []u8) !usize {
        if (!isValidChannel(self.channel)) return error.InvalidChannelNumber;
        const data_len: u16 = @intCast(self.data.len);
        const total = header_size + self.data.len;
        if (buf.len < total) return error.BufferTooSmall;

        std.mem.writeInt(u16, buf[0..2], self.channel, .big);
        std.mem.writeInt(u16, buf[2..4], data_len, .big);
        @memcpy(buf[header_size..][0..self.data.len], self.data);

        return total;
    }

    /// Serialize with 4-byte padding (rfc8656-s12.5-r2: MUST pad over TCP)
    pub fn serializePadded(self: *const ChannelMessage, buf: []u8) !usize {
        const data_len: u16 = @intCast(self.data.len);
        const padded_len = std.mem.alignForward(usize, self.data.len, 4);
        const total = header_size + padded_len;
        if (!isValidChannel(self.channel)) return error.InvalidChannelNumber;
        if (buf.len < total) return error.BufferTooSmall;

        std.mem.writeInt(u16, buf[0..2], self.channel, .big);
        std.mem.writeInt(u16, buf[2..4], data_len, .big);
        @memcpy(buf[header_size..][0..self.data.len], self.data);
        // Zero padding bytes
        for (self.data.len..padded_len) |i| {
            buf[header_size + i] = 0;
        }

        return total;
    }
};

// ============================================================================
// Attribute Encoding Helpers
// ============================================================================

/// Encode REQUESTED-TRANSPORT attribute value (4 bytes).
/// Byte 0 = protocol number, bytes 1-3 = RFFU (reserved, must be zero).
/// (rfc8656-s7.1-r4: Allocate MUST include REQUESTED-TRANSPORT)
pub fn encodeRequestedTransport(allocator: Allocator, protocol: u8) ![]u8 {
    const buf = try allocator.alloc(u8, 4);
    buf[0] = protocol;
    buf[1] = 0; // RFFU
    buf[2] = 0;
    buf[3] = 0;
    return buf;
}

/// Encode LIFETIME attribute value (4 bytes, big-endian u32 seconds).
pub fn encodeLifetime(allocator: Allocator, seconds: u32) ![]u8 {
    const buf = try allocator.alloc(u8, 4);
    std.mem.writeInt(u32, buf[0..4], seconds, .big);
    return buf;
}

/// Decode LIFETIME attribute value from raw bytes.
pub fn decodeLifetime(value: []const u8) !u32 {
    if (value.len < 4) return error.InvalidAttribute;
    return std.mem.readInt(u32, value[0..4], .big);
}

/// Encode CHANNEL-NUMBER attribute value (4 bytes: u16 channel + 2 bytes RFFU).
pub fn encodeChannelNumber(allocator: Allocator, channel: u16) ![]u8 {
    if (!ChannelMessage.isValidChannel(channel)) return error.InvalidChannelNumber;
    const buf = try allocator.alloc(u8, 4);
    std.mem.writeInt(u16, buf[0..2], channel, .big);
    buf[2] = 0; // RFFU
    buf[3] = 0;
    return buf;
}

/// Decode CHANNEL-NUMBER from raw attribute value.
pub fn decodeChannelNumber(value: []const u8) !u16 {
    if (value.len < 4) return error.InvalidAttribute;
    const ch = std.mem.readInt(u16, value[0..2], .big);
    if (!ChannelMessage.isValidChannel(ch)) return error.InvalidChannelNumber;
    return ch;
}

/// Encode REQUESTED-ADDRESS-FAMILY attribute (4 bytes: u8 family + 3 RFFU).
pub fn encodeRequestedAddressFamily(allocator: Allocator, family: stun.AddressFamily) ![]u8 {
    const buf = try allocator.alloc(u8, 4);
    buf[0] = switch (family) {
        .ipv4 => 0x01,
        .ipv6 => 0x02,
    };
    buf[1] = 0;
    buf[2] = 0;
    buf[3] = 0;
    return buf;
}

// ============================================================================
// TURN Client
// ============================================================================

/// TURN client state machine (RFC 8656 §6-§12).
/// Manages allocation lifecycle, permissions, and channel bindings.
pub const TurnClient = struct {
    allocator: Allocator,
    server_addr: stun.Address,
    relay_addr: ?stun.Address,
    mapped_addr: ?stun.Address,
    lifetime: u32,
    permissions: std.ArrayListUnmanaged(stun.Address),
    channels: std.AutoHashMapUnmanaged(u16, stun.Address),
    allocated: bool,

    /// Initialize a new TURN client targeting the given server.
    pub fn init(allocator: Allocator, server: stun.Address) TurnClient {
        return .{
            .allocator = allocator,
            .server_addr = server,
            .relay_addr = null,
            .mapped_addr = null,
            .lifetime = default_lifetime,
            .permissions = .empty,
            .channels = .empty,
            .allocated = false,
        };
    }

    /// Build an Allocate request message (rfc8656-s7.1-r4: MUST include REQUESTED-TRANSPORT).
    /// Returns the serialized STUN message bytes (caller owns the memory).
    pub fn buildAllocateRequest(self: *TurnClient, transport: u8) ![]u8 {
        var builder = stun.MessageBuilder.init(self.allocator);
        defer builder.deinit();

        builder.setClass(.request);
        builder.setMethod(@enumFromInt(@intFromEnum(TurnMethod.allocate)));
        builder.randomTransactionId();

        // rfc8656-s7.1-r4: MUST include REQUESTED-TRANSPORT
        const rt_val = try encodeRequestedTransport(self.allocator, transport);
        try builder.addAttributeOwned(@enumFromInt(@intFromEnum(TurnAttributeType.requested_transport)), rt_val);

        return builder.build();
    }

    /// Process an Allocate success response: extract relay address, mapped address, lifetime.
    pub fn handleAllocateResponse(self: *TurnClient, msg: *const stun.Message) !AllocateResponse {
        const msg_type = msg.getType();
        if (msg_type.class != .success) return error.NotSuccessResponse;

        // Extract XOR-RELAYED-ADDRESS
        const relay_attr = msg.getAttribute(@enumFromInt(@intFromEnum(TurnAttributeType.xor_relayed_address))) orelse
            return error.MissingRelayAddress;
        const relay_addr = try relay_attr.parseXorMappedAddress(msg.header.transaction_id);

        // Extract XOR-MAPPED-ADDRESS
        const mapped_attr = msg.getAttribute(.xor_mapped_address) orelse
            return error.MissingMappedAddress;
        const mapped_addr = try mapped_attr.parseXorMappedAddress(msg.header.transaction_id);

        // Extract LIFETIME
        const lifetime_attr = msg.getAttribute(@enumFromInt(@intFromEnum(TurnAttributeType.lifetime))) orelse
            return error.MissingLifetime;
        const lifetime_val = try decodeLifetime(lifetime_attr.value);

        self.relay_addr = relay_addr;
        self.mapped_addr = mapped_addr;
        self.lifetime = lifetime_val;
        self.allocated = true;

        return .{
            .relayed_address = relay_addr,
            .mapped_address = mapped_addr,
            .lifetime = lifetime_val,
        };
    }

    /// Build a Refresh request. (rfc8656-s8-r1: MUST refresh before lifetime expires)
    /// Use lifetime=0 to delete the allocation (rfc8656-s8-r2).
    pub fn buildRefreshRequest(self: *TurnClient, lifetime: u32) ![]u8 {
        var builder = stun.MessageBuilder.init(self.allocator);
        defer builder.deinit();

        builder.setClass(.request);
        builder.setMethod(@enumFromInt(@intFromEnum(TurnMethod.refresh)));
        builder.randomTransactionId();

        const lt_val = try encodeLifetime(self.allocator, lifetime);
        try builder.addAttributeOwned(@enumFromInt(@intFromEnum(TurnAttributeType.lifetime)), lt_val);

        return builder.build();
    }

    /// Handle a Refresh success response: update lifetime.
    /// If lifetime was 0, marks allocation as deleted.
    pub fn handleRefreshResponse(self: *TurnClient, msg: *const stun.Message) !void {
        const msg_type = msg.getType();
        if (msg_type.class != .success) return error.NotSuccessResponse;

        const lifetime_attr = msg.getAttribute(@enumFromInt(@intFromEnum(TurnAttributeType.lifetime))) orelse
            return error.MissingLifetime;
        const lifetime_val = try decodeLifetime(lifetime_attr.value);
        self.lifetime = lifetime_val;

        if (lifetime_val == 0) {
            self.allocated = false;
            self.relay_addr = null;
            self.mapped_addr = null;
            self.permissions.clearAndFree(self.allocator);
            self.channels.clearAndFree(self.allocator);
        }
    }

    /// Build a CreatePermission request.
    /// (rfc8656-s10.1-r1: MUST include at least one XOR-PEER-ADDRESS)
    /// (rfc8656-s10.1-r4: address family MUST match relay address)
    pub fn buildCreatePermissionRequest(self: *TurnClient, peer: stun.Address) ![]u8 {
        // rfc8656-s10.1-r4: address family must match relay
        if (self.relay_addr) |relay| {
            if (@intFromEnum(peer.family) != @intFromEnum(relay.family))
                return error.AddressFamilyMismatch;
        }

        var builder = stun.MessageBuilder.init(self.allocator);
        defer builder.deinit();

        builder.setClass(.request);
        builder.setMethod(@enumFromInt(@intFromEnum(TurnMethod.create_permission)));
        builder.randomTransactionId();

        // Encode XOR-PEER-ADDRESS (same format as XOR-MAPPED-ADDRESS)
        const peer_val = try stun.Attribute.encodeXorMappedAddress(
            self.allocator,
            peer,
            builder.transaction_id,
        );
        try builder.addAttributeOwned(
            @enumFromInt(@intFromEnum(TurnAttributeType.xor_peer_address)),
            peer_val,
        );

        return builder.build();
    }

    /// Record a permission after successful CreatePermission response.
    pub fn addPermission(self: *TurnClient, peer: stun.Address) !void {
        try self.permissions.append(self.allocator, peer);
    }

    /// Build a ChannelBind request.
    /// (rfc8656-s12-r1: channel MUST be 0x4000-0x7FFF)
    /// (rfc8656-s12.1-r1: XOR-PEER-ADDRESS MUST match relay address family)
    pub fn buildChannelBindRequest(self: *TurnClient, channel: u16, peer: stun.Address) ![]u8 {
        if (!ChannelMessage.isValidChannel(channel)) return error.InvalidChannelNumber;

        // rfc8656-s12.1-r1: address family must match relay
        if (self.relay_addr) |relay| {
            if (@intFromEnum(peer.family) != @intFromEnum(relay.family))
                return error.AddressFamilyMismatch;
        }

        var builder = stun.MessageBuilder.init(self.allocator);
        defer builder.deinit();

        builder.setClass(.request);
        builder.setMethod(@enumFromInt(@intFromEnum(TurnMethod.channel_bind)));
        builder.randomTransactionId();

        // CHANNEL-NUMBER attribute
        const ch_val = try encodeChannelNumber(self.allocator, channel);
        try builder.addAttributeOwned(@enumFromInt(@intFromEnum(TurnAttributeType.channel_number)), ch_val);

        // XOR-PEER-ADDRESS attribute
        const peer_val = try stun.Attribute.encodeXorMappedAddress(
            self.allocator,
            peer,
            builder.transaction_id,
        );
        try builder.addAttributeOwned(
            @enumFromInt(@intFromEnum(TurnAttributeType.xor_peer_address)),
            peer_val,
        );

        return builder.build();
    }

    /// Record a channel binding after successful ChannelBind response.
    pub fn addChannelBinding(self: *TurnClient, channel: u16, peer: stun.Address) !void {
        try self.channels.put(self.allocator, channel, peer);
    }

    /// Build a Send indication (rfc8656-s11.1-r2: MUST include XOR-PEER-ADDRESS and DATA).
    pub fn buildSendIndication(self: *TurnClient, peer: stun.Address, data: []const u8) ![]u8 {
        var builder = stun.MessageBuilder.init(self.allocator);
        defer builder.deinit();

        builder.setClass(.indication);
        builder.setMethod(@enumFromInt(@intFromEnum(TurnMethod.send)));
        builder.randomTransactionId();

        // XOR-PEER-ADDRESS
        const peer_val = try stun.Attribute.encodeXorMappedAddress(
            self.allocator,
            peer,
            builder.transaction_id,
        );
        try builder.addAttributeOwned(
            @enumFromInt(@intFromEnum(TurnAttributeType.xor_peer_address)),
            peer_val,
        );

        // DATA attribute (raw payload)
        try builder.addAttribute(@enumFromInt(@intFromEnum(TurnAttributeType.data)), data);

        return builder.build();
    }

    /// Parse a Data indication received from the server.
    /// Returns the peer address and data payload.
    pub fn parseDataIndication(_: *TurnClient, msg: *const stun.Message) !struct { peer: stun.Address, data: []const u8 } {
        const msg_type = msg.getType();
        if (msg_type.class != .indication) return error.NotIndication;

        // Extract XOR-PEER-ADDRESS
        const peer_attr = msg.getAttribute(@enumFromInt(@intFromEnum(TurnAttributeType.xor_peer_address))) orelse
            return error.MissingPeerAddress;
        const peer_addr = try peer_attr.parseXorMappedAddress(msg.header.transaction_id);

        // Extract DATA
        const data_attr = msg.getAttribute(@enumFromInt(@intFromEnum(TurnAttributeType.data))) orelse
            return error.MissingData;

        return .{ .peer = peer_addr, .data = data_attr.value };
    }

    pub fn deinit(self: *TurnClient) void {
        self.permissions.deinit(self.allocator);
        self.channels.deinit(self.allocator);
    }
};

// ============================================================================
// Tests — RFC 8656 rule compliance
// ============================================================================

const testing = std.testing;

// --- ChannelMessage tests ---

// rfc8656-s12-r1: channel numbers MUST be in range 0x4000-0x7FFF
test "channel number validation - valid range" {
    try testing.expect(ChannelMessage.isValidChannel(0x4000));
    try testing.expect(ChannelMessage.isValidChannel(0x5000));
    try testing.expect(ChannelMessage.isValidChannel(0x7FFF));
}

test "channel number validation - invalid range" {
    try testing.expect(!ChannelMessage.isValidChannel(0x0000));
    try testing.expect(!ChannelMessage.isValidChannel(0x3FFF));
    try testing.expect(!ChannelMessage.isValidChannel(0x8000));
    try testing.expect(!ChannelMessage.isValidChannel(0xFFFF));
}

// ChannelData parse/serialize round-trip
test "channel data message round-trip" {
    const payload = "hello TURN";
    const msg = ChannelMessage{ .channel = 0x4001, .data = payload };

    var buf: [64]u8 = undefined;
    const written = try msg.serialize(&buf);
    try testing.expectEqual(@as(usize, 4 + payload.len), written);

    // First 2 bytes: channel number
    try testing.expectEqual(@as(u16, 0x4001), std.mem.readInt(u16, buf[0..2], .big));
    // Next 2 bytes: data length
    try testing.expectEqual(@as(u16, @intCast(payload.len)), std.mem.readInt(u16, buf[2..4], .big));

    // Parse it back
    const parsed = try ChannelMessage.parse(buf[0..written]);
    try testing.expectEqual(@as(u16, 0x4001), parsed.channel);
    try testing.expectEqualSlices(u8, payload, parsed.data);
}

test "channel data parse rejects invalid channel" {
    var buf: [8]u8 = undefined;
    std.mem.writeInt(u16, buf[0..2], 0x3FFF, .big); // below valid range
    std.mem.writeInt(u16, buf[2..4], 2, .big);
    buf[4] = 0xAB;
    buf[5] = 0xCD;

    const result = ChannelMessage.parse(&buf);
    try testing.expectError(error.InvalidChannelNumber, result);
}

test "channel data parse rejects truncated message" {
    var buf: [6]u8 = undefined;
    std.mem.writeInt(u16, buf[0..2], 0x4000, .big);
    std.mem.writeInt(u16, buf[2..4], 10, .big); // claims 10 bytes but only 2 available
    buf[4] = 0;
    buf[5] = 0;

    const result = ChannelMessage.parse(&buf);
    try testing.expectError(error.MessageTruncated, result);
}

// rfc8656-s12.5-r2: ChannelData over TCP MUST be padded to 4-byte boundary
test "channel data padded serialization" {
    const payload = "abc"; // 3 bytes → padded to 4
    const msg = ChannelMessage{ .channel = 0x4000, .data = payload };

    var buf: [64]u8 = undefined;
    const written = try msg.serializePadded(&buf);
    try testing.expectEqual(@as(usize, 8), written); // 4 header + 4 padded data

    // Length field still says 3
    try testing.expectEqual(@as(u16, 3), std.mem.readInt(u16, buf[2..4], .big));
    // Padding byte is zero
    try testing.expectEqual(@as(u8, 0), buf[7]);
}

// --- Attribute encoding tests ---

// rfc8656-s7.1-r4: Allocate MUST include REQUESTED-TRANSPORT
test "encode requested transport - UDP" {
    const val = try encodeRequestedTransport(testing.allocator, Transport.udp);
    defer testing.allocator.free(val);

    try testing.expectEqual(@as(usize, 4), val.len);
    try testing.expectEqual(Transport.udp, val[0]);
    try testing.expectEqual(@as(u8, 0), val[1]); // RFFU
    try testing.expectEqual(@as(u8, 0), val[2]);
    try testing.expectEqual(@as(u8, 0), val[3]);
}

test "encode and decode lifetime" {
    const val = try encodeLifetime(testing.allocator, 600);
    defer testing.allocator.free(val);

    const decoded = try decodeLifetime(val);
    try testing.expectEqual(@as(u32, 600), decoded);
}

// Refresh with lifetime 0 MUST delete the allocation (rfc8656-s8-r2)
test "encode lifetime zero for deletion" {
    const val = try encodeLifetime(testing.allocator, 0);
    defer testing.allocator.free(val);

    const decoded = try decodeLifetime(val);
    try testing.expectEqual(@as(u32, 0), decoded);
}

test "encode and decode channel number" {
    const val = try encodeChannelNumber(testing.allocator, 0x4001);
    defer testing.allocator.free(val);

    try testing.expectEqual(@as(usize, 4), val.len);
    const decoded = try decodeChannelNumber(val);
    try testing.expectEqual(@as(u16, 0x4001), decoded);
}

test "encode channel number rejects invalid" {
    const result = encodeChannelNumber(testing.allocator, 0x3FFF);
    try testing.expectError(error.InvalidChannelNumber, result);
}

// --- TurnClient message building tests ---

// rfc8656-s7.1-r4: Allocate request MUST include REQUESTED-TRANSPORT
test "allocate request includes REQUESTED-TRANSPORT" {
    const server = stun.Address{
        .family = .ipv4,
        .port = 3478,
        .addr = .{ .ipv4 = .{ 192, 168, 1, 1 } },
    };

    var client = TurnClient.init(testing.allocator, server);
    defer client.deinit();

    const msg_bytes = try client.buildAllocateRequest(Transport.udp);
    defer testing.allocator.free(msg_bytes);

    // Parse the built message
    const msg = try stun.Message.parse(testing.allocator, msg_bytes);
    defer msg.deinit();

    // Verify it's an Allocate Request
    const mt = msg.getType();
    try testing.expectEqual(stun.Class.request, mt.class);
    try testing.expectEqual(@as(u12, @intFromEnum(TurnMethod.allocate)), @intFromEnum(mt.method));

    // Verify REQUESTED-TRANSPORT attribute is present
    const rt_attr = msg.getAttribute(@enumFromInt(@intFromEnum(TurnAttributeType.requested_transport)));
    try testing.expect(rt_attr != null);
    try testing.expectEqual(Transport.udp, rt_attr.?.value[0]);
}

// rfc8656-s8-r1: Refresh request with lifetime
test "refresh request includes LIFETIME" {
    const server = stun.Address{
        .family = .ipv4,
        .port = 3478,
        .addr = .{ .ipv4 = .{ 10, 0, 0, 1 } },
    };

    var client = TurnClient.init(testing.allocator, server);
    defer client.deinit();

    const msg_bytes = try client.buildRefreshRequest(600);
    defer testing.allocator.free(msg_bytes);

    const msg = try stun.Message.parse(testing.allocator, msg_bytes);
    defer msg.deinit();

    const mt = msg.getType();
    try testing.expectEqual(stun.Class.request, mt.class);
    try testing.expectEqual(@as(u12, @intFromEnum(TurnMethod.refresh)), @intFromEnum(mt.method));

    const lt_attr = msg.getAttribute(@enumFromInt(@intFromEnum(TurnAttributeType.lifetime)));
    try testing.expect(lt_attr != null);
    const lt_val = try decodeLifetime(lt_attr.?.value);
    try testing.expectEqual(@as(u32, 600), lt_val);
}

// rfc8656-s8-r2: Refresh with 0 lifetime deletes allocation
test "refresh with zero lifetime for deletion" {
    const server = stun.Address{
        .family = .ipv4,
        .port = 3478,
        .addr = .{ .ipv4 = .{ 10, 0, 0, 1 } },
    };

    var client = TurnClient.init(testing.allocator, server);
    defer client.deinit();

    const msg_bytes = try client.buildRefreshRequest(0);
    defer testing.allocator.free(msg_bytes);

    const msg = try stun.Message.parse(testing.allocator, msg_bytes);
    defer msg.deinit();

    const lt_attr = msg.getAttribute(@enumFromInt(@intFromEnum(TurnAttributeType.lifetime)));
    try testing.expect(lt_attr != null);
    const lt_val = try decodeLifetime(lt_attr.?.value);
    try testing.expectEqual(@as(u32, 0), lt_val);
}

// rfc8656-s10.1-r1: CreatePermission MUST include XOR-PEER-ADDRESS
test "create permission request includes XOR-PEER-ADDRESS" {
    const server = stun.Address{
        .family = .ipv4,
        .port = 3478,
        .addr = .{ .ipv4 = .{ 10, 0, 0, 1 } },
    };
    const peer = stun.Address{
        .family = .ipv4,
        .port = 9000,
        .addr = .{ .ipv4 = .{ 192, 168, 1, 100 } },
    };

    var client = TurnClient.init(testing.allocator, server);
    defer client.deinit();
    // Set relay to match address family
    client.relay_addr = stun.Address{
        .family = .ipv4,
        .port = 50000,
        .addr = .{ .ipv4 = .{ 203, 0, 113, 1 } },
    };

    const msg_bytes = try client.buildCreatePermissionRequest(peer);
    defer testing.allocator.free(msg_bytes);

    const msg = try stun.Message.parse(testing.allocator, msg_bytes);
    defer msg.deinit();

    const mt = msg.getType();
    try testing.expectEqual(stun.Class.request, mt.class);
    try testing.expectEqual(@as(u12, @intFromEnum(TurnMethod.create_permission)), @intFromEnum(mt.method));

    // Verify XOR-PEER-ADDRESS is present
    const pa = msg.getAttribute(@enumFromInt(@intFromEnum(TurnAttributeType.xor_peer_address)));
    try testing.expect(pa != null);
}

// rfc8656-s10.1-r4: CreatePermission addresses MUST match allocation address family
test "create permission rejects mismatched address family" {
    const server = stun.Address{
        .family = .ipv4,
        .port = 3478,
        .addr = .{ .ipv4 = .{ 10, 0, 0, 1 } },
    };
    const ipv6_peer = stun.Address{
        .family = .ipv6,
        .port = 9000,
        .addr = .{ .ipv6 = .{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } },
    };

    var client = TurnClient.init(testing.allocator, server);
    defer client.deinit();
    client.relay_addr = stun.Address{
        .family = .ipv4,
        .port = 50000,
        .addr = .{ .ipv4 = .{ 203, 0, 113, 1 } },
    };

    const result = client.buildCreatePermissionRequest(ipv6_peer);
    try testing.expectError(error.AddressFamilyMismatch, result);
}

// rfc8656-s12-r1: ChannelBind with valid channel and matching address family
test "channel bind request" {
    const server = stun.Address{
        .family = .ipv4,
        .port = 3478,
        .addr = .{ .ipv4 = .{ 10, 0, 0, 1 } },
    };
    const peer = stun.Address{
        .family = .ipv4,
        .port = 9000,
        .addr = .{ .ipv4 = .{ 192, 168, 1, 100 } },
    };

    var client = TurnClient.init(testing.allocator, server);
    defer client.deinit();
    client.relay_addr = stun.Address{
        .family = .ipv4,
        .port = 50000,
        .addr = .{ .ipv4 = .{ 203, 0, 113, 1 } },
    };

    const msg_bytes = try client.buildChannelBindRequest(0x4001, peer);
    defer testing.allocator.free(msg_bytes);

    const msg = try stun.Message.parse(testing.allocator, msg_bytes);
    defer msg.deinit();

    const mt = msg.getType();
    try testing.expectEqual(stun.Class.request, mt.class);
    try testing.expectEqual(@as(u12, @intFromEnum(TurnMethod.channel_bind)), @intFromEnum(mt.method));

    // Verify CHANNEL-NUMBER attribute
    const ch_attr = msg.getAttribute(@enumFromInt(@intFromEnum(TurnAttributeType.channel_number)));
    try testing.expect(ch_attr != null);
    const ch_val = try decodeChannelNumber(ch_attr.?.value);
    try testing.expectEqual(@as(u16, 0x4001), ch_val);
}

test "channel bind rejects invalid channel number" {
    const server = stun.Address{
        .family = .ipv4,
        .port = 3478,
        .addr = .{ .ipv4 = .{ 10, 0, 0, 1 } },
    };
    const peer = stun.Address{
        .family = .ipv4,
        .port = 9000,
        .addr = .{ .ipv4 = .{ 192, 168, 1, 100 } },
    };

    var client = TurnClient.init(testing.allocator, server);
    defer client.deinit();

    const result = client.buildChannelBindRequest(0x3FFF, peer);
    try testing.expectError(error.InvalidChannelNumber, result);
}

// rfc8656-s11.1-r2: Send indication MUST include XOR-PEER-ADDRESS and DATA
test "send indication includes required attributes" {
    const server = stun.Address{
        .family = .ipv4,
        .port = 3478,
        .addr = .{ .ipv4 = .{ 10, 0, 0, 1 } },
    };
    const peer = stun.Address{
        .family = .ipv4,
        .port = 9000,
        .addr = .{ .ipv4 = .{ 192, 168, 1, 100 } },
    };

    var client = TurnClient.init(testing.allocator, server);
    defer client.deinit();

    const payload = "test data";
    const msg_bytes = try client.buildSendIndication(peer, payload);
    defer testing.allocator.free(msg_bytes);

    const msg = try stun.Message.parse(testing.allocator, msg_bytes);
    defer msg.deinit();

    const mt = msg.getType();
    try testing.expectEqual(stun.Class.indication, mt.class);
    try testing.expectEqual(@as(u12, @intFromEnum(TurnMethod.send)), @intFromEnum(mt.method));

    // Verify XOR-PEER-ADDRESS
    const pa = msg.getAttribute(@enumFromInt(@intFromEnum(TurnAttributeType.xor_peer_address)));
    try testing.expect(pa != null);

    // Verify DATA
    const da = msg.getAttribute(@enumFromInt(@intFromEnum(TurnAttributeType.data)));
    try testing.expect(da != null);
    try testing.expectEqualSlices(u8, payload, da.?.value);
}

// rfc8656-s9-r1: Permission Lifetime MUST be 300 seconds
test "permission lifetime constant is 300" {
    try testing.expectEqual(@as(u32, 300), permission_lifetime);
}

// rfc8656-s3.7-r1: PMTU MUST be 1280 for IPv6
test "ipv6 pmtu constant is 1280" {
    try testing.expectEqual(@as(u16, 1280), ipv6_pmtu);
}

// --- TurnClient state management tests ---

test "client tracks permissions" {
    const server = stun.Address{
        .family = .ipv4,
        .port = 3478,
        .addr = .{ .ipv4 = .{ 10, 0, 0, 1 } },
    };

    var client = TurnClient.init(testing.allocator, server);
    defer client.deinit();

    const peer1 = stun.Address{ .family = .ipv4, .port = 9000, .addr = .{ .ipv4 = .{ 1, 2, 3, 4 } } };
    const peer2 = stun.Address{ .family = .ipv4, .port = 9001, .addr = .{ .ipv4 = .{ 5, 6, 7, 8 } } };

    try client.addPermission(peer1);
    try client.addPermission(peer2);
    try testing.expectEqual(@as(usize, 2), client.permissions.items.len);
}

test "client tracks channel bindings" {
    const server = stun.Address{
        .family = .ipv4,
        .port = 3478,
        .addr = .{ .ipv4 = .{ 10, 0, 0, 1 } },
    };

    var client = TurnClient.init(testing.allocator, server);
    defer client.deinit();

    const peer = stun.Address{ .family = .ipv4, .port = 9000, .addr = .{ .ipv4 = .{ 1, 2, 3, 4 } } };
    try client.addChannelBinding(0x4001, peer);

    const found = client.channels.get(0x4001);
    try testing.expect(found != null);
    try testing.expectEqual(@as(u16, 9000), found.?.port);
}

// --- TURN method encoding tests ---

test "TURN methods encode correctly as STUN message types" {
    // Allocate Request
    const alloc_req = stun.MessageType{
        .class = .request,
        .method = @enumFromInt(@intFromEnum(TurnMethod.allocate)),
    };
    try testing.expectEqual(@as(u16, 0x0003), alloc_req.encode());

    // Allocate Success Response
    const alloc_resp = stun.MessageType{
        .class = .success,
        .method = @enumFromInt(@intFromEnum(TurnMethod.allocate)),
    };
    try testing.expectEqual(@as(u16, 0x0103), alloc_resp.encode());

    // Refresh Request
    const refresh_req = stun.MessageType{
        .class = .request,
        .method = @enumFromInt(@intFromEnum(TurnMethod.refresh)),
    };
    try testing.expectEqual(@as(u16, 0x0004), refresh_req.encode());

    // Send Indication
    const send_ind = stun.MessageType{
        .class = .indication,
        .method = @enumFromInt(@intFromEnum(TurnMethod.send)),
    };
    try testing.expectEqual(@as(u16, 0x0016), send_ind.encode());

    // Data Indication
    const data_ind = stun.MessageType{
        .class = .indication,
        .method = @enumFromInt(@intFromEnum(TurnMethod.data)),
    };
    try testing.expectEqual(@as(u16, 0x0017), data_ind.encode());

    // CreatePermission Request
    const perm_req = stun.MessageType{
        .class = .request,
        .method = @enumFromInt(@intFromEnum(TurnMethod.create_permission)),
    };
    try testing.expectEqual(@as(u16, 0x0008), perm_req.encode());

    // ChannelBind Request
    const cb_req = stun.MessageType{
        .class = .request,
        .method = @enumFromInt(@intFromEnum(TurnMethod.channel_bind)),
    };
    try testing.expectEqual(@as(u16, 0x0009), cb_req.encode());
}
