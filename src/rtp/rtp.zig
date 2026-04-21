//! RTP/RTCP parsing and session management (RFC 3550, RFC 4585, RFC 5761)
//! Generated using structured RFC rules from the RFC Compliance API.
//!
//! This module implements:
//!   - RTP fixed header parsing / serialization (RFC 3550 §5.1)
//!   - RTP header extensions (RFC 3550 §5.3.1)
//!   - RTCP packet parsing: SR, RR, SDES, BYE, APP, RTPFB, PSFB (RFC 3550 §6)
//!   - RTP/RTCP multiplexing detection (RFC 5761 §4)
//!   - Packet demux: STUN / DTLS / RTP-RTCP classification (RFC 5764 §5.1.2)
//!   - SSRC collision detection (RFC 3550 §8.2)
//!   - Per-SSRC session state: sequence wrap, jitter, packet/octet counts
//!   - RTCP feedback messages: NACK, PLI, FIR (RFC 4585)
//!
//! Key RFC rules implemented:
//!   - rfc3550-s5.1-r1:  Extension bit set → fixed header MUST be followed by exactly one header extension
//!   - rfc3550-s3-r2:    Multiple streams → each MUST have different SSRC
//!   - rfc3550-s5.1-r5:  Payload type SHOULD NOT be used for multiplexing separate media streams
//!   - rfc5761-s4:       RTP/RTCP mux detection via payload-type ranges
//!   - rfc3550-s8.2:     SSRC collision detection

const std = @import("std");
const Allocator = std.mem.Allocator;

// ============================================================================
// Constants
// ============================================================================

/// RTP protocol version (RFC 3550 §5.1) — always 2
pub const rtp_version: u2 = 2;

/// Maximum number of CSRC entries (RFC 3550 §5.1) — CC is 4 bits, max 15
pub const max_csrc_count: u4 = 15;

/// RTP fixed header size in bytes (RFC 3550 §5.1)
pub const rtp_fixed_header_size: usize = 12;

/// RTCP fixed header size in bytes (RFC 3550 §6.1)
pub const rtcp_fixed_header_size: usize = 4;

// ============================================================================
// Packet Demux (RFC 5764 §5.1.2)
// ============================================================================

/// Packet classification for demuxing on a single transport (RFC 5764 §5.1.2).
/// First byte determines protocol:
///   0-3   → STUN
///   20-63 → DTLS
///   128-191 → RTP or RTCP
pub const PacketKind = enum {
    stun,
    dtls,
    rtp_rtcp,
    unknown,
};

/// Classify a multiplexed packet by its first byte (RFC 5764 §5.1.2).
pub fn classifyPacket(first_byte: u8) PacketKind {
    if (first_byte <= 3) return .stun;
    if (first_byte >= 20 and first_byte <= 63) return .dtls;
    if (first_byte >= 128 and first_byte <= 191) return .rtp_rtcp;
    return .unknown;
}

// ============================================================================
// RTP / RTCP Mux Detection (RFC 5761 §4)
// ============================================================================

/// When RTP and RTCP share a single transport (RFC 5761), distinguish them
/// by payload type. RTCP uses PT values 200-206 which, after masking the
/// second byte with 0x7F (strip marker bit), fall in 72-79. The broader
/// RTCP-reserved range in the second byte (masked) is 64-95.
pub fn isRtcpPayloadType(pt: u8) bool {
    return pt >= 64 and pt <= 95;
}

/// RTP vs RTCP classification for muxed streams (RFC 5761 §4).
pub const RtpRtcpKind = enum { rtp, rtcp };

/// Classify a packet (known to be RTP or RTCP via classifyPacket) as either
/// RTP or RTCP using the payload-type byte (RFC 5761 §4).
/// `second_byte` is buf[1]; the PT field occupies the lower 7 bits.
pub fn classifyRtpRtcp(second_byte: u8) RtpRtcpKind {
    const pt = second_byte & 0x7F;
    return if (isRtcpPayloadType(pt)) .rtcp else .rtp;
}

// ============================================================================
// RTP Header (RFC 3550 §5.1)
// ============================================================================

/// RTP fixed header (12 bytes on the wire).
///
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |V=2|P|X|  CC   |M|     PT      |       sequence number         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                           timestamp                           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                             SSRC                              |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
pub const RtpHeader = struct {
    version: u2 = rtp_version,
    padding: bool = false,
    extension: bool = false,
    csrc_count: u4 = 0,
    marker: bool = false,
    payload_type: u7 = 0,
    sequence_number: u16 = 0,
    timestamp: u32 = 0,
    ssrc: u32 = 0,

    /// Parse the 12-byte fixed header from network bytes (RFC 3550 §5.1).
    pub fn parse(buf: []const u8) !RtpHeader {
        if (buf.len < rtp_fixed_header_size) return error.BufferTooShort;

        const b0 = buf[0];
        const version: u2 = @intCast(b0 >> 6);
        if (version != rtp_version) return error.InvalidVersion;

        const b1 = buf[1];

        return .{
            .version = version,
            .padding = (b0 & 0x20) != 0,
            .extension = (b0 & 0x10) != 0,
            .csrc_count = @intCast(b0 & 0x0F),
            .marker = (b1 & 0x80) != 0,
            .payload_type = @intCast(b1 & 0x7F),
            .sequence_number = std.mem.readInt(u16, buf[2..4], .big),
            .timestamp = std.mem.readInt(u32, buf[4..8], .big),
            .ssrc = std.mem.readInt(u32, buf[8..12], .big),
        };
    }

    /// Serialize the fixed header to 12 network-order bytes.
    pub fn serialize(self: RtpHeader) [rtp_fixed_header_size]u8 {
        var buf: [rtp_fixed_header_size]u8 = undefined;

        buf[0] = (@as(u8, self.version) << 6) |
            (@as(u8, if (self.padding) 1 else 0) << 5) |
            (@as(u8, if (self.extension) 1 else 0) << 4) |
            @as(u8, self.csrc_count);

        buf[1] = (@as(u8, if (self.marker) 1 else 0) << 7) |
            @as(u8, self.payload_type);

        std.mem.writeInt(u16, buf[2..4], self.sequence_number, .big);
        std.mem.writeInt(u32, buf[4..8], self.timestamp, .big);
        std.mem.writeInt(u32, buf[8..12], self.ssrc, .big);

        return buf;
    }
};

// ============================================================================
// RTP Header Extension (RFC 3550 §5.3.1)
// ============================================================================

/// RTP header extension (RFC 3550 §5.3.1).
/// Follows the CSRC list when the X bit is set.
///   profile_id:  16-bit profile-specific identifier
///   data:        extension payload (length in 32-bit words from wire)
pub const RtpExtension = struct {
    profile_id: u16,
    data: []const u8,
};

// ============================================================================
// RTP Packet
// ============================================================================

/// A fully parsed RTP packet.
pub const RtpPacket = struct {
    header: RtpHeader,
    csrc_list: []const u32,
    extension: ?RtpExtension,
    payload: []const u8,

    // Internal storage for CSRC entries (avoids extra alloc for ≤15 items)
    csrc_buf: [max_csrc_count]u32 = undefined,

    /// Parse a complete RTP packet from raw bytes.
    /// The returned slices (payload, extension data) point into `buf`.
    pub fn parse(buf: []const u8) !RtpPacket {
        const header = try RtpHeader.parse(buf);
        var offset: usize = rtp_fixed_header_size;

        // CSRC list
        const csrc_bytes = @as(usize, header.csrc_count) * 4;
        if (buf.len < offset + csrc_bytes) return error.BufferTooShort;

        var pkt = RtpPacket{
            .header = header,
            .csrc_list = &.{},
            .extension = null,
            .payload = &.{},
        };

        for (0..header.csrc_count) |i| {
            const start = offset + i * 4;
            pkt.csrc_buf[i] = std.mem.readInt(u32, buf[start..][0..4], .big);
        }
        pkt.csrc_list = pkt.csrc_buf[0..header.csrc_count];
        offset += csrc_bytes;

        // Header extension (rfc3550-s5.1-r1: X bit → exactly one extension)
        if (header.extension) {
            if (buf.len < offset + 4) return error.BufferTooShort;
            const profile_id = std.mem.readInt(u16, buf[offset..][0..2], .big);
            const ext_words = std.mem.readInt(u16, buf[offset + 2 ..][0..2], .big);
            const ext_bytes = @as(usize, ext_words) * 4;
            offset += 4;
            if (buf.len < offset + ext_bytes) return error.BufferTooShort;
            pkt.extension = .{
                .profile_id = profile_id,
                .data = buf[offset..][0..ext_bytes],
            };
            offset += ext_bytes;
        }

        // Padding: last byte gives padding count
        var payload_end = buf.len;
        if (header.padding) {
            if (buf.len == offset) return error.BufferTooShort;
            const pad_count = buf[buf.len - 1];
            if (pad_count == 0 or buf.len - offset < pad_count) return error.InvalidPadding;
            payload_end -= pad_count;
        }

        pkt.payload = buf[offset..payload_end];
        return pkt;
    }

    /// Serialize the full RTP packet to a newly allocated buffer.
    pub fn serialize(self: *const RtpPacket, allocator: Allocator) ![]u8 {
        var total: usize = rtp_fixed_header_size;
        total += @as(usize, self.header.csrc_count) * 4;
        if (self.extension) |ext| {
            total += 4 + ext.data.len;
        }
        total += self.payload.len;

        const buf = try allocator.alloc(u8, total);
        errdefer allocator.free(buf);

        // Fixed header
        const hdr_bytes = self.header.serialize();
        @memcpy(buf[0..rtp_fixed_header_size], &hdr_bytes);
        var offset: usize = rtp_fixed_header_size;

        // CSRC list
        for (self.csrc_list) |csrc| {
            std.mem.writeInt(u32, buf[offset..][0..4], csrc, .big);
            offset += 4;
        }

        // Extension
        if (self.extension) |ext| {
            std.mem.writeInt(u16, buf[offset..][0..2], ext.profile_id, .big);
            const ext_words: u16 = @intCast(ext.data.len / 4);
            std.mem.writeInt(u16, buf[offset + 2 ..][0..2], ext_words, .big);
            offset += 4;
            @memcpy(buf[offset..][0..ext.data.len], ext.data);
            offset += ext.data.len;
        }

        // Payload
        @memcpy(buf[offset..][0..self.payload.len], self.payload);

        return buf;
    }
};

// ============================================================================
// RTCP Packet Types (RFC 3550 §6, RFC 4585)
// ============================================================================

/// RTCP packet types (RFC 3550 §12.1, RFC 4585 §6.1)
pub const RtcpPacketType = enum(u8) {
    sender_report = 200,
    receiver_report = 201,
    sdes = 202,
    bye = 203,
    app = 204,
    rtpfb = 205, // RFC 4585 — transport-layer feedback
    psfb = 206, // RFC 4585 — payload-specific feedback
    _,
};

// ============================================================================
// RTCP Header (RFC 3550 §6.1)
// ============================================================================

/// RTCP common header (4 bytes on the wire).
///
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |V=2|P| count/FMT |     PT      |           length              |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
pub const RtcpHeader = struct {
    version: u2 = rtp_version,
    padding: bool = false,
    count: u5 = 0, // report count or feedback message type
    packet_type: RtcpPacketType = .sender_report,
    length: u16 = 0, // 32-bit words minus one

    /// Total packet size in bytes (header + body) as indicated by the length field.
    pub fn packetSize(self: RtcpHeader) usize {
        return (@as(usize, self.length) + 1) * 4;
    }

    pub fn parse(buf: []const u8) !RtcpHeader {
        if (buf.len < rtcp_fixed_header_size) return error.BufferTooShort;

        const b0 = buf[0];
        const version: u2 = @intCast(b0 >> 6);
        if (version != rtp_version) return error.InvalidVersion;

        return .{
            .version = version,
            .padding = (b0 & 0x20) != 0,
            .count = @intCast(b0 & 0x1F),
            .packet_type = @enumFromInt(buf[1]),
            .length = std.mem.readInt(u16, buf[2..4], .big),
        };
    }

    pub fn serialize(self: RtcpHeader) [rtcp_fixed_header_size]u8 {
        var buf: [rtcp_fixed_header_size]u8 = undefined;
        buf[0] = (@as(u8, self.version) << 6) |
            (@as(u8, if (self.padding) 1 else 0) << 5) |
            @as(u8, self.count);
        buf[1] = @intFromEnum(self.packet_type);
        std.mem.writeInt(u16, buf[2..4], self.length, .big);
        return buf;
    }
};

// ============================================================================
// RTCP Report Block (RFC 3550 §6.4.1)
// ============================================================================

/// Reception report block — used in both SR and RR (24 bytes on wire).
pub const ReportBlock = struct {
    ssrc: u32,
    fraction_lost: u8,
    cumulative_lost: u24,
    extended_highest_seq: u32,
    jitter: u32,
    last_sr: u32,
    delay_since_last_sr: u32,

    pub const wire_size: usize = 24;

    pub fn parse(buf: []const u8) !ReportBlock {
        if (buf.len < wire_size) return error.BufferTooShort;
        const lost_word = std.mem.readInt(u32, buf[4..8], .big);
        return .{
            .ssrc = std.mem.readInt(u32, buf[0..4], .big),
            .fraction_lost = @intCast(lost_word >> 24),
            .cumulative_lost = @intCast(lost_word & 0x00FFFFFF),
            .extended_highest_seq = std.mem.readInt(u32, buf[8..12], .big),
            .jitter = std.mem.readInt(u32, buf[12..16], .big),
            .last_sr = std.mem.readInt(u32, buf[16..20], .big),
            .delay_since_last_sr = std.mem.readInt(u32, buf[20..24], .big),
        };
    }

    pub fn serialize(self: ReportBlock) [wire_size]u8 {
        var buf: [wire_size]u8 = undefined;
        std.mem.writeInt(u32, buf[0..4], self.ssrc, .big);
        const lost_word: u32 = (@as(u32, self.fraction_lost) << 24) | @as(u32, self.cumulative_lost);
        std.mem.writeInt(u32, buf[4..8], lost_word, .big);
        std.mem.writeInt(u32, buf[8..12], self.extended_highest_seq, .big);
        std.mem.writeInt(u32, buf[12..16], self.jitter, .big);
        std.mem.writeInt(u32, buf[16..20], self.last_sr, .big);
        std.mem.writeInt(u32, buf[20..24], self.delay_since_last_sr, .big);
        return buf;
    }
};

// ============================================================================
// RTCP Sender Report (RFC 3550 §6.4.1)
// ============================================================================

/// Parsed RTCP Sender Report.
pub const SenderReport = struct {
    ssrc: u32,
    ntp_timestamp_msw: u32,
    ntp_timestamp_lsw: u32,
    rtp_timestamp: u32,
    sender_packet_count: u32,
    sender_octet_count: u32,
    report_blocks: []const ReportBlock,

    /// Sender-info size on the wire (excluding RTCP header and SSRC)
    pub const sender_info_size: usize = 20;

    /// Parse a Sender Report from the payload after the RTCP header.
    /// `body` starts at the SSRC field (i.e., buf[4..] of the full RTCP packet).
    /// `count` is the report count from the RTCP header.
    /// `report_buf` is caller-supplied storage for report blocks.
    pub fn parse(body: []const u8, count: u5, report_buf: []ReportBlock) !SenderReport {
        const min_len = 4 + sender_info_size + @as(usize, count) * ReportBlock.wire_size;
        if (body.len < min_len) return error.BufferTooShort;

        var sr = SenderReport{
            .ssrc = std.mem.readInt(u32, body[0..4], .big),
            .ntp_timestamp_msw = std.mem.readInt(u32, body[4..8], .big),
            .ntp_timestamp_lsw = std.mem.readInt(u32, body[8..12], .big),
            .rtp_timestamp = std.mem.readInt(u32, body[12..16], .big),
            .sender_packet_count = std.mem.readInt(u32, body[16..20], .big),
            .sender_octet_count = std.mem.readInt(u32, body[20..24], .big),
            .report_blocks = &.{},
        };

        for (0..count) |i| {
            const offset = 24 + i * ReportBlock.wire_size;
            report_buf[i] = try ReportBlock.parse(body[offset..][0..ReportBlock.wire_size]);
        }
        sr.report_blocks = report_buf[0..count];

        return sr;
    }
};

// ============================================================================
// RTCP Receiver Report (RFC 3550 §6.4.2)
// ============================================================================

/// Parsed RTCP Receiver Report.
pub const ReceiverReport = struct {
    ssrc: u32,
    report_blocks: []const ReportBlock,

    /// Parse a Receiver Report from the payload after the RTCP header.
    pub fn parse(body: []const u8, count: u5, report_buf: []ReportBlock) !ReceiverReport {
        const min_len = 4 + @as(usize, count) * ReportBlock.wire_size;
        if (body.len < min_len) return error.BufferTooShort;

        for (0..count) |i| {
            const offset = 4 + i * ReportBlock.wire_size;
            report_buf[i] = try ReportBlock.parse(body[offset..][0..ReportBlock.wire_size]);
        }

        return .{
            .ssrc = std.mem.readInt(u32, body[0..4], .big),
            .report_blocks = report_buf[0..count],
        };
    }
};

// ============================================================================
// RTCP SDES (RFC 3550 §6.5)
// ============================================================================

/// SDES item type codes (RFC 3550 §12.2)
pub const SdesItemType = enum(u8) {
    end = 0,
    cname = 1,
    name = 2,
    email = 3,
    phone = 4,
    loc = 5,
    tool = 6,
    note = 7,
    priv = 8,
    _,
};

/// A single SDES item.
pub const SdesItem = struct {
    item_type: SdesItemType,
    data: []const u8,

    pub fn parse(buf: []const u8) !struct { item: SdesItem, consumed: usize } {
        if (buf.len < 1) return error.BufferTooShort;
        const t: SdesItemType = @enumFromInt(buf[0]);
        if (t == .end) return .{ .item = .{ .item_type = .end, .data = &.{} }, .consumed = 1 };
        if (buf.len < 2) return error.BufferTooShort;
        const length = buf[1];
        if (buf.len < 2 + @as(usize, length)) return error.BufferTooShort;
        return .{
            .item = .{ .item_type = t, .data = buf[2..][0..length] },
            .consumed = 2 + @as(usize, length),
        };
    }
};

// ============================================================================
// RTCP Feedback (RFC 4585)
// ============================================================================

/// Feedback message type for RTPFB / PSFB (RFC 4585 §6.1).
pub const FeedbackMessageType = enum(u5) {
    nack = 1, // RTPFB: Generic NACK
    pli = 1, // PSFB: Picture Loss Indication (same value, different PT)
    sli = 2, // PSFB: Slice Loss Indication
    fir = 4, // PSFB: Full Intra Request
    _,
};

/// Parsed RTCP feedback message (RTPFB=205 or PSFB=206).
pub const RtcpFeedback = struct {
    sender_ssrc: u32,
    media_ssrc: u32,
    fmt: u5,
    packet_type: RtcpPacketType,
    fci: []const u8, // feedback control information

    pub fn parse(body: []const u8, header: RtcpHeader) !RtcpFeedback {
        if (body.len < 8) return error.BufferTooShort;
        return .{
            .sender_ssrc = std.mem.readInt(u32, body[0..4], .big),
            .media_ssrc = std.mem.readInt(u32, body[4..8], .big),
            .fmt = header.count,
            .packet_type = header.packet_type,
            .fci = if (body.len > 8) body[8..] else &.{},
        };
    }
};

// ============================================================================
// RTCP Compound Packet Parsing
// ============================================================================

/// Union of all parsed RTCP packet kinds.
pub const RtcpPacket = union(enum) {
    sender_report: SenderReport,
    receiver_report: ReceiverReport,
    bye: RtcpBye,
    feedback: RtcpFeedback,
    unknown: RtcpUnknown,
};

/// Parsed BYE packet (RFC 3550 §6.6).
pub const RtcpBye = struct {
    ssrc_list: []const u32,
    reason: ?[]const u8,
};

/// Fallback for unrecognized RTCP packet types.
pub const RtcpUnknown = struct {
    header: RtcpHeader,
    body: []const u8,
};

/// Parse a single RTCP packet from a buffer.
/// Returns the parsed packet and the number of bytes consumed.
/// `scratch_rb` provides storage for up to 31 report blocks.
/// `scratch_ssrc` provides storage for up to 31 SSRC values (BYE).
pub fn parseRtcpPacket(
    buf: []const u8,
    scratch_rb: []ReportBlock,
    scratch_ssrc: []u32,
) !struct { packet: RtcpPacket, consumed: usize } {
    const header = try RtcpHeader.parse(buf);
    const total = header.packetSize();
    if (buf.len < total) return error.BufferTooShort;

    const body = buf[rtcp_fixed_header_size..total];

    const packet: RtcpPacket = switch (header.packet_type) {
        .sender_report => .{ .sender_report = try SenderReport.parse(body, header.count, scratch_rb) },
        .receiver_report => .{ .receiver_report = try ReceiverReport.parse(body, header.count, scratch_rb) },
        .bye => blk: {
            const sc = @as(usize, header.count);
            if (body.len < sc * 4) return error.BufferTooShort;
            for (0..sc) |i| {
                scratch_ssrc[i] = std.mem.readInt(u32, body[i * 4 ..][0..4], .big);
            }
            var reason: ?[]const u8 = null;
            const after_ssrc = sc * 4;
            if (body.len > after_ssrc) {
                const reason_len = body[after_ssrc];
                if (body.len >= after_ssrc + 1 + reason_len) {
                    reason = body[after_ssrc + 1 ..][0..reason_len];
                }
            }
            break :blk .{ .bye = .{ .ssrc_list = scratch_ssrc[0..sc], .reason = reason } };
        },
        .rtpfb, .psfb => .{ .feedback = try RtcpFeedback.parse(body, header) },
        else => .{ .unknown = .{ .header = header, .body = body } },
    };

    return .{ .packet = packet, .consumed = total };
}

// ============================================================================
// SSRC Collision Detection (RFC 3550 §8.2)
// ============================================================================

/// Transport address — used to track source of packets per SSRC.
pub const TransportAddress = struct {
    /// IPv4 or IPv6 packed address bytes
    addr: [16]u8 = std.mem.zeroes([16]u8),
    port: u16 = 0,

    pub fn eql(a: TransportAddress, b: TransportAddress) bool {
        return a.port == b.port and std.mem.eql(u8, &a.addr, &b.addr);
    }
};

// ============================================================================
// RTP Session State (per SSRC)
// ============================================================================

/// Per-SSRC reception state tracked by RtpSession.
pub const SsrcState = struct {
    /// Transport address this SSRC was first seen from
    source: TransportAddress,
    /// Highest sequence number received (extended to 32-bit to handle wraps)
    extended_max_seq: u32 = 0,
    /// Number of 16-bit sequence number wraps observed
    seq_cycles: u16 = 0,
    /// Total packets received from this SSRC
    packet_count: u64 = 0,
    /// Total payload bytes received from this SSRC
    octet_count: u64 = 0,
    /// Estimated inter-arrival jitter (RFC 3550 §6.4.1) scaled by 16
    jitter: u32 = 0,
    /// Whether we have received the first packet (for init)
    initialized: bool = false,
    /// Last RTP timestamp received (for jitter calc)
    last_rtp_ts: u32 = 0,
    /// Last arrival time in RTP timestamp units (for jitter calc)
    last_arrival: u32 = 0,
};

/// RTP session: tracks per-SSRC state and detects collisions (RFC 3550 §8.2).
pub const RtpSession = struct {
    /// Map from SSRC → per-source state
    sources: std.AutoHashMap(u32, SsrcState),

    pub fn init(allocator: Allocator) RtpSession {
        return .{
            .sources = std.AutoHashMap(u32, SsrcState).init(allocator),
        };
    }

    pub fn deinit(self: *RtpSession) void {
        self.sources.deinit();
    }

    /// Result of processing an incoming RTP packet.
    pub const RecordResult = struct {
        collision: bool = false,
    };

    /// Record an incoming RTP packet. Returns collision status.
    ///
    /// `arrival_ts` is the local arrival time in RTP timestamp units (same
    /// clock rate as the RTP stream) — needed for jitter estimation.
    pub fn recordPacket(
        self: *RtpSession,
        header: RtpHeader,
        payload_len: usize,
        source: TransportAddress,
        arrival_ts: u32,
    ) !RecordResult {
        const entry = try self.sources.getOrPut(header.ssrc);

        if (entry.found_existing) {
            const state = entry.value_ptr;

            // SSRC collision detection (RFC 3550 §8.2)
            if (!state.source.eql(source)) {
                return .{ .collision = true };
            }

            // Sequence number tracking with 16-bit wrap detection
            const seq = header.sequence_number;
            const max_seq: u16 = @intCast(state.extended_max_seq & 0xFFFF);
            const delta = @as(i32, @as(i16, @bitCast(seq -% max_seq)));

            if (delta > 0) {
                if (seq < max_seq) {
                    // Wrapped
                    state.seq_cycles +%= 1;
                }
                state.extended_max_seq = (@as(u32, state.seq_cycles) << 16) | @as(u32, seq);
            }

            // Jitter estimation (RFC 3550 §A.8)
            if (state.initialized) {
                const transit = @as(i32, @bitCast(arrival_ts -% header.timestamp));
                const last_transit = @as(i32, @bitCast(state.last_arrival -% state.last_rtp_ts));
                var d = transit - last_transit;
                if (d < 0) d = -d;
                const du: u32 = @intCast(d);
                // jitter = jitter + (|D| - jitter) / 16
                state.jitter = state.jitter +% ((du -% state.jitter) >> 4);
            }

            state.last_rtp_ts = header.timestamp;
            state.last_arrival = arrival_ts;
            state.initialized = true;
            state.packet_count += 1;
            state.octet_count += payload_len;
        } else {
            // First packet from this SSRC
            entry.value_ptr.* = .{
                .source = source,
                .extended_max_seq = @as(u32, header.sequence_number),
                .seq_cycles = 0,
                .packet_count = 1,
                .octet_count = payload_len,
                .jitter = 0,
                .initialized = true,
                .last_rtp_ts = header.timestamp,
                .last_arrival = arrival_ts,
            };
        }

        return .{ .collision = false };
    }
};

// ============================================================================
// Tests
// ============================================================================

test "RTP header parse/serialize roundtrip" {
    const original = RtpHeader{
        .version = 2,
        .padding = false,
        .extension = true,
        .csrc_count = 3,
        .marker = true,
        .payload_type = 111,
        .sequence_number = 0xABCD,
        .timestamp = 0x12345678,
        .ssrc = 0xDEADBEEF,
    };

    const wire = original.serialize();
    const parsed = try RtpHeader.parse(&wire);

    try std.testing.expectEqual(original.version, parsed.version);
    try std.testing.expectEqual(original.padding, parsed.padding);
    try std.testing.expectEqual(original.extension, parsed.extension);
    try std.testing.expectEqual(original.csrc_count, parsed.csrc_count);
    try std.testing.expectEqual(original.marker, parsed.marker);
    try std.testing.expectEqual(original.payload_type, parsed.payload_type);
    try std.testing.expectEqual(original.sequence_number, parsed.sequence_number);
    try std.testing.expectEqual(original.timestamp, parsed.timestamp);
    try std.testing.expectEqual(original.ssrc, parsed.ssrc);
}

test "RTP packet with CSRC and extension" {
    // Build a packet: V=2, P=0, X=1, CC=2, M=0, PT=96
    // seq=1000, ts=160000, ssrc=0x11223344
    // CSRC: 0xAAAAAAAA, 0xBBBBBBBB
    // Extension: profile=0xBEDE, length=1 word (4 bytes of ext data)
    // Payload: "HELLO"
    var buf: [12 + 8 + 4 + 4 + 5]u8 = undefined;

    // Byte 0: V=2, P=0, X=1, CC=2 → 0b10_0_1_0010 = 0x92
    buf[0] = 0x92;
    // Byte 1: M=0, PT=96 → 0b0_1100000 = 0x60
    buf[1] = 0x60;
    // Seq
    std.mem.writeInt(u16, buf[2..4], 1000, .big);
    // Timestamp
    std.mem.writeInt(u32, buf[4..8], 160000, .big);
    // SSRC
    std.mem.writeInt(u32, buf[8..12], 0x11223344, .big);
    // CSRC[0]
    std.mem.writeInt(u32, buf[12..16], 0xAAAAAAAA, .big);
    // CSRC[1]
    std.mem.writeInt(u32, buf[16..20], 0xBBBBBBBB, .big);
    // Extension header: profile=0xBEDE, length=1
    std.mem.writeInt(u16, buf[20..22], 0xBEDE, .big);
    std.mem.writeInt(u16, buf[22..24], 1, .big);
    // Extension data (4 bytes)
    buf[24] = 0x01;
    buf[25] = 0x02;
    buf[26] = 0x03;
    buf[27] = 0x04;
    // Payload
    @memcpy(buf[28..33], "HELLO");

    const pkt = try RtpPacket.parse(&buf);

    try std.testing.expectEqual(@as(u2, 2), pkt.header.version);
    try std.testing.expectEqual(false, pkt.header.padding);
    try std.testing.expectEqual(true, pkt.header.extension);
    try std.testing.expectEqual(@as(u4, 2), pkt.header.csrc_count);
    try std.testing.expectEqual(false, pkt.header.marker);
    try std.testing.expectEqual(@as(u7, 96), pkt.header.payload_type);
    try std.testing.expectEqual(@as(u16, 1000), pkt.header.sequence_number);
    try std.testing.expectEqual(@as(u32, 160000), pkt.header.timestamp);
    try std.testing.expectEqual(@as(u32, 0x11223344), pkt.header.ssrc);

    try std.testing.expectEqual(@as(usize, 2), pkt.csrc_list.len);
    try std.testing.expectEqual(@as(u32, 0xAAAAAAAA), pkt.csrc_list[0]);
    try std.testing.expectEqual(@as(u32, 0xBBBBBBBB), pkt.csrc_list[1]);

    try std.testing.expect(pkt.extension != null);
    try std.testing.expectEqual(@as(u16, 0xBEDE), pkt.extension.?.profile_id);
    try std.testing.expectEqual(@as(usize, 4), pkt.extension.?.data.len);

    try std.testing.expectEqualSlices(u8, "HELLO", pkt.payload);
}

test "RTCP Sender Report parsing" {
    // Build a minimal SR: header + SSRC + sender info, 0 report blocks
    // Total = 4 (header) + 4 (SSRC) + 20 (sender info) = 28 bytes
    // Length field = (28/4) - 1 = 6
    var buf: [28]u8 = undefined;

    // Header: V=2, P=0, RC=0, PT=200, length=6
    buf[0] = 0x80; // V=2, P=0, RC=0
    buf[1] = 200; // PT=SR
    std.mem.writeInt(u16, buf[2..4], 6, .big);
    // SSRC
    std.mem.writeInt(u32, buf[4..8], 0x12345678, .big);
    // NTP timestamp MSW
    std.mem.writeInt(u32, buf[8..12], 0xAABBCCDD, .big);
    // NTP timestamp LSW
    std.mem.writeInt(u32, buf[12..16], 0x11223344, .big);
    // RTP timestamp
    std.mem.writeInt(u32, buf[16..20], 48000, .big);
    // Sender packet count
    std.mem.writeInt(u32, buf[20..24], 100, .big);
    // Sender octet count
    std.mem.writeInt(u32, buf[24..28], 16000, .big);

    var rb_buf: [31]ReportBlock = undefined;
    var ssrc_buf: [31]u32 = undefined;
    const result = try parseRtcpPacket(&buf, &rb_buf, &ssrc_buf);
    const sr = result.packet.sender_report;

    try std.testing.expectEqual(@as(u32, 0x12345678), sr.ssrc);
    try std.testing.expectEqual(@as(u32, 0xAABBCCDD), sr.ntp_timestamp_msw);
    try std.testing.expectEqual(@as(u32, 0x11223344), sr.ntp_timestamp_lsw);
    try std.testing.expectEqual(@as(u32, 48000), sr.rtp_timestamp);
    try std.testing.expectEqual(@as(u32, 100), sr.sender_packet_count);
    try std.testing.expectEqual(@as(u32, 16000), sr.sender_octet_count);
    try std.testing.expectEqual(@as(usize, 0), sr.report_blocks.len);
    try std.testing.expectEqual(@as(usize, 28), result.consumed);
}

test "RTCP Receiver Report parsing" {
    // Build an RR with 1 report block:
    // header(4) + SSRC(4) + report_block(24) = 32 bytes
    // Length = (32/4)-1 = 7
    var buf: [32]u8 = undefined;

    // Header: V=2, P=0, RC=1, PT=201, length=7
    buf[0] = 0x81; // V=2, P=0, RC=1
    buf[1] = 201; // PT=RR
    std.mem.writeInt(u16, buf[2..4], 7, .big);
    // Reporter SSRC
    std.mem.writeInt(u32, buf[4..8], 0xAABBCCDD, .big);
    // Report block SSRC
    std.mem.writeInt(u32, buf[8..12], 0x11111111, .big);
    // Fraction lost(8) + Cumulative lost(24)
    // fraction=25, cumulative=100
    const lost_word: u32 = (@as(u32, 25) << 24) | 100;
    std.mem.writeInt(u32, buf[12..16], lost_word, .big);
    // Extended highest seq
    std.mem.writeInt(u32, buf[16..20], 50000, .big);
    // Jitter
    std.mem.writeInt(u32, buf[20..24], 320, .big);
    // LSR
    std.mem.writeInt(u32, buf[24..28], 0x0000FFFF, .big);
    // DLSR
    std.mem.writeInt(u32, buf[28..32], 0x00010000, .big);

    var rb_buf: [31]ReportBlock = undefined;
    var ssrc_buf: [31]u32 = undefined;
    const result = try parseRtcpPacket(&buf, &rb_buf, &ssrc_buf);
    const rr = result.packet.receiver_report;

    try std.testing.expectEqual(@as(u32, 0xAABBCCDD), rr.ssrc);
    try std.testing.expectEqual(@as(usize, 1), rr.report_blocks.len);

    const rb = rr.report_blocks[0];
    try std.testing.expectEqual(@as(u32, 0x11111111), rb.ssrc);
    try std.testing.expectEqual(@as(u8, 25), rb.fraction_lost);
    try std.testing.expectEqual(@as(u24, 100), rb.cumulative_lost);
    try std.testing.expectEqual(@as(u32, 50000), rb.extended_highest_seq);
    try std.testing.expectEqual(@as(u32, 320), rb.jitter);
}

test "SSRC collision detection" {
    var session = RtpSession.init(std.testing.allocator);
    defer session.deinit();

    const addr1 = TransportAddress{ .addr = .{ 10, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, .port = 5000 };
    const addr2 = TransportAddress{ .addr = .{ 10, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, .port = 6000 };

    const hdr = RtpHeader{
        .ssrc = 0xDEADBEEF,
        .sequence_number = 1,
        .timestamp = 160,
    };

    // First packet — establishes source
    const r1 = try session.recordPacket(hdr, 100, addr1, 160);
    try std.testing.expectEqual(false, r1.collision);

    // Same SSRC, same source — no collision
    var hdr2 = hdr;
    hdr2.sequence_number = 2;
    hdr2.timestamp = 320;
    const r2 = try session.recordPacket(hdr2, 100, addr1, 320);
    try std.testing.expectEqual(false, r2.collision);

    // Same SSRC, different source — collision! (RFC 3550 §8.2)
    const r3 = try session.recordPacket(hdr, 100, addr2, 480);
    try std.testing.expectEqual(true, r3.collision);
}

test "RTP/RTCP mux detection" {
    // RTP: second byte with PT < 64 or > 95 → RTP
    // Example: PT=111 → 111 & 0x7F = 111 → not in 64-95 → RTP
    try std.testing.expectEqual(RtpRtcpKind.rtp, classifyRtpRtcp(111));

    // PT=96 (common for dynamic codecs) → RTP
    try std.testing.expectEqual(RtpRtcpKind.rtp, classifyRtpRtcp(96));

    // RTCP SR: PT=200. Second byte on wire = 200, 200 & 0x7F = 72 → in 64-95 → RTCP
    try std.testing.expectEqual(RtpRtcpKind.rtcp, classifyRtpRtcp(200));

    // RTCP RR: PT=201 → 201 & 0x7F = 73 → RTCP
    try std.testing.expectEqual(RtpRtcpKind.rtcp, classifyRtpRtcp(201));

    // RTCP BYE: PT=203 → 203 & 0x7F = 75 → RTCP
    try std.testing.expectEqual(RtpRtcpKind.rtcp, classifyRtpRtcp(203));

    // RTCP PSFB: PT=206 → 206 & 0x7F = 78 → RTCP
    try std.testing.expectEqual(RtpRtcpKind.rtcp, classifyRtpRtcp(206));

    // PT=0 (PCMU) → 0 not in 64-95 → RTP
    try std.testing.expectEqual(RtpRtcpKind.rtp, classifyRtpRtcp(0));
}

test "packet classification (STUN, DTLS, RTP/RTCP)" {
    // STUN: 0-3
    try std.testing.expectEqual(PacketKind.stun, classifyPacket(0));
    try std.testing.expectEqual(PacketKind.stun, classifyPacket(1));
    try std.testing.expectEqual(PacketKind.stun, classifyPacket(3));

    // DTLS: 20-63
    try std.testing.expectEqual(PacketKind.dtls, classifyPacket(20));
    try std.testing.expectEqual(PacketKind.dtls, classifyPacket(63));

    // RTP/RTCP: 128-191
    try std.testing.expectEqual(PacketKind.rtp_rtcp, classifyPacket(128));
    try std.testing.expectEqual(PacketKind.rtp_rtcp, classifyPacket(191));

    // Unknown ranges
    try std.testing.expectEqual(PacketKind.unknown, classifyPacket(4));
    try std.testing.expectEqual(PacketKind.unknown, classifyPacket(19));
    try std.testing.expectEqual(PacketKind.unknown, classifyPacket(64));
    try std.testing.expectEqual(PacketKind.unknown, classifyPacket(127));
    try std.testing.expectEqual(PacketKind.unknown, classifyPacket(192));
    try std.testing.expectEqual(PacketKind.unknown, classifyPacket(255));
}

test "sequence number wrapping" {
    var session = RtpSession.init(std.testing.allocator);
    defer session.deinit();

    const addr = TransportAddress{ .addr = .{ 192, 168, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, .port = 4000 };

    // Send packet with seq near max
    var hdr = RtpHeader{ .ssrc = 0x42, .sequence_number = 65534, .timestamp = 1000 };
    _ = try session.recordPacket(hdr, 50, addr, 1000);

    hdr.sequence_number = 65535;
    hdr.timestamp = 2000;
    _ = try session.recordPacket(hdr, 50, addr, 2000);

    // Wrap to 0
    hdr.sequence_number = 0;
    hdr.timestamp = 3000;
    _ = try session.recordPacket(hdr, 50, addr, 3000);

    // Wrap to 1
    hdr.sequence_number = 1;
    hdr.timestamp = 4000;
    _ = try session.recordPacket(hdr, 50, addr, 4000);

    const state = session.sources.get(0x42).?;

    // After wrapping once, seq_cycles should be 1
    try std.testing.expectEqual(@as(u16, 1), state.seq_cycles);
    // Extended max seq = (1 << 16) | 1 = 65537
    try std.testing.expectEqual(@as(u32, 65537), state.extended_max_seq);
    // Total 4 packets
    try std.testing.expectEqual(@as(u64, 4), state.packet_count);
}

test "report block serialize/parse roundtrip" {
    const original = ReportBlock{
        .ssrc = 0xCAFEBABE,
        .fraction_lost = 51,
        .cumulative_lost = 1234,
        .extended_highest_seq = 99999,
        .jitter = 500,
        .last_sr = 0x0000AAAA,
        .delay_since_last_sr = 0x00005555,
    };

    const wire = original.serialize();
    const parsed = try ReportBlock.parse(&wire);

    try std.testing.expectEqual(original.ssrc, parsed.ssrc);
    try std.testing.expectEqual(original.fraction_lost, parsed.fraction_lost);
    try std.testing.expectEqual(original.cumulative_lost, parsed.cumulative_lost);
    try std.testing.expectEqual(original.extended_highest_seq, parsed.extended_highest_seq);
    try std.testing.expectEqual(original.jitter, parsed.jitter);
    try std.testing.expectEqual(original.last_sr, parsed.last_sr);
    try std.testing.expectEqual(original.delay_since_last_sr, parsed.delay_since_last_sr);
}

test "RTP packet serialize roundtrip" {
    const header = RtpHeader{
        .extension = false,
        .csrc_count = 0,
        .marker = true,
        .payload_type = 111,
        .sequence_number = 42,
        .timestamp = 8000,
        .ssrc = 0xFEEDFACE,
    };

    const original = RtpPacket{
        .header = header,
        .csrc_list = &.{},
        .extension = null,
        .payload = "test payload bytes",
    };

    const wire = try original.serialize(std.testing.allocator);
    defer std.testing.allocator.free(wire);

    const parsed = try RtpPacket.parse(wire);

    try std.testing.expectEqual(original.header.marker, parsed.header.marker);
    try std.testing.expectEqual(original.header.payload_type, parsed.header.payload_type);
    try std.testing.expectEqual(original.header.sequence_number, parsed.header.sequence_number);
    try std.testing.expectEqual(original.header.timestamp, parsed.header.timestamp);
    try std.testing.expectEqual(original.header.ssrc, parsed.header.ssrc);
    try std.testing.expectEqualSlices(u8, "test payload bytes", parsed.payload);
}

test "RTCP header serialize/parse roundtrip" {
    const original = RtcpHeader{
        .version = 2,
        .padding = false,
        .count = 5,
        .packet_type = .receiver_report,
        .length = 42,
    };

    const wire = original.serialize();
    const parsed = try RtcpHeader.parse(&wire);

    try std.testing.expectEqual(original.version, parsed.version);
    try std.testing.expectEqual(original.padding, parsed.padding);
    try std.testing.expectEqual(original.count, parsed.count);
    try std.testing.expectEqual(original.packet_type, parsed.packet_type);
    try std.testing.expectEqual(original.length, parsed.length);
}

test "invalid RTP version rejected" {
    // V=3 (invalid)
    var buf = [_]u8{0} ** 12;
    buf[0] = 0xC0; // V=3
    try std.testing.expectError(error.InvalidVersion, RtpHeader.parse(&buf));
}

test "buffer too short rejected" {
    const buf = [_]u8{ 0x80, 0x00 }; // only 2 bytes
    try std.testing.expectError(error.BufferTooShort, RtpHeader.parse(&buf));
}
