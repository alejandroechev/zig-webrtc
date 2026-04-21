//! SDP line-by-line parser (RFC 8866)
//!
//! Parses an SDP text description into a SessionDescription struct.
//! Enforces RFC 8866 ordering: v= must be first, then o=, s=, etc.
//! Session-level fields must appear before any media-level (m=) lines.

const std = @import("std");
const Allocator = std.mem.Allocator;
const sdp = @import("sdp.zig");

const SessionDescription = sdp.SessionDescription;
const Origin = sdp.Origin;
const Connection = sdp.Connection;
const MediaDescription = sdp.MediaDescription;
const Attribute = sdp.Attribute;
const Bandwidth = sdp.Bandwidth;
const Timing = sdp.Timing;

pub const ParseError = error{
    /// SDP must start with v= line
    MissingVersion,
    /// v= value must be 0
    InvalidVersion,
    /// Line does not match <type>=<value> format (RFC 8866 §5)
    InvalidLineFormat,
    /// o= line is missing after v=
    MissingOrigin,
    /// s= line is missing after o=
    MissingSessionName,
    /// t= line is missing
    MissingTiming,
    /// o= line has wrong number of fields (need 6)
    InvalidOrigin,
    /// m= line has wrong format
    InvalidMedia,
    /// b= line has wrong format
    InvalidBandwidth,
    /// t= line has wrong format
    InvalidTiming,
    /// c= line has wrong format
    InvalidConnection,
    /// Session-level field appeared after m= line
    SessionFieldAfterMedia,
    /// Lines appeared out of RFC 8866 required order
    OrderViolation,
};

const Line = struct {
    type_char: u8,
    value: []const u8,
};

fn parseLine(line: []const u8) ParseError!Line {
    if (line.len < 2) return ParseError.InvalidLineFormat;
    if (line[1] != '=') return ParseError.InvalidLineFormat;
    return Line{
        .type_char = line[0],
        .value = if (line.len > 2) line[2..] else "",
    };
}

fn parseOrigin(value: []const u8) ParseError!Origin {
    var it = std.mem.tokenizeScalar(u8, value, ' ');
    const username = it.next() orelse return ParseError.InvalidOrigin;
    const sess_id = it.next() orelse return ParseError.InvalidOrigin;
    const sess_version = it.next() orelse return ParseError.InvalidOrigin;
    const net_type = it.next() orelse return ParseError.InvalidOrigin;
    const addr_type = it.next() orelse return ParseError.InvalidOrigin;
    const unicast_address = it.next() orelse return ParseError.InvalidOrigin;
    return Origin{
        .username = username,
        .sess_id = sess_id,
        .sess_version = sess_version,
        .net_type = net_type,
        .addr_type = addr_type,
        .unicast_address = unicast_address,
    };
}

fn parseConnection(value: []const u8) ParseError!Connection {
    var it = std.mem.tokenizeScalar(u8, value, ' ');
    const net_type = it.next() orelse return ParseError.InvalidConnection;
    const addr_type = it.next() orelse return ParseError.InvalidConnection;
    const address = it.next() orelse return ParseError.InvalidConnection;
    return Connection{
        .net_type = net_type,
        .addr_type = addr_type,
        .address = address,
    };
}

fn parseBandwidth(value: []const u8) ParseError!Bandwidth {
    const colon_pos = std.mem.indexOfScalar(u8, value, ':') orelse return ParseError.InvalidBandwidth;
    const bw_type = value[0..colon_pos];
    const bw_str = value[colon_pos + 1 ..];
    const bandwidth = std.fmt.parseInt(u32, bw_str, 10) catch return ParseError.InvalidBandwidth;
    return Bandwidth{
        .bw_type = bw_type,
        .bandwidth = bandwidth,
    };
}

fn parseTiming(value: []const u8) ParseError!Timing {
    var it = std.mem.tokenizeScalar(u8, value, ' ');
    const start_str = it.next() orelse return ParseError.InvalidTiming;
    const stop_str = it.next() orelse return ParseError.InvalidTiming;
    const start = std.fmt.parseInt(u64, start_str, 10) catch return ParseError.InvalidTiming;
    const stop = std.fmt.parseInt(u64, stop_str, 10) catch return ParseError.InvalidTiming;
    return Timing{
        .start = start,
        .stop = stop,
    };
}

fn parseAttribute(value: []const u8) Attribute {
    if (std.mem.indexOfScalar(u8, value, ':')) |colon_pos| {
        return Attribute{
            .name = value[0..colon_pos],
            .value = value[colon_pos + 1 ..],
        };
    }
    return Attribute{
        .name = value,
        .value = null,
    };
}

fn parseMediaLine(allocator: Allocator, value: []const u8) !MediaDescription {
    var it = std.mem.tokenizeScalar(u8, value, ' ');

    const media_type = it.next() orelse return ParseError.InvalidMedia;
    const port_str = it.next() orelse return ParseError.InvalidMedia;
    const proto = it.next() orelse return ParseError.InvalidMedia;

    // Parse port, which may include /num_ports
    var port: u16 = undefined;
    var num_ports: ?u16 = null;
    if (std.mem.indexOfScalar(u8, port_str, '/')) |slash_pos| {
        port = std.fmt.parseInt(u16, port_str[0..slash_pos], 10) catch return ParseError.InvalidMedia;
        num_ports = std.fmt.parseInt(u16, port_str[slash_pos + 1 ..], 10) catch return ParseError.InvalidMedia;
    } else {
        port = std.fmt.parseInt(u16, port_str, 10) catch return ParseError.InvalidMedia;
    }

    // Remaining tokens are format strings
    var formats: std.ArrayList([]const u8) = .empty;
    errdefer formats.deinit(allocator);
    while (it.next()) |fmt_str| {
        try formats.append(allocator, fmt_str);
    }

    return MediaDescription{
        .media_type = media_type,
        .port = port,
        .num_ports = num_ports,
        .proto = proto,
        .formats = try formats.toOwnedSlice(allocator),
        .info = null,
        .connection = null,
        .bandwidths = &.{},
        .attributes = &.{},
    };
}

/// Parse an SDP text description into a SessionDescription.
/// All string fields reference slices into the original `text` buffer —
/// the caller must keep `text` alive for the lifetime of the returned struct.
pub fn parseSdp(allocator: Allocator, text: []const u8) !SessionDescription {
    var emails: std.ArrayList([]const u8) = .empty;
    defer emails.deinit(allocator);
    var phones: std.ArrayList([]const u8) = .empty;
    defer phones.deinit(allocator);
    var session_bandwidths: std.ArrayList(Bandwidth) = .empty;
    defer session_bandwidths.deinit(allocator);
    var session_attributes: std.ArrayList(Attribute) = .empty;
    defer session_attributes.deinit(allocator);
    var media_list: std.ArrayList(MediaDescription) = .empty;
    defer media_list.deinit(allocator);
    errdefer for (media_list.items) |media| {
        allocator.free(media.formats);
        allocator.free(media.bandwidths);
        allocator.free(media.attributes);
    };

    // Per-media accumulators
    var media_bandwidths: std.ArrayList(Bandwidth) = .empty;
    defer media_bandwidths.deinit(allocator);
    var media_attributes: std.ArrayList(Attribute) = .empty;
    defer media_attributes.deinit(allocator);

    var version: ?u8 = null;
    var origin: ?Origin = null;
    var session_name: ?[]const u8 = null;
    var session_info: ?[]const u8 = null;
    var session_uri: ?[]const u8 = null;
    var session_connection: ?Connection = null;
    var timing: ?Timing = null;
    var in_media = false;

    // Track ordering state for session-level lines
    const OrderState = enum { start, after_v, after_o, after_s, session_body, time_section, session_attrs, media };
    var order_state: OrderState = .start;

    // Collect lines — tolerate both CRLF and LF (RFC 8866 §5)
    var lines: std.ArrayList([]const u8) = .empty;
    defer lines.deinit(allocator);

    // First split by \r\n, then each part by \n
    var crlf_iter = std.mem.splitSequence(u8, text, "\r\n");
    while (crlf_iter.next()) |crlf_part| {
        var lf_iter = std.mem.splitScalar(u8, crlf_part, '\n');
        while (lf_iter.next()) |line| {
            try lines.append(allocator, line);
        }
    }

    for (lines.items) |raw_line| {
        if (raw_line.len == 0) continue;

        const parsed = try parseLine(raw_line);

        switch (parsed.type_char) {
            'v' => {
                if (order_state != .start) return ParseError.OrderViolation;
                const v = std.fmt.parseInt(u8, parsed.value, 10) catch return ParseError.InvalidVersion;
                if (v != 0) return ParseError.InvalidVersion;
                version = v;
                order_state = .after_v;
            },
            'o' => {
                if (order_state != .after_v) return ParseError.OrderViolation;
                origin = try parseOrigin(parsed.value);
                order_state = .after_o;
            },
            's' => {
                if (order_state != .after_o) return ParseError.OrderViolation;
                session_name = parsed.value;
                order_state = .after_s;
            },
            'i' => {
                if (in_media) {
                    if (media_list.items.len > 0) {
                        media_list.items[media_list.items.len - 1].info = parsed.value;
                    }
                } else {
                    if (@intFromEnum(order_state) < @intFromEnum(OrderState.after_s)) return ParseError.OrderViolation;
                    session_info = parsed.value;
                    order_state = .session_body;
                }
            },
            'u' => {
                if (in_media) return ParseError.SessionFieldAfterMedia;
                if (@intFromEnum(order_state) < @intFromEnum(OrderState.after_s)) return ParseError.OrderViolation;
                session_uri = parsed.value;
                order_state = .session_body;
            },
            'e' => {
                if (in_media) return ParseError.SessionFieldAfterMedia;
                if (@intFromEnum(order_state) < @intFromEnum(OrderState.after_s)) return ParseError.OrderViolation;
                try emails.append(allocator, parsed.value);
                order_state = .session_body;
            },
            'p' => {
                if (in_media) return ParseError.SessionFieldAfterMedia;
                if (@intFromEnum(order_state) < @intFromEnum(OrderState.after_s)) return ParseError.OrderViolation;
                try phones.append(allocator, parsed.value);
                order_state = .session_body;
            },
            'c' => {
                const conn = try parseConnection(parsed.value);
                if (in_media) {
                    if (media_list.items.len > 0) {
                        media_list.items[media_list.items.len - 1].connection = conn;
                    }
                } else {
                    if (@intFromEnum(order_state) < @intFromEnum(OrderState.after_s)) return ParseError.OrderViolation;
                    session_connection = conn;
                    order_state = .session_body;
                }
            },
            'b' => {
                const bw = try parseBandwidth(parsed.value);
                if (in_media) {
                    try media_bandwidths.append(allocator, bw);
                } else {
                    if (@intFromEnum(order_state) < @intFromEnum(OrderState.after_s)) return ParseError.OrderViolation;
                    try session_bandwidths.append(allocator, bw);
                    order_state = .session_body;
                }
            },
            't' => {
                if (@intFromEnum(order_state) < @intFromEnum(OrderState.after_s)) return ParseError.OrderViolation;
                timing = try parseTiming(parsed.value);
                order_state = .time_section;
            },
            'r', 'z' => {
                // Repeat and timezone lines — skip (not stored in simplified model)
                if (@intFromEnum(order_state) < @intFromEnum(OrderState.time_section)) return ParseError.OrderViolation;
            },
            'k' => {
                // k= is obsolete (RFC 8866 §5.12) — ignore
            },
            'a' => {
                const attr = parseAttribute(parsed.value);
                if (in_media) {
                    try media_attributes.append(allocator, attr);
                } else {
                    if (@intFromEnum(order_state) < @intFromEnum(OrderState.after_s)) return ParseError.OrderViolation;
                    try session_attributes.append(allocator, attr);
                    order_state = .session_attrs;
                }
            },
            'm' => {
                // Finalize previous media description
                if (in_media and media_list.items.len > 0) {
                    const last = &media_list.items[media_list.items.len - 1];
                    last.bandwidths = try media_bandwidths.toOwnedSlice(allocator);
                    last.attributes = try media_attributes.toOwnedSlice(allocator);
                    media_bandwidths = .empty;
                    media_attributes = .empty;
                }

                if (@intFromEnum(order_state) < @intFromEnum(OrderState.time_section)) {
                    if (timing == null) return ParseError.MissingTiming;
                }

                const media_desc = try parseMediaLine(allocator, parsed.value);
                try media_list.append(allocator, media_desc);
                in_media = true;
                order_state = .media;
            },
            else => {
                // RFC 8866 §5: parser MUST ignore unknown type letters
            },
        }
    }

    // Finalize last media description
    if (in_media and media_list.items.len > 0) {
        const last = &media_list.items[media_list.items.len - 1];
        last.bandwidths = try media_bandwidths.toOwnedSlice(allocator);
        last.attributes = try media_attributes.toOwnedSlice(allocator);
    }

    // Validate required fields
    if (version == null) return ParseError.MissingVersion;
    if (origin == null) return ParseError.MissingOrigin;
    if (session_name == null) return ParseError.MissingSessionName;
    if (timing == null) return ParseError.MissingTiming;

    return SessionDescription{
        .version = version.?,
        .origin = origin.?,
        .session_name = session_name.?,
        .info = session_info,
        .uri = session_uri,
        .emails = try emails.toOwnedSlice(allocator),
        .phones = try phones.toOwnedSlice(allocator),
        .connection = session_connection,
        .bandwidths = try session_bandwidths.toOwnedSlice(allocator),
        .timing = timing.?,
        .media = try media_list.toOwnedSlice(allocator),
        .attributes = try session_attributes.toOwnedSlice(allocator),
    };
}
