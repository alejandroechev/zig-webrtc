//! SDP parser and serializer (RFC 8866, RFC 3264)
//! Generated from 670 structured RFC rules (8866, 3264, 8843) via RFC Compliance API.
//!
//! SDP (Session Description Protocol) is a text-based format for describing
//! multimedia sessions. Each line is `<type>=<value>` where type is a single
//! character. This module provides:
//!   - Type definitions for all SDP elements
//!   - A strict parser enforcing RFC 8866 ordering rules
//!   - A serializer producing spec-compliant output

const std = @import("std");
const Allocator = std.mem.Allocator;
const parser_mod = @import("parser.zig");
const serializer_mod = @import("serializer.zig");

pub const ParseError = parser_mod.ParseError;

// ── Core SDP types (RFC 8866 §5) ──────────────────────────────────────

/// Origin field: o=<username> <sess-id> <sess-version> <nettype> <addrtype> <unicast-address>
pub const Origin = struct {
    username: []const u8,
    sess_id: []const u8,
    sess_version: []const u8,
    net_type: []const u8,
    addr_type: []const u8,
    unicast_address: []const u8,
};

/// Connection field: c=<nettype> <addrtype> <connection-address>
pub const Connection = struct {
    net_type: []const u8,
    addr_type: []const u8,
    address: []const u8,
};

/// Bandwidth field: b=<bwtype>:<bandwidth>
pub const Bandwidth = struct {
    bw_type: []const u8,
    bandwidth: u32,
};

/// Timing field: t=<start-time> <stop-time>
pub const Timing = struct {
    start: u64,
    stop: u64,
};

/// Attribute field: a=<name> or a=<name>:<value>
pub const Attribute = struct {
    name: []const u8,
    value: ?[]const u8, // null for property (flag) attributes
};

/// Media description (RFC 8866 §5.14): m=<media> <port>[/<num_ports>] <proto> <fmt> ...
pub const MediaDescription = struct {
    media_type: []const u8, // "audio", "video", "application", "text", "message"
    port: u16,
    num_ports: ?u16,
    proto: []const u8, // "UDP/TLS/RTP/SAVPF", "RTP/AVP", etc.
    formats: []const []const u8, // payload type numbers or format strings
    info: ?[]const u8, // i= (media title)
    connection: ?Connection, // c= (media-level)
    bandwidths: []const Bandwidth, // b= (media-level)
    attributes: []const Attribute, // a= (media-level)
};

/// Complete SDP session description (RFC 8866 §5).
///
/// All string fields are slices into the original SDP text buffer when
/// produced by `parse()`. The caller must keep the source text alive.
pub const SessionDescription = struct {
    version: u8, // v= (must be 0)
    origin: Origin, // o=
    session_name: []const u8, // s=
    info: ?[]const u8, // i= (optional)
    uri: ?[]const u8, // u= (optional)
    emails: []const []const u8, // e= (zero or more)
    phones: []const []const u8, // p= (zero or more)
    connection: ?Connection, // c= (optional at session level)
    bandwidths: []const Bandwidth, // b= (zero or more)
    timing: Timing, // t=
    media: []const MediaDescription, // m= sections
    attributes: []const Attribute, // a= (session-level)

    /// Parse an SDP text description into a SessionDescription.
    /// String fields reference slices into `sdp_text` — keep it alive.
    pub fn parse(allocator: Allocator, sdp_text: []const u8) !SessionDescription {
        return parser_mod.parseSdp(allocator, sdp_text);
    }

    /// Serialize this SessionDescription into RFC 8866 compliant SDP text.
    /// Returns an owned slice; caller must free with `allocator.free()`.
    pub fn serialize(self: *const SessionDescription, allocator: Allocator) ![]u8 {
        return serializer_mod.serializeSdp(self, allocator);
    }

    /// Free all allocator-owned memory in this SessionDescription.
    pub fn deinit(self: *SessionDescription, allocator: Allocator) void {
        // Free media descriptions
        for (self.media) |*media| {
            allocator.free(media.formats);
            allocator.free(media.bandwidths);
            allocator.free(media.attributes);
        }
        allocator.free(self.media);
        allocator.free(self.emails);
        allocator.free(self.phones);
        allocator.free(self.bandwidths);
        allocator.free(self.attributes);
    }
};

// ── Tests ──────────────────────────────────────────────────────────────

const testing = std.testing;
const expectEqual = testing.expectEqual;
const expectEqualStrings = testing.expectEqualStrings;

test "RFC8866: v= line must be first and value must be 0" {
    // Missing v= entirely
    const no_v = "o=- 123 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n";
    const result1 = SessionDescription.parse(testing.allocator, no_v);
    try testing.expectError(ParseError.OrderViolation, result1);

    // v=1 is invalid
    const bad_v = "v=1\r\no=- 123 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n";
    const result2 = SessionDescription.parse(testing.allocator, bad_v);
    try testing.expectError(ParseError.InvalidVersion, result2);
}

test "RFC8866: lines must be type=value format" {
    const bad = "v=0\r\nthis is not valid\r\n";
    const result = SessionDescription.parse(testing.allocator, bad);
    try testing.expectError(ParseError.InvalidLineFormat, result);
}

test "RFC8866: o= must follow v=" {
    // s= before o= should fail
    const bad = "v=0\r\ns=-\r\no=- 123 1 IN IP4 127.0.0.1\r\nt=0 0\r\n";
    const result = SessionDescription.parse(testing.allocator, bad);
    try testing.expectError(ParseError.OrderViolation, result);
}

test "RFC8866: session-level fields must appear before media-level" {
    // u= after m= should fail
    const bad = "v=0\r\no=- 123 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\nm=audio 9 RTP/AVP 0\r\nu=http://example.com\r\n";
    const result = SessionDescription.parse(testing.allocator, bad);
    try testing.expectError(ParseError.SessionFieldAfterMedia, result);
}

test "RFC8866: reject SDP without v= line" {
    const result = SessionDescription.parse(testing.allocator, "s=-\r\n");
    try testing.expectError(ParseError.OrderViolation, result);
}

test "RFC8866: parse valid SDP offer" {
    const sdp_text =
        "v=0\r\n" ++
        "o=jdoe 3724394400 3724394405 IN IP4 198.51.100.1\r\n" ++
        "s=Call to John Smith\r\n" ++
        "i=SDP Offer #1\r\n" ++
        "u=http://www.jdoe.example.com/home.html\r\n" ++
        "e=Jane Doe <jane@jdoe.example.com>\r\n" ++
        "p=+1 617 555-6011\r\n" ++
        "c=IN IP4 198.51.100.1\r\n" ++
        "t=0 0\r\n" ++
        "m=audio 49170 RTP/AVP 0\r\n" ++
        "m=audio 49180 RTP/AVP 0\r\n" ++
        "m=video 51372 RTP/AVP 99\r\n" ++
        "c=IN IP6 2001:db8::2\r\n" ++
        "a=rtpmap:99 h263-1998/90000\r\n";

    var desc = try SessionDescription.parse(testing.allocator, sdp_text);
    defer desc.deinit(testing.allocator);

    try expectEqual(@as(u8, 0), desc.version);
    try expectEqualStrings("jdoe", desc.origin.username);
    try expectEqualStrings("Call to John Smith", desc.session_name);
    try expectEqualStrings("SDP Offer #1", desc.info.?);
    try expectEqualStrings("http://www.jdoe.example.com/home.html", desc.uri.?);
    try expectEqual(@as(usize, 1), desc.emails.len);
    try expectEqual(@as(usize, 1), desc.phones.len);
    try expectEqualStrings("IN", desc.connection.?.net_type);
    try expectEqual(@as(u64, 0), desc.timing.start);
    try expectEqual(@as(usize, 3), desc.media.len);
    try expectEqualStrings("audio", desc.media[0].media_type);
    try expectEqual(@as(u16, 49170), desc.media[0].port);
    try expectEqualStrings("video", desc.media[2].media_type);
    try expectEqualStrings("IP6", desc.media[2].connection.?.addr_type);
}

test "RFC8866: roundtrip parse-serialize" {
    const sdp_text =
        "v=0\r\n" ++
        "o=- 12345 2 IN IP4 127.0.0.1\r\n" ++
        "s=-\r\n" ++
        "t=0 0\r\n" ++
        "a=group:BUNDLE 0\r\n" ++
        "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n" ++
        "c=IN IP4 0.0.0.0\r\n" ++
        "a=mid:0\r\n" ++
        "a=rtpmap:111 opus/48000/2\r\n";

    var desc = try SessionDescription.parse(testing.allocator, sdp_text);
    defer desc.deinit(testing.allocator);

    const serialized = try desc.serialize(testing.allocator);
    defer testing.allocator.free(serialized);

    // Re-parse the serialized output
    var desc2 = try SessionDescription.parse(testing.allocator, serialized);
    defer desc2.deinit(testing.allocator);

    try expectEqual(desc.version, desc2.version);
    try expectEqualStrings(desc.origin.username, desc2.origin.username);
    try expectEqualStrings(desc.session_name, desc2.session_name);
    try expectEqual(desc.timing.start, desc2.timing.start);
    try expectEqual(desc.media.len, desc2.media.len);
    try expectEqual(desc.attributes.len, desc2.attributes.len);
    try expectEqualStrings("group", desc2.attributes[0].name);
    try expectEqualStrings("BUNDLE 0", desc2.attributes[0].value.?);
}

test "parse WebRTC SDP offer" {
    const sdp_text =
        \\v=0
        \\o=- 12345 2 IN IP4 127.0.0.1
        \\s=-
        \\t=0 0
        \\a=group:BUNDLE 0
        \\m=audio 9 UDP/TLS/RTP/SAVPF 111
        \\c=IN IP4 0.0.0.0
        \\a=mid:0
        \\a=rtpmap:111 opus/48000/2
    ;
    var desc = try SessionDescription.parse(testing.allocator, sdp_text);
    defer desc.deinit(testing.allocator);

    try expectEqual(@as(u8, 0), desc.version);
    try expectEqual(@as(usize, 1), desc.media.len);
    try expectEqualStrings("audio", desc.media[0].media_type);
    try expectEqual(@as(u16, 9), desc.media[0].port);
    try expectEqualStrings("UDP/TLS/RTP/SAVPF", desc.media[0].proto);
    try expectEqual(@as(usize, 1), desc.media[0].formats.len);
    try expectEqualStrings("111", desc.media[0].formats[0]);
    try expectEqual(@as(usize, 2), desc.media[0].attributes.len);
    try expectEqualStrings("mid", desc.media[0].attributes[0].name);
    try expectEqualStrings("0", desc.media[0].attributes[0].value.?);
    try expectEqualStrings("rtpmap", desc.media[0].attributes[1].name);
    try expectEqualStrings("111 opus/48000/2", desc.media[0].attributes[1].value.?);
}

test "parse complex WebRTC SDP with multiple media sections" {
    const sdp_text =
        \\v=0
        \\o=- 4567890 2 IN IP4 127.0.0.1
        \\s=-
        \\t=0 0
        \\a=group:BUNDLE 0 1
        \\a=msid-semantic: WMS
        \\m=audio 9 UDP/TLS/RTP/SAVPF 111 103 104
        \\c=IN IP4 0.0.0.0
        \\a=mid:0
        \\a=sendrecv
        \\a=rtpmap:111 opus/48000/2
        \\m=video 9 UDP/TLS/RTP/SAVPF 96 97
        \\c=IN IP4 0.0.0.0
        \\a=mid:1
        \\a=sendrecv
        \\a=rtpmap:96 VP8/90000
        \\a=rtpmap:97 H264/90000
    ;
    var desc = try SessionDescription.parse(testing.allocator, sdp_text);
    defer desc.deinit(testing.allocator);

    try expectEqual(@as(usize, 2), desc.media.len);
    try expectEqualStrings("audio", desc.media[0].media_type);
    try expectEqual(@as(usize, 3), desc.media[0].formats.len);
    try expectEqualStrings("video", desc.media[1].media_type);
    try expectEqual(@as(usize, 2), desc.media[1].formats.len);
    try expectEqual(@as(usize, 2), desc.attributes.len);
    try expectEqualStrings("group", desc.attributes[0].name);
}

test "parse SDP with bandwidth lines" {
    const sdp_text =
        "v=0\r\n" ++
        "o=- 1 1 IN IP4 127.0.0.1\r\n" ++
        "s=-\r\n" ++
        "b=CT:1000\r\n" ++
        "t=0 0\r\n" ++
        "m=video 9 RTP/AVP 96\r\n" ++
        "b=AS:500\r\n" ++
        "a=rtpmap:96 VP8/90000\r\n";

    var desc = try SessionDescription.parse(testing.allocator, sdp_text);
    defer desc.deinit(testing.allocator);

    try expectEqual(@as(usize, 1), desc.bandwidths.len);
    try expectEqualStrings("CT", desc.bandwidths[0].bw_type);
    try expectEqual(@as(u32, 1000), desc.bandwidths[0].bandwidth);
    try expectEqual(@as(usize, 1), desc.media[0].bandwidths.len);
    try expectEqualStrings("AS", desc.media[0].bandwidths[0].bw_type);
    try expectEqual(@as(u32, 500), desc.media[0].bandwidths[0].bandwidth);
}

test "parse SDP with flag attributes (property attributes)" {
    const sdp_text =
        "v=0\r\n" ++
        "o=- 1 1 IN IP4 127.0.0.1\r\n" ++
        "s=-\r\n" ++
        "t=0 0\r\n" ++
        "m=audio 9 RTP/AVP 0\r\n" ++
        "a=sendrecv\r\n" ++
        "a=rtcp-mux\r\n";

    var desc = try SessionDescription.parse(testing.allocator, sdp_text);
    defer desc.deinit(testing.allocator);

    try expectEqual(@as(usize, 2), desc.media[0].attributes.len);
    try expectEqualStrings("sendrecv", desc.media[0].attributes[0].name);
    try expectEqual(@as(?[]const u8, null), desc.media[0].attributes[0].value);
    try expectEqualStrings("rtcp-mux", desc.media[0].attributes[1].name);
    try expectEqual(@as(?[]const u8, null), desc.media[0].attributes[1].value);
}

test "parse SDP with port/num_ports notation" {
    const sdp_text =
        "v=0\r\n" ++
        "o=- 1 1 IN IP4 127.0.0.1\r\n" ++
        "s=-\r\n" ++
        "t=0 0\r\n" ++
        "m=video 49170/2 RTP/AVP 31\r\n";

    var desc = try SessionDescription.parse(testing.allocator, sdp_text);
    defer desc.deinit(testing.allocator);

    try expectEqual(@as(u16, 49170), desc.media[0].port);
    try expectEqual(@as(u16, 2), desc.media[0].num_ports.?);
}

// Import sub-modules so their tests are also discovered
comptime {
    _ = @import("parser.zig");
    _ = @import("serializer.zig");
}
