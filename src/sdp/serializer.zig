//! SDP serializer (RFC 8866)
//!
//! Serializes a SessionDescription struct into SDP text format.
//! Output follows the strict ordering defined in RFC 8866 §5:
//! v=, o=, s=, i=*, u=*, e=*, p=*, c=*, b=*, t=, a=*, then m= sections.

const std = @import("std");
const Allocator = std.mem.Allocator;
const sdp = @import("sdp.zig");

const SessionDescription = sdp.SessionDescription;

/// Serialize a SessionDescription into RFC 8866 compliant SDP text.
/// Returns an owned slice that the caller must free with `allocator.free()`.
pub fn serializeSdp(desc: *const SessionDescription, allocator: Allocator) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);

    // v= (protocol version) — must be first
    try buf.print(allocator, "v={d}\r\n", .{desc.version});

    // o= (origin)
    try buf.print(allocator, "o={s} {s} {s} {s} {s} {s}\r\n", .{
        desc.origin.username,
        desc.origin.sess_id,
        desc.origin.sess_version,
        desc.origin.net_type,
        desc.origin.addr_type,
        desc.origin.unicast_address,
    });

    // s= (session name)
    try buf.print(allocator, "s={s}\r\n", .{desc.session_name});

    // i=* (session information, optional)
    if (desc.info) |info| {
        try buf.print(allocator, "i={s}\r\n", .{info});
    }

    // u=* (URI, optional)
    if (desc.uri) |uri| {
        try buf.print(allocator, "u={s}\r\n", .{uri});
    }

    // e=* (email addresses)
    for (desc.emails) |email| {
        try buf.print(allocator, "e={s}\r\n", .{email});
    }

    // p=* (phone numbers)
    for (desc.phones) |phone| {
        try buf.print(allocator, "p={s}\r\n", .{phone});
    }

    // c=* (session-level connection information)
    if (desc.connection) |conn| {
        try buf.print(allocator, "c={s} {s} {s}\r\n", .{ conn.net_type, conn.addr_type, conn.address });
    }

    // b=* (session-level bandwidth)
    for (desc.bandwidths) |bw| {
        try buf.print(allocator, "b={s}:{d}\r\n", .{ bw.bw_type, bw.bandwidth });
    }

    // t= (timing)
    try buf.print(allocator, "t={d} {d}\r\n", .{ desc.timing.start, desc.timing.stop });

    // a=* (session-level attributes)
    for (desc.attributes) |attr| {
        if (attr.value) |val| {
            try buf.print(allocator, "a={s}:{s}\r\n", .{ attr.name, val });
        } else {
            try buf.print(allocator, "a={s}\r\n", .{attr.name});
        }
    }

    // m= sections (media descriptions)
    for (desc.media) |media| {
        // m= line
        try buf.print(allocator, "m={s} {d}", .{ media.media_type, media.port });
        if (media.num_ports) |np| {
            try buf.print(allocator, "/{d}", .{np});
        }
        try buf.print(allocator, " {s}", .{media.proto});
        for (media.formats) |fmt| {
            try buf.print(allocator, " {s}", .{fmt});
        }
        try buf.appendSlice(allocator, "\r\n");

        // i=* (media title)
        if (media.info) |info| {
            try buf.print(allocator, "i={s}\r\n", .{info});
        }

        // c=* (media-level connection)
        if (media.connection) |conn| {
            try buf.print(allocator, "c={s} {s} {s}\r\n", .{ conn.net_type, conn.addr_type, conn.address });
        }

        // b=* (media-level bandwidth)
        for (media.bandwidths) |bw| {
            try buf.print(allocator, "b={s}:{d}\r\n", .{ bw.bw_type, bw.bandwidth });
        }

        // a=* (media-level attributes)
        for (media.attributes) |attr| {
            if (attr.value) |val| {
                try buf.print(allocator, "a={s}:{s}\r\n", .{ attr.name, val });
            } else {
                try buf.print(allocator, "a={s}\r\n", .{attr.name});
            }
        }
    }

    return buf.toOwnedSlice(allocator);
}
