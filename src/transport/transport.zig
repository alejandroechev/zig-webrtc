//! UDP transport layer
//! The bottom of the WebRTC protocol stack — provides raw UDP send/recv
//! for STUN, DTLS, and SRTP packets over a single multiplexed socket.

const std = @import("std");

// Use C winsock2 API directly (link_libc is enabled in build.zig)
const c = @cImport({
    @cInclude("winsock2.h");
    @cInclude("ws2tcpip.h");
});

// ============================================================================
// Errors
// ============================================================================

pub const TransportError = error{
    SocketCreationFailed,
    BindFailed,
    SendFailed,
    RecvFailed,
    SocketClosed,
    WsaStartupFailed,
};

// ============================================================================
// Address helper
// ============================================================================

/// IPv4 socket address wrapper.
pub const Ipv4Address = struct {
    addr: c.struct_sockaddr_in,

    /// Create an IPv4 address from octets and port (host byte order).
    pub fn init(octets: [4]u8, port: u16) Ipv4Address {
        var sa: c.struct_sockaddr_in = std.mem.zeroes(c.struct_sockaddr_in);
        sa.sin_family = c.AF_INET;
        sa.sin_port = std.mem.nativeToBig(u16, port);
        sa.sin_addr.S_un.S_addr = @bitCast(octets);
        return .{ .addr = sa };
    }

    pub fn getPort(self: Ipv4Address) u16 {
        return std.mem.bigToNative(u16, self.addr.sin_port);
    }
};

// ============================================================================
// Recv result
// ============================================================================

pub const RecvResult = struct {
    len: usize,
    src_addr: c.struct_sockaddr_in,
};

// ============================================================================
// UdpTransport
// ============================================================================

/// A UDP socket for sending and receiving datagrams.
/// In WebRTC, a single UDP port is multiplexed for STUN, DTLS, and
/// SRTP/SRTCP packets (demuxed by first-byte ranges per RFC 5764 §5.1.2).
pub const UdpTransport = struct {
    socket: c.SOCKET,
    local_addr: Ipv4Address,
    is_closed: bool,

    /// Ensure Winsock is initialized (idempotent).
    fn ensureWsa() !void {
        var wsa: c.WSADATA = undefined;
        const rc = c.WSAStartup(0x0202, &wsa);
        if (rc != 0) return TransportError.WsaStartupFailed;
    }

    /// Create and bind a UDP socket to the given local IPv4 address.
    pub fn init(bind_addr: Ipv4Address) !UdpTransport {
        try ensureWsa();

        const sock = c.socket(c.AF_INET, c.SOCK_DGRAM, c.IPPROTO_UDP);
        if (sock == c.INVALID_SOCKET) return TransportError.SocketCreationFailed;
        errdefer _ = c.closesocket(sock);

        // Allow address reuse
        const enable: c_int = 1;
        _ = c.setsockopt(sock, c.SOL_SOCKET, c.SO_REUSEADDR, @ptrCast(&enable), @sizeOf(c_int));

        const rc = c.bind(sock, @ptrCast(&bind_addr.addr), @sizeOf(c.struct_sockaddr_in));
        if (rc != 0) return TransportError.BindFailed;

        // Query the actual bound address (useful when binding to port 0)
        var actual = bind_addr.addr;
        var addr_len: c_int = @sizeOf(c.struct_sockaddr_in);
        _ = c.getsockname(sock, @ptrCast(&actual), &addr_len);

        return .{
            .socket = sock,
            .local_addr = .{ .addr = actual },
            .is_closed = false,
        };
    }

    /// Send a datagram to the destination address.
    pub fn send(self: *UdpTransport, data: []const u8, dest: Ipv4Address) !usize {
        if (self.is_closed) return TransportError.SocketClosed;
        const rc = c.sendto(
            self.socket,
            @ptrCast(data.ptr),
            @intCast(data.len),
            0,
            @ptrCast(&dest.addr),
            @sizeOf(c.struct_sockaddr_in),
        );
        if (rc == c.SOCKET_ERROR) return TransportError.SendFailed;
        return @intCast(rc);
    }

    /// Receive a datagram into the provided buffer.
    pub fn recv(self: *UdpTransport, buf: []u8) !RecvResult {
        if (self.is_closed) return TransportError.SocketClosed;
        var src_addr: c.struct_sockaddr_in = std.mem.zeroes(c.struct_sockaddr_in);
        var addr_len: c_int = @sizeOf(c.struct_sockaddr_in);
        const rc = c.recvfrom(
            self.socket,
            @ptrCast(buf.ptr),
            @intCast(buf.len),
            0,
            @ptrCast(&src_addr),
            &addr_len,
        );
        if (rc == c.SOCKET_ERROR) return TransportError.RecvFailed;
        return .{
            .len = @intCast(rc),
            .src_addr = src_addr,
        };
    }

    /// Close the underlying socket. Safe to call multiple times.
    pub fn close(self: *UdpTransport) void {
        if (!self.is_closed) {
            _ = c.closesocket(self.socket);
            self.is_closed = true;
        }
    }
};

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "UdpTransport: init binds socket and close is idempotent" {
    const addr = Ipv4Address.init(.{ 127, 0, 0, 1 }, 0);
    var t = try UdpTransport.init(addr);
    defer t.close();

    try testing.expect(t.local_addr.getPort() != 0);
    try testing.expect(!t.is_closed);

    t.close();
    try testing.expect(t.is_closed);

    // Double-close should not crash
    t.close();
}

test "UdpTransport: loopback send and recv" {
    const addr = Ipv4Address.init(.{ 127, 0, 0, 1 }, 0);
    var sender = try UdpTransport.init(addr);
    defer sender.close();
    var receiver = try UdpTransport.init(addr);
    defer receiver.close();

    const msg = "hello webrtc";
    _ = try sender.send(msg, receiver.local_addr);

    var buf: [256]u8 = undefined;
    const result = try receiver.recv(&buf);
    try testing.expectEqualStrings(msg, buf[0..result.len]);
}

test "UdpTransport: send/recv on closed socket returns error" {
    const addr = Ipv4Address.init(.{ 127, 0, 0, 1 }, 0);
    var t = try UdpTransport.init(addr);
    t.close();

    var buf: [64]u8 = undefined;
    try testing.expectError(TransportError.SocketClosed, t.send("x", addr));
    try testing.expectError(TransportError.SocketClosed, t.recv(&buf));
}
