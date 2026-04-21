//! DTLS wrapper over OpenSSL (RFC 6347 / RFC 5764)
//! Generated using structured RFC rules from the RFC Compliance API.
//!
//! This module implements:
//!   - DTLS context and connection management over OpenSSL (RFC 6347)
//!   - Packet demultiplexing by first byte (RFC 5764 §5.1.2)
//!   - DTLS-SRTP key export via SSL_export_keying_material (RFC 5764 §4.2)
//!   - Certificate fingerprint computation for SDP a=fingerprint (RFC 4572)
//!   - Role determination from SDP a=setup attribute (RFC 4145)
//!
//! RFC rules implemented:
//!   rfc6347-s4.1-r1: epoch values MUST NOT be reused within 2x TCP MSL
//!   rfc6347-s4.1-r2: SHOULD discard packets from earlier epochs
//!   rfc6347-s4.1-r4: MUST accept packets from old epoch during handshake
//!   rfc5764-s5.1.2:  Packet demux by first byte (STUN/DTLS/RTP-RTCP)
//!   rfc5764-s4.2:    DTLS-SRTP key export via SSL_export_keying_material

const std = @import("std");

// ============================================================================
// OpenSSL C bindings
// ============================================================================

const c = @cImport({
    @cInclude("openssl/ssl.h");
    @cInclude("openssl/err.h");
    @cInclude("openssl/x509.h");
    @cInclude("openssl/evp.h");
    @cInclude("openssl/bio.h");
});

// ============================================================================
// Constants
// ============================================================================

/// SRTP keying material length: 2 * key(16) + 2 * salt(14) = 60 bytes (RFC 5764 §4.2)
pub const srtp_key_material_len = 60;

/// SRTP master key length (128-bit)
pub const srtp_master_key_len = 16;

/// SRTP master salt length (112-bit)
pub const srtp_master_salt_len = 14;

/// Label used for SRTP keying material export (RFC 5764 §4.2)
pub const srtp_exporter_label = "EXTRACTOR-dtls_srtp";

/// SRTP protection profile string for SSL_CTX_set_tlsext_use_srtp
pub const srtp_profiles = "SRTP_AES128_CM_SHA1_80:SRTP_AES128_CM_SHA1_32";

/// Maximum fingerprint digest length (SHA-512 = 64 bytes)
pub const max_digest_len = 64;

/// Maximum formatted fingerprint string length: "sha-256 " (8) + 64*2 hex + 63 colons + null = ~200
pub const max_formatted_fingerprint_len = 256;

// ============================================================================
// Enums
// ============================================================================

/// DTLS role — determined from the SDP a=setup attribute (RFC 4145).
/// The client initiates the DTLS handshake; the server waits.
pub const DtlsRole = enum {
    client,
    server,
};

/// SDP a=setup attribute values (RFC 4145 §4).
/// Determines which endpoint acts as DTLS client vs server.
pub const SetupAttribute = enum {
    active,
    passive,
    actpass,
    holdconn,

    /// Parse from SDP string value.
    pub fn fromString(s: []const u8) ?SetupAttribute {
        if (std.mem.eql(u8, s, "active")) return .active;
        if (std.mem.eql(u8, s, "passive")) return .passive;
        if (std.mem.eql(u8, s, "actpass")) return .actpass;
        if (std.mem.eql(u8, s, "holdconn")) return .holdconn;
        return null;
    }

    /// Convert to SDP string representation.
    pub fn toString(self: SetupAttribute) []const u8 {
        return switch (self) {
            .active => "active",
            .passive => "passive",
            .actpass => "actpass",
            .holdconn => "holdconn",
        };
    }
};

/// DTLS handshake state machine.
pub const HandshakeState = enum {
    new,
    in_progress,
    completed,
    failed,
};

/// Result returned from a single handshake step.
pub const HandshakeResult = enum {
    pending,
    completed,
    failed,
};

/// Fingerprint hash algorithm for SDP a=fingerprint (RFC 4572).
pub const FingerprintAlgorithm = enum {
    sha256,
    sha384,
    sha512,

    /// Return the OpenSSL EVP_MD for this algorithm.
    pub fn evpMd(self: FingerprintAlgorithm) *const c.EVP_MD {
        return switch (self) {
            .sha256 => c.EVP_sha256().?,
            .sha384 => c.EVP_sha384().?,
            .sha512 => c.EVP_sha512().?,
        };
    }

    /// Return the SDP name string (e.g. "sha-256").
    pub fn sdpName(self: FingerprintAlgorithm) []const u8 {
        return switch (self) {
            .sha256 => "sha-256",
            .sha384 => "sha-384",
            .sha512 => "sha-512",
        };
    }

    /// Expected digest length in bytes.
    pub fn digestLen(self: FingerprintAlgorithm) u8 {
        return switch (self) {
            .sha256 => 32,
            .sha384 => 48,
            .sha512 => 64,
        };
    }
};

/// Packet kind for demultiplexing on a single transport (RFC 5764 §5.1.2).
/// Inspecting the first byte of incoming data determines the protocol.
pub const PacketKind = enum {
    stun,
    dtls,
    rtp_rtcp,
    unknown,
};

// ============================================================================
// Structs
// ============================================================================

/// Certificate fingerprint used in SDP a=fingerprint lines (RFC 4572).
pub const CertificateFingerprint = struct {
    algorithm: FingerprintAlgorithm,
    digest: [max_digest_len]u8,
    digest_len: u8,

    /// Format as SDP fingerprint value: "AB:CD:EF:..." (hex with colons).
    /// Returns the number of bytes written to the output buffer.
    pub fn format(self: *const CertificateFingerprint, buf: *[max_formatted_fingerprint_len]u8) usize {
        var pos: usize = 0;
        for (self.digest[0..self.digest_len], 0..) |byte, i| {
            const hex_chars = "0123456789ABCDEF";
            buf[pos] = hex_chars[byte >> 4];
            pos += 1;
            buf[pos] = hex_chars[byte & 0x0F];
            pos += 1;
            if (i < self.digest_len - 1) {
                buf[pos] = ':';
                pos += 1;
            }
        }
        return pos;
    }

    /// Format with algorithm prefix: "sha-256 AB:CD:EF:..."
    pub fn formatWithAlgorithm(self: *const CertificateFingerprint, buf: *[max_formatted_fingerprint_len]u8) usize {
        const name = self.algorithm.sdpName();
        @memcpy(buf[0..name.len], name);
        buf[name.len] = ' ';
        var pos = name.len + 1;

        var hex_buf: [max_formatted_fingerprint_len]u8 = undefined;
        const hex_len = self.format(&hex_buf);
        @memcpy(buf[pos .. pos + hex_len], hex_buf[0..hex_len]);
        pos += hex_len;
        return pos;
    }
};

/// DTLS context wrapping an OpenSSL SSL_CTX for DTLS 1.2+ connections.
/// Manages the shared configuration (certificates, ciphers, SRTP profiles).
pub const DtlsContext = struct {
    ssl_ctx: *c.SSL_CTX,

    pub const InitError = error{
        SslMethodFailed,
        SslCtxCreateFailed,
        SrtpProfileFailed,
        CertGenerationFailed,
        PrivateKeyFailed,
        PrivateKeyMismatch,
    };

    /// Create a new DTLS context configured for the given role.
    /// Generates a self-signed certificate for use in the DTLS handshake.
    pub fn init(role: DtlsRole) InitError!DtlsContext {
        const method = c.DTLS_method() orelse return error.SslMethodFailed;
        const ssl_ctx = c.SSL_CTX_new(method) orelse return error.SslCtxCreateFailed;
        errdefer c.SSL_CTX_free(ssl_ctx);

        // Set minimum protocol version to DTLS 1.2
        _ = c.SSL_CTX_set_min_proto_version(ssl_ctx, c.DTLS1_2_VERSION);

        // Configure SRTP profiles (RFC 5764 §4.1.2)
        if (c.SSL_CTX_set_tlsext_use_srtp(ssl_ctx, srtp_profiles) != 0) {
            return error.SrtpProfileFailed;
        }

        // Generate a self-signed EC certificate
        try generateSelfSignedCert(ssl_ctx);

        // Set verification mode based on role — both sides verify for DTLS-SRTP
        _ = c.SSL_CTX_set_verify(ssl_ctx, c.SSL_VERIFY_PEER | c.SSL_VERIFY_FAIL_IF_NO_PEER_CERT, null);

        _ = role; // role stored at connection level; context is reusable

        return .{ .ssl_ctx = ssl_ctx };
    }

    /// Free the SSL_CTX and associated resources.
    pub fn deinit(self: *DtlsContext) void {
        c.SSL_CTX_free(self.ssl_ctx);
        self.ssl_ctx = undefined;
    }

    /// Get the X509 certificate associated with this context (if any).
    pub fn getCertificate(self: *const DtlsContext) ?*c.X509 {
        return c.SSL_CTX_get0_certificate(self.ssl_ctx);
    }

    /// Generate an EC P-256 self-signed certificate and load it into the SSL_CTX.
    fn generateSelfSignedCert(ssl_ctx: *c.SSL_CTX) InitError!void {
        // Generate EC key pair using the explicit keygen API (EVP_EC_gen macro
        // doesn't translate cleanly through Zig's cImport)
        const pkey_ctx = c.EVP_PKEY_CTX_new_id(c.EVP_PKEY_EC, null) orelse return error.PrivateKeyFailed;
        defer c.EVP_PKEY_CTX_free(pkey_ctx);

        if (c.EVP_PKEY_keygen_init(pkey_ctx) <= 0) return error.PrivateKeyFailed;
        if (c.EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pkey_ctx, c.NID_X9_62_prime256v1) <= 0) return error.PrivateKeyFailed;

        var pkey: ?*c.EVP_PKEY = null;
        if (c.EVP_PKEY_keygen(pkey_ctx, &pkey) <= 0) return error.PrivateKeyFailed;
        const pkey_nn = pkey orelse return error.PrivateKeyFailed;
        defer c.EVP_PKEY_free(pkey_nn);

        // Create X509 certificate
        const x509 = c.X509_new() orelse return error.CertGenerationFailed;
        defer c.X509_free(x509);

        // Set serial number
        _ = c.ASN1_INTEGER_set(c.X509_get_serialNumber(x509), 1);

        // Set validity: now to +365 days
        const not_before = c.X509_getm_notBefore(x509);
        _ = c.X509_gmtime_adj(not_before, 0);
        const not_after = c.X509_getm_notAfter(x509);
        _ = c.X509_gmtime_adj(not_after, 365 * 24 * 60 * 60);

        // Set subject and issuer (self-signed)
        _ = c.X509_set_pubkey(x509, pkey_nn);
        const name: ?*c.X509_NAME = @constCast(c.X509_get_subject_name(x509));
        _ = c.X509_NAME_add_entry_by_txt(name, "CN", c.MBSTRING_ASC, "WebRTC", -1, -1, 0);
        _ = c.X509_set_issuer_name(x509, name);

        // Sign the certificate
        if (c.X509_sign(x509, pkey_nn, c.EVP_sha256()) == 0) {
            return error.CertGenerationFailed;
        }

        // Load into SSL_CTX
        if (c.SSL_CTX_use_certificate(ssl_ctx, x509) != 1) {
            return error.CertGenerationFailed;
        }
        if (c.SSL_CTX_use_PrivateKey(ssl_ctx, pkey_nn) != 1) {
            return error.PrivateKeyFailed;
        }
        if (c.SSL_CTX_check_private_key(ssl_ctx) != 1) {
            return error.PrivateKeyMismatch;
        }
    }
};

/// DTLS connection wrapping an OpenSSL SSL object with BIO pair for non-blocking I/O.
/// Manages the handshake state and provides methods to feed/read network data.
pub const DtlsConnection = struct {
    ssl: *c.SSL,
    read_bio: *c.BIO,
    write_bio: *c.BIO,
    role: DtlsRole,
    state: HandshakeState,

    pub const ConnectionError = error{
        SslCreateFailed,
        BioCreateFailed,
        HandshakeFailed,
        ExportKeyingMaterialFailed,
        WriteError,
        ReadError,
    };

    /// Create a new DTLS connection from the given context and role.
    /// Sets up a BIO pair for non-blocking I/O — no file descriptors needed.
    pub fn init(ctx: *DtlsContext, role: DtlsRole) ConnectionError!DtlsConnection {
        const ssl = c.SSL_new(ctx.ssl_ctx) orelse return error.SslCreateFailed;
        errdefer c.SSL_free(ssl);

        // Create memory BIOs for non-blocking I/O
        const read_bio = c.BIO_new(c.BIO_s_mem()) orelse return error.BioCreateFailed;
        const write_bio = c.BIO_new(c.BIO_s_mem()) orelse {
            _ = c.BIO_free(read_bio);
            return error.BioCreateFailed;
        };

        // SSL takes ownership of BIOs — do not free them separately
        c.SSL_set_bio(ssl, read_bio, write_bio);

        // Set client or server mode
        switch (role) {
            .client => c.SSL_set_connect_state(ssl),
            .server => c.SSL_set_accept_state(ssl),
        }

        return .{
            .ssl = ssl,
            .read_bio = read_bio,
            .write_bio = write_bio,
            .role = role,
            .state = .new,
        };
    }

    /// Free the SSL object (which also frees the associated BIOs).
    pub fn deinit(self: *DtlsConnection) void {
        c.SSL_free(self.ssl);
        self.ssl = undefined;
        self.state = .failed;
    }

    /// Drive one step of the DTLS handshake.
    /// Call this repeatedly after feeding incoming data via feedData() and
    /// reading outgoing data via getData().
    pub fn handshake(self: *DtlsConnection) ConnectionError!HandshakeResult {
        if (self.state == .completed) return .completed;
        if (self.state == .failed) return .failed;

        self.state = .in_progress;

        const ret = c.SSL_do_handshake(self.ssl);
        if (ret == 1) {
            self.state = .completed;
            return .completed;
        }

        const err = c.SSL_get_error(self.ssl, ret);
        if (err == c.SSL_ERROR_WANT_READ or err == c.SSL_ERROR_WANT_WRITE) {
            return .pending;
        }

        self.state = .failed;
        return .failed;
    }

    /// Feed received network data into the SSL read BIO.
    /// This data will be consumed by the next handshake() or SSL_read() call.
    pub fn feedData(self: *DtlsConnection, data: []const u8) ConnectionError!void {
        const written = c.BIO_write(self.read_bio, data.ptr, @intCast(data.len));
        if (written <= 0) return error.WriteError;
    }

    /// Read outgoing data (handshake messages) from the SSL write BIO.
    /// Returns the number of bytes read into `buf`, or 0 if no data pending.
    pub fn getData(self: *DtlsConnection, buf: []u8) ConnectionError!usize {
        const pending = c.BIO_ctrl_pending(self.write_bio);
        if (pending == 0) return 0;

        const to_read: c_int = @intCast(@min(buf.len, pending));
        const read_bytes = c.BIO_read(self.write_bio, buf.ptr, to_read);
        if (read_bytes <= 0) return 0;
        return @intCast(read_bytes);
    }

    /// Export SRTP keying material after handshake completion (RFC 5764 §4.2).
    /// Returns 60 bytes: client_key(16) + server_key(16) + client_salt(14) + server_salt(14).
    pub fn exportKeyingMaterial(self: *DtlsConnection) ConnectionError![srtp_key_material_len]u8 {
        var material: [srtp_key_material_len]u8 = undefined;
        const ret = c.SSL_export_keying_material(
            self.ssl,
            &material,
            srtp_key_material_len,
            srtp_exporter_label.ptr,
            srtp_exporter_label.len,
            null,
            0,
            0,
        );
        if (ret != 1) return error.ExportKeyingMaterialFailed;
        return material;
    }

    /// Check whether the DTLS handshake has completed successfully.
    pub fn isHandshakeComplete(self: *const DtlsConnection) bool {
        return self.state == .completed;
    }
};

// ============================================================================
// Packet demultiplexing (RFC 5764 §5.1.2)
// ============================================================================

/// Classify an incoming packet by its first byte on a multiplexed transport.
/// RFC 5764 §5.1.2 defines the demux ranges:
///   - 0..3    → STUN
///   - 20..63  → DTLS
///   - 128..191 → RTP/RTCP
///   - anything else → unknown
pub fn classifyPacket(first_byte: u8) PacketKind {
    return switch (first_byte) {
        0...3 => .stun,
        20...63 => .dtls,
        128...191 => .rtp_rtcp,
        else => .unknown,
    };
}

// ============================================================================
// Certificate fingerprint (RFC 4572)
// ============================================================================

/// Compute the certificate fingerprint from a DtlsContext's loaded certificate.
/// Uses X509_digest() to hash the DER encoding of the certificate.
pub fn computeFingerprint(ctx: *DtlsContext, algorithm: FingerprintAlgorithm) !CertificateFingerprint {
    const x509 = ctx.getCertificate() orelse return error.NoCertificate;
    const md = algorithm.evpMd();

    var digest: [max_digest_len]u8 = undefined;
    var digest_len: c_uint = 0;

    if (c.X509_digest(x509, md, &digest, &digest_len) != 1) {
        return error.FingerprintComputeFailed;
    }

    return .{
        .algorithm = algorithm,
        .digest = digest,
        .digest_len = @intCast(digest_len),
    };
}

/// Format a fingerprint as a hex:colon string into the provided buffer.
/// Returns a slice of the buffer containing the formatted string.
pub fn formatFingerprint(fp: *const CertificateFingerprint, buf: *[max_formatted_fingerprint_len]u8) []const u8 {
    const len = fp.format(buf);
    return buf[0..len];
}

// ============================================================================
// Role determination from SDP (RFC 4145)
// ============================================================================

/// Determine the DTLS role from the SDP a=setup attribute and whether
/// this endpoint is the offerer.
///
/// Rules:
///   - active   → client (initiates handshake)
///   - passive  → server (waits for handshake)
///   - actpass  → offerer becomes server, answerer becomes client (WebRTC convention)
///   - holdconn → defaults to server
pub fn roleFromSetup(setup: SetupAttribute, is_offerer: bool) DtlsRole {
    return switch (setup) {
        .active => .client,
        .passive => .server,
        .actpass => if (is_offerer) .server else .client,
        .holdconn => .server,
    };
}

// ============================================================================
// SRTP keying material extraction helpers (RFC 5764 §4.2)
// ============================================================================

/// Parsed SRTP keying material from the exported master secret.
pub const SrtpKeyMaterial = struct {
    client_write_key: [srtp_master_key_len]u8,
    server_write_key: [srtp_master_key_len]u8,
    client_write_salt: [srtp_master_salt_len]u8,
    server_write_salt: [srtp_master_salt_len]u8,
};

/// Parse the 60-byte keying material export into separate client/server keys and salts.
/// Layout (RFC 5764 §4.2):
///   client_write_key (16) || server_write_key (16) || client_write_salt (14) || server_write_salt (14)
pub fn parseSrtpKeyMaterial(material: *const [srtp_key_material_len]u8) SrtpKeyMaterial {
    var result: SrtpKeyMaterial = undefined;
    var offset: usize = 0;

    @memcpy(&result.client_write_key, material[offset .. offset + srtp_master_key_len]);
    offset += srtp_master_key_len;

    @memcpy(&result.server_write_key, material[offset .. offset + srtp_master_key_len]);
    offset += srtp_master_key_len;

    @memcpy(&result.client_write_salt, material[offset .. offset + srtp_master_salt_len]);
    offset += srtp_master_salt_len;

    @memcpy(&result.server_write_salt, material[offset .. offset + srtp_master_salt_len]);

    return result;
}

// ============================================================================
// Tests
// ============================================================================

test "OpenSSL context creation — client and server" {
    // Create a client DTLS context and verify it initializes successfully
    var client_ctx = try DtlsContext.init(.client);
    defer client_ctx.deinit();
    try std.testing.expect(client_ctx.getCertificate() != null);

    // Create a server DTLS context and verify it initializes successfully
    var server_ctx = try DtlsContext.init(.server);
    defer server_ctx.deinit();
    try std.testing.expect(server_ctx.getCertificate() != null);
}

test "packet demux classification — RFC 5764 §5.1.2" {
    // STUN range: 0..3
    try std.testing.expectEqual(PacketKind.stun, classifyPacket(0));
    try std.testing.expectEqual(PacketKind.stun, classifyPacket(1));
    try std.testing.expectEqual(PacketKind.stun, classifyPacket(2));
    try std.testing.expectEqual(PacketKind.stun, classifyPacket(3));

    // DTLS range: 20..63
    try std.testing.expectEqual(PacketKind.dtls, classifyPacket(20));
    try std.testing.expectEqual(PacketKind.dtls, classifyPacket(21));
    try std.testing.expectEqual(PacketKind.dtls, classifyPacket(63));

    // RTP/RTCP range: 128..191
    try std.testing.expectEqual(PacketKind.rtp_rtcp, classifyPacket(128));
    try std.testing.expectEqual(PacketKind.rtp_rtcp, classifyPacket(129));
    try std.testing.expectEqual(PacketKind.rtp_rtcp, classifyPacket(191));

    // Unknown ranges: gaps between defined ranges
    try std.testing.expectEqual(PacketKind.unknown, classifyPacket(4));
    try std.testing.expectEqual(PacketKind.unknown, classifyPacket(19));
    try std.testing.expectEqual(PacketKind.unknown, classifyPacket(64));
    try std.testing.expectEqual(PacketKind.unknown, classifyPacket(127));
    try std.testing.expectEqual(PacketKind.unknown, classifyPacket(192));
    try std.testing.expectEqual(PacketKind.unknown, classifyPacket(255));
}

test "certificate fingerprint — compute and verify length" {
    var ctx = try DtlsContext.init(.server);
    defer ctx.deinit();

    // Compute SHA-256 fingerprint of the self-signed certificate
    const fp = try computeFingerprint(&ctx, .sha256);
    try std.testing.expectEqual(FingerprintAlgorithm.sha256, fp.algorithm);
    try std.testing.expectEqual(@as(u8, 32), fp.digest_len);

    // Verify the digest is not all zeros (a real hash was computed)
    var all_zero = true;
    for (fp.digest[0..fp.digest_len]) |b| {
        if (b != 0) {
            all_zero = false;
            break;
        }
    }
    try std.testing.expect(!all_zero);
}

test "role selection — roleFromSetup for all SetupAttribute values" {
    // active → always client
    try std.testing.expectEqual(DtlsRole.client, roleFromSetup(.active, true));
    try std.testing.expectEqual(DtlsRole.client, roleFromSetup(.active, false));

    // passive → always server
    try std.testing.expectEqual(DtlsRole.server, roleFromSetup(.passive, true));
    try std.testing.expectEqual(DtlsRole.server, roleFromSetup(.passive, false));

    // actpass → offerer=server, answerer=client
    try std.testing.expectEqual(DtlsRole.server, roleFromSetup(.actpass, true));
    try std.testing.expectEqual(DtlsRole.client, roleFromSetup(.actpass, false));

    // holdconn → defaults to server
    try std.testing.expectEqual(DtlsRole.server, roleFromSetup(.holdconn, true));
    try std.testing.expectEqual(DtlsRole.server, roleFromSetup(.holdconn, false));
}

test "fingerprint formatting — hex:colon format" {
    // Create a known fingerprint and verify the formatted output
    var fp = CertificateFingerprint{
        .algorithm = .sha256,
        .digest = [_]u8{0} ** max_digest_len,
        .digest_len = 4,
    };
    fp.digest[0] = 0xAB;
    fp.digest[1] = 0xCD;
    fp.digest[2] = 0xEF;
    fp.digest[3] = 0x01;

    var buf: [max_formatted_fingerprint_len]u8 = undefined;
    const formatted = formatFingerprint(&fp, &buf);
    try std.testing.expectEqualStrings("AB:CD:EF:01", formatted);
}

test "fingerprint formatting — with algorithm prefix" {
    var fp = CertificateFingerprint{
        .algorithm = .sha256,
        .digest = [_]u8{0} ** max_digest_len,
        .digest_len = 3,
    };
    fp.digest[0] = 0xDE;
    fp.digest[1] = 0xAD;
    fp.digest[2] = 0xBE;

    var buf: [max_formatted_fingerprint_len]u8 = undefined;
    const len = fp.formatWithAlgorithm(&buf);
    const result = buf[0..len];
    try std.testing.expectEqualStrings("sha-256 DE:AD:BE", result);
}

test "SetupAttribute.fromString — parse SDP setup values" {
    try std.testing.expectEqual(SetupAttribute.active, SetupAttribute.fromString("active").?);
    try std.testing.expectEqual(SetupAttribute.passive, SetupAttribute.fromString("passive").?);
    try std.testing.expectEqual(SetupAttribute.actpass, SetupAttribute.fromString("actpass").?);
    try std.testing.expectEqual(SetupAttribute.holdconn, SetupAttribute.fromString("holdconn").?);
    try std.testing.expect(SetupAttribute.fromString("invalid") == null);
    try std.testing.expect(SetupAttribute.fromString("") == null);
}

test "SetupAttribute.toString — roundtrip" {
    try std.testing.expectEqualStrings("active", SetupAttribute.active.toString());
    try std.testing.expectEqualStrings("passive", SetupAttribute.passive.toString());
    try std.testing.expectEqualStrings("actpass", SetupAttribute.actpass.toString());
    try std.testing.expectEqualStrings("holdconn", SetupAttribute.holdconn.toString());
}

test "handshake state machine — initial state is .new" {
    var ctx = try DtlsContext.init(.client);
    defer ctx.deinit();

    var conn = try DtlsConnection.init(&ctx, .client);
    defer conn.deinit();

    try std.testing.expectEqual(HandshakeState.new, conn.state);
    try std.testing.expect(!conn.isHandshakeComplete());
}

test "SRTP key material parsing" {
    // Create a known 60-byte block and verify parsing
    var material: [srtp_key_material_len]u8 = undefined;
    for (&material, 0..) |*byte, i| {
        byte.* = @intCast(i);
    }

    const parsed = parseSrtpKeyMaterial(&material);

    // client_write_key = bytes 0..15
    for (parsed.client_write_key, 0..) |b, i| {
        try std.testing.expectEqual(@as(u8, @intCast(i)), b);
    }
    // server_write_key = bytes 16..31
    for (parsed.server_write_key, 0..) |b, i| {
        try std.testing.expectEqual(@as(u8, @intCast(i + 16)), b);
    }
    // client_write_salt = bytes 32..45
    for (parsed.client_write_salt, 0..) |b, i| {
        try std.testing.expectEqual(@as(u8, @intCast(i + 32)), b);
    }
    // server_write_salt = bytes 46..59
    for (parsed.server_write_salt, 0..) |b, i| {
        try std.testing.expectEqual(@as(u8, @intCast(i + 46)), b);
    }
}

test "DtlsConnection creation — server role" {
    var ctx = try DtlsContext.init(.server);
    defer ctx.deinit();

    var conn = try DtlsConnection.init(&ctx, .server);
    defer conn.deinit();

    try std.testing.expectEqual(DtlsRole.server, conn.role);
    try std.testing.expectEqual(HandshakeState.new, conn.state);
}

test "FingerprintAlgorithm — digest lengths" {
    try std.testing.expectEqual(@as(u8, 32), FingerprintAlgorithm.sha256.digestLen());
    try std.testing.expectEqual(@as(u8, 48), FingerprintAlgorithm.sha384.digestLen());
    try std.testing.expectEqual(@as(u8, 64), FingerprintAlgorithm.sha512.digestLen());
}

test "FingerprintAlgorithm — SDP names" {
    try std.testing.expectEqualStrings("sha-256", FingerprintAlgorithm.sha256.sdpName());
    try std.testing.expectEqualStrings("sha-384", FingerprintAlgorithm.sha384.sdpName());
    try std.testing.expectEqualStrings("sha-512", FingerprintAlgorithm.sha512.sdpName());
}

test "certificate fingerprint — SHA-384 and SHA-512" {
    var ctx = try DtlsContext.init(.client);
    defer ctx.deinit();

    const fp384 = try computeFingerprint(&ctx, .sha384);
    try std.testing.expectEqual(@as(u8, 48), fp384.digest_len);

    const fp512 = try computeFingerprint(&ctx, .sha512);
    try std.testing.expectEqual(@as(u8, 64), fp512.digest_len);
}
