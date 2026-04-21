//! DTLS wrapper over OpenSSL (RFC 6347)
//! Generated using structured RFC rules from the RFC Compliance API.

const std = @import("std");

const c = @cImport({
    @cInclude("openssl/ssl.h");
    @cInclude("openssl/err.h");
});

test "module compiles" {
    // Placeholder — will be replaced by generated tests
}

test "OpenSSL is available" {
    const method = c.DTLS_method();
    try std.testing.expect(method != null);

    const ctx = c.SSL_CTX_new(method);
    try std.testing.expect(ctx != null);
    c.SSL_CTX_free(ctx);
}
