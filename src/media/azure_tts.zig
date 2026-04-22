//! Azure Speech Services TTS client
//!
//! Synthesizes text to PCM audio (16kHz, 16-bit, mono) using the Azure
//! Cognitive Services Speech REST API.  The API key is expected in the
//! AZURE_SPEECH_KEY environment variable.
//!
//! Uses `curl` via `std.process.Child` for HTTP since std.http.Client
//! has limited Windows support in Zig 0.14/0.16.

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const AzureTtsError = error{
    MissingApiKey,
    SynthesisFailed,
    InvalidResponse,
    OutOfMemory,
    SsmlBuildFailed,
};

pub const AzureTtsClient = struct {
    api_key: []const u8,
    region: []const u8,

    /// Create a new Azure TTS client.
    pub fn init(api_key: []const u8, region: []const u8) AzureTtsClient {
        return .{
            .api_key = api_key,
            .region = region,
        };
    }

    /// Build the SSML payload for a given text string.
    /// Returns an owned slice; caller must free with `allocator.free()`.
    pub fn buildSsml(allocator: Allocator, text: []const u8) ![]u8 {
        var buf: std.ArrayList(u8) = .empty;
        errdefer buf.deinit(allocator);

        try buf.appendSlice(allocator, "<speak version='1.0' xml:lang='en-US'><voice name='en-US-JennyNeural'>");
        try buf.appendSlice(allocator, text);
        try buf.appendSlice(allocator, "</voice></speak>");

        return buf.toOwnedSlice(allocator);
    }

    /// Parse raw PCM bytes (little-endian 16-bit) into i16 samples.
    /// Returns an owned slice; caller must free with `allocator.free()`.
    pub fn parsePcmResponse(allocator: Allocator, raw: []const u8) ![]i16 {
        if (raw.len < 2 or raw.len % 2 != 0) return AzureTtsError.InvalidResponse;

        const sample_count = raw.len / 2;
        const samples = try allocator.alloc(i16, sample_count);
        errdefer allocator.free(samples);

        for (0..sample_count) |i| {
            const lo: u16 = raw[i * 2];
            const hi: u16 = raw[i * 2 + 1];
            samples[i] = @bitCast(lo | (hi << 8));
        }
        return samples;
    }

    /// Synthesize text to PCM audio (16kHz, 16-bit, mono).
    /// Returns owned PCM samples; caller must free with `allocator.free()`.
    ///
    /// Shells out to `curl` for the HTTP POST to Azure Speech Services.
    pub fn synthesize(self: *const AzureTtsClient, allocator: Allocator, text: []const u8) ![]i16 {
        const ssml = buildSsml(allocator, text) catch return AzureTtsError.SsmlBuildFailed;
        defer allocator.free(ssml);

        const url = std.fmt.allocPrint(allocator, "https://{s}.tts.speech.microsoft.com/cognitiveservices/v1", .{self.region}) catch
            return AzureTtsError.OutOfMemory;
        defer allocator.free(url);

        const key_header = std.fmt.allocPrint(allocator, "Ocp-Apim-Subscription-Key: {s}", .{self.api_key}) catch
            return AzureTtsError.OutOfMemory;
        defer allocator.free(key_header);

        var child = std.process.Child.init(
            &.{
                "curl",
                "--silent",
                "--show-error",
                "--fail",
                "-X",
                "POST",
                url,
                "-H",
                key_header,
                "-H",
                "Content-Type: application/ssml+xml",
                "-H",
                "X-Microsoft-OutputFormat: raw-16khz-16bit-mono-pcm",
                "--data-raw",
                ssml,
                "--output",
                "-",
            },
            allocator,
        );
        child.stdout_behavior = .pipe;
        child.stderr_behavior = .pipe;

        try child.spawn();

        const max_response = 10 * 1024 * 1024; // 10 MB
        const stdout = child.stdout.?.reader().readAllAlloc(allocator, max_response) catch
            return AzureTtsError.SynthesisFailed;
        defer allocator.free(stdout);

        const result = child.wait() catch return AzureTtsError.SynthesisFailed;
        if (result.Exited != 0) return AzureTtsError.SynthesisFailed;

        return parsePcmResponse(allocator, stdout);
    }
};

// ── Tests ──────────────────────────────────────────────────────────────

const testing = std.testing;

test "AzureTTS: buildSsml generates correct SSML" {
    const ssml = try AzureTtsClient.buildSsml(testing.allocator, "Hello world");
    defer testing.allocator.free(ssml);

    try testing.expectEqualStrings(
        "<speak version='1.0' xml:lang='en-US'><voice name='en-US-JennyNeural'>Hello world</voice></speak>",
        ssml,
    );
}

test "AzureTTS: buildSsml with empty text" {
    const ssml = try AzureTtsClient.buildSsml(testing.allocator, "");
    defer testing.allocator.free(ssml);

    try testing.expectEqualStrings(
        "<speak version='1.0' xml:lang='en-US'><voice name='en-US-JennyNeural'></voice></speak>",
        ssml,
    );
}

test "AzureTTS: parsePcmResponse decodes little-endian 16-bit samples" {
    // 0x0100 = 256, 0xFF7F = 32767, 0x0080 = -32768 (as i16)
    const raw = [_]u8{ 0x00, 0x01, 0xFF, 0x7F, 0x00, 0x80 };
    const samples = try AzureTtsClient.parsePcmResponse(testing.allocator, &raw);
    defer testing.allocator.free(samples);

    try testing.expectEqual(@as(usize, 3), samples.len);
    try testing.expectEqual(@as(i16, 256), samples[0]);
    try testing.expectEqual(@as(i16, 32767), samples[1]);
    try testing.expectEqual(@as(i16, -32768), samples[2]);
}

test "AzureTTS: parsePcmResponse rejects odd-length input" {
    const raw = [_]u8{ 0x00, 0x01, 0xFF };
    const result = AzureTtsClient.parsePcmResponse(testing.allocator, &raw);
    try testing.expectError(AzureTtsError.InvalidResponse, result);
}

test "AzureTTS: parsePcmResponse rejects empty input" {
    const result = AzureTtsClient.parsePcmResponse(testing.allocator, &.{});
    try testing.expectError(AzureTtsError.InvalidResponse, result);
}

test "AzureTTS: init stores api_key and region" {
    const client = AzureTtsClient.init("test-key-123", "eastus2");
    try testing.expectEqualStrings("test-key-123", client.api_key);
    try testing.expectEqualStrings("eastus2", client.region);
}
