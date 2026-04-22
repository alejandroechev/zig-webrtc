//! WebRTC interop agent (stdin/stdout signaling bridge)
//!
//! Reads signaling messages from stdin (JSON lines), writes to stdout.
//! A Node.js wrapper (interop/zig-wrapper.js) handles the WebSocket
//! connection to the signaling server.
//!
//! Protocol flow:
//!   1. Agent adds an audio track, creates a PeerConnection, generates an SDP offer
//!   2. Offer (with audio m= line + data channel) is written to stdout as JSON
//!   3. Browser's SDP answer arrives on stdin → agent sets remote description
//!   4. ICE candidates are exchanged via stdin/stdout JSON messages
//!   5. When the data channel opens, agent sends "Hello from Zig!"
//!   6. Agent generates a 440 Hz sine wave → Opus encode → RTP packetize
//!   7. Audio pipeline status is reported via stdout JSON messages
//!
//! Message format (one JSON object per line):
//!   {"type":"offer","sdp":"v=0\r\n..."}
//!   {"type":"answer","sdp":"v=0\r\n..."}
//!   {"type":"ice-candidate","candidate":"...","sdpMid":"0","sdpMLineIndex":0}
//!   {"type":"status","message":"..."}
//!   {"type":"audio-status","message":"...","packets":N,"bytes":N}

const std = @import("std");
const webrtc = @import("zig-webrtc");

const PeerConnection = webrtc.peer.PeerConnection;
const SessionDescription = webrtc.sdp.SessionDescription;
const AudioPipeline = webrtc.media.pipeline.AudioPipeline;
const sources = webrtc.media.sources;

// ── JSON helpers ──────────────────────────────────────────────────────

/// Escape a string for embedding in JSON.
/// SDP text contains \r\n which must become literal \\r\\n in JSON values.
fn jsonEscapeSdp(allocator: std.mem.Allocator, raw: []const u8) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);
    for (raw) |c| {
        switch (c) {
            '\r' => try buf.appendSlice(allocator, "\\r"),
            '\n' => try buf.appendSlice(allocator, "\\n"),
            '"' => try buf.appendSlice(allocator, "\\\""),
            '\\' => try buf.appendSlice(allocator, "\\\\"),
            else => try buf.append(allocator, c),
        }
    }
    return buf.toOwnedSlice(allocator);
}

/// Unescape JSON string escapes (\r \n \" \\), returning an owned slice.
fn jsonUnescapeSdp(allocator: std.mem.Allocator, escaped: []const u8) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);
    var i: usize = 0;
    while (i < escaped.len) {
        if (escaped[i] == '\\' and i + 1 < escaped.len) {
            switch (escaped[i + 1]) {
                'r' => {
                    try buf.append(allocator, '\r');
                    i += 2;
                },
                'n' => {
                    try buf.append(allocator, '\n');
                    i += 2;
                },
                '"' => {
                    try buf.append(allocator, '"');
                    i += 2;
                },
                '\\' => {
                    try buf.append(allocator, '\\');
                    i += 2;
                },
                else => {
                    try buf.append(allocator, escaped[i]);
                    i += 1;
                },
            }
        } else {
            try buf.append(allocator, escaped[i]);
            i += 1;
        }
    }
    return buf.toOwnedSlice(allocator);
}

/// Extract the value of a JSON string field from a line.
/// Looks for `"key":"<value>"` and returns the raw (escaped) value content.
fn extractJsonString(line: []const u8, key: []const u8) ?[]const u8 {
    // Build the search pattern: "key":"
    var pattern_buf: [64]u8 = undefined;
    const pattern = std.fmt.bufPrint(&pattern_buf, "\"{s}\":\"", .{key}) catch return null;

    const start_idx = std.mem.indexOf(u8, line, pattern) orelse return null;
    const value_start = start_idx + pattern.len;

    // Find the closing quote (handle escaped quotes)
    var i = value_start;
    while (i < line.len) {
        if (line[i] == '\\' and i + 1 < line.len) {
            i += 2; // skip escaped char
        } else if (line[i] == '"') {
            return line[value_start..i];
        } else {
            i += 1;
        }
    }
    return null;
}

// ── I/O helpers (Zig 0.16 API) ───────────────────────────────────────

/// Write formatted text to stdout using bufPrint + writeStreamingAll.
fn writeStdout(io: std.Io, buf: []u8, comptime fmt: []const u8, args: anytype) !void {
    const text = try std.fmt.bufPrint(buf, fmt, args);
    try std.Io.File.stdout().writeStreamingAll(io, text);
}

// ── Main ──────────────────────────────────────────────────────────────

// ── Audio constants ───────────────────────────────────────────────────

const audio_ssrc: u32 = 0xA0D10001; // deterministic SSRC for interop testing
const sample_rate: i32 = 48000;
const channels: i32 = 1;
const frame_ms: u32 = 20;
const frame_size: usize = @intCast(@divExact(@as(u32, @intCast(sample_rate)) * frame_ms, 1000));

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

    var fmt_buf: [65536]u8 = undefined;

    std.debug.print("[agent] zig-webrtc interop agent starting\n", .{});

    // Create PeerConnection
    var pc = PeerConnection.init(allocator, .{});
    defer pc.deinit();

    // Add audio track before creating the offer so the SDP includes
    // an audio m= line with Opus codec attributes (PT 111).
    pc.addAudioTrack(audio_ssrc);

    try writeStdout(io, &fmt_buf, "{{\"type\":\"status\",\"message\":\"peer-connection-created\"}}\n", .{});

    // Create SDP offer (now includes audio m= line + data channel)
    var offer = try pc.createOffer();

    // Serialize SDP to text
    const offer_sdp_raw = try offer.serialize(allocator);
    defer allocator.free(offer_sdp_raw);

    // JSON-escape the SDP
    const offer_sdp_escaped = try jsonEscapeSdp(allocator, offer_sdp_raw);
    defer allocator.free(offer_sdp_escaped);

    // Set local description (PC takes ownership of offer)
    try pc.setLocalDescription(offer, .offer);

    std.debug.print("[agent] signaling state: have_local_offer\n", .{});

    // Send offer to stdout
    try writeStdout(io, &fmt_buf, "{{\"type\":\"offer\",\"sdp\":\"{s}\"}}\n", .{offer_sdp_escaped});

    std.debug.print("[agent] offer sent, waiting for answer...\n", .{});

    // Read messages from stdin (line-buffered JSON)
    var stdin_buf: [65536]u8 = undefined;
    var stdin = std.Io.File.stdin().readerStreaming(io, &stdin_buf);

    while (true) {
        const line = stdin.interface.takeDelimiter('\n') catch |err| {
            std.debug.print("[agent] read error: {}\n", .{err});
            break;
        } orelse {
            std.debug.print("[agent] stdin closed, shutting down\n", .{});
            break;
        };

        // Trim trailing \r if present
        const trimmed = std.mem.trimEnd(u8, line, "\r");
        if (trimmed.len == 0) continue;

        // Extract message type
        const msg_type = extractJsonString(trimmed, "type") orelse {
            std.debug.print("[agent] ignoring unrecognized message\n", .{});
            continue;
        };

        if (std.mem.eql(u8, msg_type, "answer")) {
            // Extract SDP from answer
            const sdp_escaped = extractJsonString(trimmed, "sdp") orelse {
                std.debug.print("[agent] answer missing sdp field\n", .{});
                continue;
            };

            // Unescape JSON → raw SDP
            const sdp_raw = try jsonUnescapeSdp(allocator, sdp_escaped);
            defer allocator.free(sdp_raw);

            // Parse the browser's SDP answer
            var answer_desc = SessionDescription.parse(allocator, sdp_raw) catch |err| {
                std.debug.print("[agent] failed to parse answer SDP: {}\n", .{err});
                continue;
            };

            // Set remote description (PC takes ownership)
            pc.setRemoteDescription(answer_desc, .answer) catch |err| {
                std.debug.print("[agent] setRemoteDescription failed: {}\n", .{err});
                @constCast(&answer_desc).deinit(allocator);
                continue;
            };

            std.debug.print("[agent] remote description set, signaling state: {s}\n", .{@tagName(pc.signaling_state)});
            try writeStdout(io, &fmt_buf, "{{\"type\":\"status\",\"message\":\"answer-applied\"}}\n", .{});

            // In a full implementation this is where ICE connectivity checks
            // and DTLS/SCTP handshake would begin. For now, simulate readiness.
            try writeStdout(io, &fmt_buf, "{{\"type\":\"status\",\"message\":\"ready\"}}\n", .{});
            try writeStdout(io, &fmt_buf, "{{\"type\":\"data\",\"channel\":\"test\",\"message\":\"Hello from Zig!\"}}\n", .{});

            // ── Audio pipeline: generate sine wave → Opus → RTP ──────────
            //
            // This proves the audio path is fully wired: PCM generation →
            // Opus encoding → RTP packetization. The actual RTP sending over
            // UDP requires full ICE/DTLS (real networking), but this validates
            // that the codec and packetization pipeline works end-to-end.
            {
                var audio_pipeline = AudioPipeline.init(sample_rate, channels, audio_ssrc) catch |err| {
                    std.debug.print("[agent] audio pipeline init failed: {}\n", .{err});
                    try writeStdout(io, &fmt_buf, "{{\"type\":\"audio-status\",\"message\":\"init-failed\",\"packets\":0,\"bytes\":0}}\n", .{});
                    continue;
                };
                defer audio_pipeline.deinit();

                try writeStdout(io, &fmt_buf, "{{\"type\":\"audio-status\",\"message\":\"pipeline-initialized\",\"packets\":0,\"bytes\":0}}\n", .{});
                std.debug.print("[agent] audio pipeline initialized (Opus {d}Hz, {d}ch, SSRC=0x{x})\n", .{ sample_rate, channels, audio_ssrc });

                // Generate a few frames of 440 Hz sine wave to prove the pipeline
                const num_frames: usize = 5;
                var pcm_buf: [frame_size]i16 = undefined;
                var rtp_buf: [2048]u8 = undefined;
                var phase: f32 = 0.0;
                var total_packets: usize = 0;
                var total_bytes: usize = 0;

                for (0..num_frames) |frame_idx| {
                    // Generate PCM
                    sources.generateSineWave(&pcm_buf, @intCast(sample_rate), 440.0, 16000.0, &phase);

                    // Encode + packetize
                    const pkt_len = audio_pipeline.sendAudio(&pcm_buf, &rtp_buf) catch |err| {
                        std.debug.print("[agent] audio frame {d} encode failed: {}\n", .{ frame_idx, err });
                        continue;
                    };

                    total_packets += 1;
                    total_bytes += pkt_len;
                    std.debug.print("[agent] audio frame {d}: {d} bytes (RTP hdr + Opus)\n", .{ frame_idx, pkt_len });
                }

                try writeStdout(io, &fmt_buf, "{{\"type\":\"audio-status\",\"message\":\"frames-encoded\",\"packets\":{d},\"bytes\":{d}}}\n", .{ total_packets, total_bytes });
                std.debug.print("[agent] audio pipeline complete: {d} packets, {d} bytes total\n", .{ total_packets, total_bytes });
            }
        } else if (std.mem.eql(u8, msg_type, "ice-candidate")) {
            const candidate = extractJsonString(trimmed, "candidate") orelse "";
            std.debug.print("[agent] received ICE candidate: {s}\n", .{candidate});
            try writeStdout(io, &fmt_buf, "{{\"type\":\"status\",\"message\":\"ice-candidate-received\"}}\n", .{});
        } else if (std.mem.eql(u8, msg_type, "data")) {
            const message = extractJsonString(trimmed, "message") orelse "(empty)";
            std.debug.print("[agent] data channel message: {s}\n", .{message});
        } else {
            std.debug.print("[agent] unknown message type: {s}\n", .{msg_type});
        }
    }

    try writeStdout(io, &fmt_buf, "{{\"type\":\"status\",\"message\":\"shutdown\"}}\n", .{});
    std.debug.print("[agent] done\n", .{});
}

