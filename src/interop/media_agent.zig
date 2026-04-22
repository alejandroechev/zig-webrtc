//! Media agent: real UDP transport + ICE-lite + DTLS + SRTP audio sending
//!
//! This standalone agent:
//!   1. Opens a UDP socket on a random port
//!   2. Reads pre-synthesized PCM audio, resamples 16kHz→48kHz
//!   3. Creates SDP offer with host ICE candidate
//!   4. Exchanges signaling via stdin/stdout JSON
//!   5. Responds to browser STUN binding requests (ICE-lite)
//!   6. Performs DTLS handshake (passive/server role)
//!   7. Extracts SRTP keys from DTLS
//!   8. Sends Opus-encoded audio over SRTP/RTP at 20ms intervals
//!
//! Fallback: if DTLS fails, sends unencrypted RTP for packet-level validation.

const std = @import("std");
const webrtc = @import("zig-webrtc");

const UdpTransport = webrtc.transport.UdpTransport;
const Ipv4Address = webrtc.transport.Ipv4Address;
const stun = webrtc.stun;
const dtls = webrtc.dtls;
const srtp_mod = webrtc.srtp;
const rtp_mod = webrtc.rtp;
const AudioPipeline = webrtc.media.pipeline.AudioPipeline;

// ── Constants ─────────────────────────────────────────────────────────

const audio_ssrc: u32 = 0xA0D10001;
const opus_payload_type: u7 = 111;
const sample_rate_48k: i32 = 48000;
const channels: i32 = 1;
const frame_ms: u32 = 20;
const frame_size_48k: usize = 960; // 48000 * 20 / 1000
const frame_size_16k: usize = 320; // 16000 * 20 / 1000

// ICE credentials (used in STUN message integrity)
const ice_ufrag = "zigm";
const ice_pwd = "zigmediaagentpassword12345678";

// ── JSON helpers ──────────────────────────────────────────────────────

fn jsonEscapeSdp(allocator: std.mem.Allocator, raw: []const u8) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);
    for (raw) |ch| {
        switch (ch) {
            '\r' => try buf.appendSlice(allocator, "\\r"),
            '\n' => try buf.appendSlice(allocator, "\\n"),
            '"' => try buf.appendSlice(allocator, "\\\""),
            '\\' => try buf.appendSlice(allocator, "\\\\"),
            else => try buf.append(allocator, ch),
        }
    }
    return buf.toOwnedSlice(allocator);
}

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

fn extractJsonString(line: []const u8, key: []const u8) ?[]const u8 {
    var pattern_buf: [64]u8 = undefined;
    const pattern = std.fmt.bufPrint(&pattern_buf, "\"{s}\":\"", .{key}) catch return null;

    const start_idx = std.mem.indexOf(u8, line, pattern) orelse return null;
    const value_start = start_idx + pattern.len;

    var i = value_start;
    while (i < line.len) {
        if (line[i] == '\\' and i + 1 < line.len) {
            i += 2;
        } else if (line[i] == '"') {
            return line[value_start..i];
        } else {
            i += 1;
        }
    }
    return null;
}

// ── I/O helpers ───────────────────────────────────────────────────────

fn writeStdout(io: std.Io, buf: []u8, comptime fmt: []const u8, args: anytype) !void {
    const text = try std.fmt.bufPrint(buf, fmt, args);
    try std.Io.File.stdout().writeStreamingAll(io, text);
}

fn log(comptime fmt: []const u8, args: anytype) void {
    std.debug.print("[media-agent] " ++ fmt ++ "\n", args);
}

// ── SDP generation ────────────────────────────────────────────────────

fn buildSdpOffer(
    allocator: std.mem.Allocator,
    port: u16,
    fingerprint_str: []const u8,
) ![]u8 {
    var sdp: std.ArrayList(u8) = .empty;
    errdefer sdp.deinit(allocator);

    // Session-level
    try sdp.appendSlice(allocator, "v=0\r\n");
    try sdp.appendSlice(allocator, "o=zig-media 1 1 IN IP4 127.0.0.1\r\n");
    try sdp.appendSlice(allocator, "s=zig-webrtc-media\r\n");
    try sdp.appendSlice(allocator, "t=0 0\r\n");

    // Bundle + ICE-lite
    try sdp.appendSlice(allocator, "a=group:BUNDLE 0\r\n");
    try sdp.appendSlice(allocator, "a=ice-lite\r\n");
    try sdp.appendSlice(allocator, "a=msid-semantic:WMS *\r\n");

    // Audio m= line
    var line_buf: [512]u8 = undefined;

    const mline = try std.fmt.bufPrint(&line_buf, "m=audio {d} UDP/TLS/RTP/SAVPF 111\r\n", .{port});
    try sdp.appendSlice(allocator, mline);

    try sdp.appendSlice(allocator, "c=IN IP4 127.0.0.1\r\n");

    const mid = try std.fmt.bufPrint(&line_buf, "a=mid:0\r\n", .{});
    try sdp.appendSlice(allocator, mid);

    // ICE credentials
    const ufrag_line = try std.fmt.bufPrint(&line_buf, "a=ice-ufrag:{s}\r\n", .{ice_ufrag});
    try sdp.appendSlice(allocator, ufrag_line);
    const pwd_line = try std.fmt.bufPrint(&line_buf, "a=ice-pwd:{s}\r\n", .{ice_pwd});
    try sdp.appendSlice(allocator, pwd_line);

    // DTLS fingerprint + setup
    const fp_line = try std.fmt.bufPrint(&line_buf, "a=fingerprint:{s}\r\n", .{fingerprint_str});
    try sdp.appendSlice(allocator, fp_line);
    try sdp.appendSlice(allocator, "a=setup:actpass\r\n");

    // Direction: send only
    try sdp.appendSlice(allocator, "a=sendonly\r\n");

    // RTCP-mux
    try sdp.appendSlice(allocator, "a=rtcp-mux\r\n");

    // Opus codec
    try sdp.appendSlice(allocator, "a=rtpmap:111 opus/48000/2\r\n");
    try sdp.appendSlice(allocator, "a=fmtp:111 minptime=10;useinbandfec=1\r\n");

    // SSRC
    const ssrc_line = try std.fmt.bufPrint(&line_buf, "a=ssrc:{d} cname:zig-media\r\n", .{audio_ssrc});
    try sdp.appendSlice(allocator, ssrc_line);

    // ICE candidate (host, 127.0.0.1)
    const cand = try std.fmt.bufPrint(
        &line_buf,
        "a=candidate:1 1 udp 2130706431 127.0.0.1 {d} typ host\r\n",
        .{port},
    );
    try sdp.appendSlice(allocator, cand);

    return sdp.toOwnedSlice(allocator);
}

// ── Audio file reading + resampling ───────────────────────────────────

/// Read 16kHz 16-bit mono PCM file and resample to 48kHz by triplicating samples.
fn loadAndResamplePcm(allocator: std.mem.Allocator, path: []const u8) ![]i16 {
    // Use C fopen/fread since Zig 0.16 removed std.fs.cwd()
    const c_file = @cImport(@cInclude("stdio.h"));
    const path_z = try allocator.dupeZ(u8, path);
    defer allocator.free(path_z);

    const fp = c_file.fopen(path_z.ptr, "rb") orelse {
        log("failed to open PCM file '{s}'", .{path});
        return error.FileOpenFailed;
    };
    defer _ = c_file.fclose(fp);

    // Seek to end to get file size
    _ = c_file.fseek(fp, 0, c_file.SEEK_END);
    const file_size: usize = @intCast(c_file.ftell(fp));
    _ = c_file.fseek(fp, 0, c_file.SEEK_SET);

    const num_samples_16k = file_size / 2; // 16-bit samples

    const pcm_16k = try allocator.alloc(i16, num_samples_16k);
    defer allocator.free(pcm_16k);

    const bytes = std.mem.sliceAsBytes(pcm_16k);
    const read_count = c_file.fread(bytes.ptr, 1, bytes.len, fp);
    if (read_count < bytes.len) {
        log("short read: got {d} of {d} bytes", .{ read_count, bytes.len });
    }

    // Resample 16kHz → 48kHz: triplicate each sample
    const num_samples_48k = num_samples_16k * 3;
    const pcm_48k = try allocator.alloc(i16, num_samples_48k);
    for (pcm_16k[0..num_samples_16k], 0..) |sample, i| {
        pcm_48k[i * 3 + 0] = sample;
        pcm_48k[i * 3 + 1] = sample;
        pcm_48k[i * 3 + 2] = sample;
    }

    log("loaded PCM: {d} samples @16kHz → {d} samples @48kHz ({d} frames)", .{
        num_samples_16k, num_samples_48k, num_samples_48k / frame_size_48k,
    });

    return pcm_48k;
}

// ── STUN response builder ─────────────────────────────────────────────

/// Build a STUN Binding Success Response with XOR-MAPPED-ADDRESS.
fn buildStunResponse(
    allocator: std.mem.Allocator,
    request_tid: [12]u8,
    src_ip: [4]u8,
    src_port: u16,
) ![]u8 {
    var builder = stun.MessageBuilder.init(allocator);
    defer builder.deinit();

    builder.setClass(.success);
    builder.setMethod(.binding);
    builder.setTransactionId(request_tid);

    // Build XOR-MAPPED-ADDRESS attribute value (IPv4)
    var xma_val: [8]u8 = undefined;
    xma_val[0] = 0; // reserved
    xma_val[1] = 0x01; // IPv4
    const xored_port = src_port ^ 0x2112;
    std.mem.writeInt(u16, xma_val[2..4], xored_port, .big);
    xma_val[4] = src_ip[0] ^ 0x21;
    xma_val[5] = src_ip[1] ^ 0x12;
    xma_val[6] = src_ip[2] ^ 0xA4;
    xma_val[7] = src_ip[3] ^ 0x42;

    try builder.addAttribute(.xor_mapped_address, &xma_val);

    // Add MESSAGE-INTEGRITY using the combined ICE password
    // For ICE-lite, the key for responses to browser requests is: browser_ufrag:our_ufrag / our_pwd
    // Actually for short-term credential mechanism, key = SASLprep(password) of the responding agent
    // We use our ICE password as the key
    try builder.addMessageIntegrity(ice_pwd);
    try builder.addFingerprint();

    return builder.build();
}

// ── Extract source IP from sockaddr_in ────────────────────────────────
// Use bytes directly to avoid cImport type mismatch between modules

fn extractIpv4FromRecv(src_addr: anytype) [4]u8 {
    // sockaddr_in layout: sin_family(2) + sin_port(2) + sin_addr(4) + padding(8)
    const bytes = std.mem.asBytes(src_addr);
    return bytes[4..8].*;
}

fn extractPortFromRecv(src_addr: anytype) u16 {
    const bytes = std.mem.asBytes(src_addr);
    return std.mem.readInt(u16, bytes[2..4], .big);
}

// ── Set recv timeout on socket ────────────────────────────────────────

const c = @cImport({
    @cInclude("winsock2.h");
});

fn setRecvTimeout(transport_sock: *UdpTransport, ms: u32) void {
    const timeout: c_int = @intCast(ms);
    _ = c.setsockopt(
        transport_sock.socket,
        c.SOL_SOCKET,
        c.SO_RCVTIMEO,
        @ptrCast(&timeout),
        @sizeOf(c_int),
    );
}

// ── Main ──────────────────────────────────────────────────────────────

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

    var fmt_buf: [65536]u8 = undefined;

    log("starting", .{});

    // ── Step 1: Open UDP socket on random port ──────────────────────
    const bind_addr = Ipv4Address.init(.{ 127, 0, 0, 1 }, 0);
    var transport = UdpTransport.init(bind_addr) catch |err| {
        log("UDP socket failed: {}", .{err});
        return err;
    };
    defer transport.close();

    const local_port = transport.local_addr.getPort();
    log("UDP socket bound to 127.0.0.1:{d}", .{local_port});

    // ── Step 2: Initialize DTLS context ─────────────────────────────
    var dtls_ctx = dtls.DtlsContext.init(.server) catch |err| {
        log("DTLS context init failed: {}", .{err});
        return err;
    };
    defer dtls_ctx.deinit();

    // Get certificate fingerprint for SDP
    const fingerprint = dtls.computeFingerprint(&dtls_ctx, .sha256) catch |err| {
        log("fingerprint computation failed: {}", .{err});
        return err;
    };
    var fp_buf: [dtls.max_formatted_fingerprint_len]u8 = undefined;
    const fp_len = fingerprint.formatWithAlgorithm(&fp_buf);
    const fingerprint_str = fp_buf[0..fp_len];

    log("DTLS fingerprint: {s}", .{fingerprint_str});

    // ── Step 3: Build and send SDP offer ─────────────────────────────
    const sdp_raw = try buildSdpOffer(allocator, local_port, fingerprint_str);
    defer allocator.free(sdp_raw);

    const sdp_escaped = try jsonEscapeSdp(allocator, sdp_raw);
    defer allocator.free(sdp_escaped);

    try writeStdout(io, &fmt_buf, "{{\"type\":\"offer\",\"sdp\":\"{s}\"}}\n", .{sdp_escaped});
    try writeStdout(io, &fmt_buf, "{{\"type\":\"status\",\"message\":\"waiting-for-answer\"}}\n", .{});

    log("SDP offer sent, waiting for answer...", .{});

    // ── Step 4: Wait for answer on stdin ─────────────────────────────
    var stdin_buf: [65536]u8 = undefined;
    var stdin = std.Io.File.stdin().readerStreaming(io, &stdin_buf);

    var answer_received = false;
    var remote_ufrag: ?[]u8 = null;
    defer if (remote_ufrag) |u| allocator.free(u);

    while (!answer_received) {
        const line = stdin.interface.takeDelimiter('\n') catch |err| {
            log("stdin read error: {}", .{err});
            return err;
        } orelse {
            log("stdin closed before answer", .{});
            return error.UnexpectedEof;
        };

        const trimmed = std.mem.trimEnd(u8, line, "\r");
        if (trimmed.len == 0) continue;

        const msg_type = extractJsonString(trimmed, "type") orelse continue;

        if (std.mem.eql(u8, msg_type, "answer")) {
            const sdp_escaped_answer = extractJsonString(trimmed, "sdp") orelse {
                log("answer missing sdp field", .{});
                continue;
            };
            const answer_sdp = try jsonUnescapeSdp(allocator, sdp_escaped_answer);
            defer allocator.free(answer_sdp);

            log("answer SDP received ({d} bytes)", .{answer_sdp.len});

            // Extract remote ICE ufrag from answer SDP
            var line_iter = std.mem.splitScalar(u8, answer_sdp, '\n');
            while (line_iter.next()) |sdp_line| {
                const clean = std.mem.trimEnd(u8, sdp_line, "\r");
                if (std.mem.startsWith(u8, clean, "a=ice-ufrag:")) {
                    remote_ufrag = try allocator.dupe(u8, clean["a=ice-ufrag:".len..]);
                    log("remote ICE ufrag: {s}", .{remote_ufrag.?});
                }
            }

            answer_received = true;
            try writeStdout(io, &fmt_buf, "{{\"type\":\"status\",\"message\":\"answer-received\"}}\n", .{});
        } else if (std.mem.eql(u8, msg_type, "ice-candidate")) {
            log("received ICE candidate (pre-answer)", .{});
        }
    }

    // ── Step 5: ICE connectivity — wait for STUN binding request ─────
    try writeStdout(io, &fmt_buf, "{{\"type\":\"status\",\"message\":\"ice-checking\"}}\n", .{});
    log("waiting for STUN binding requests...", .{});

    // Set a 10-second timeout for receiving STUN
    setRecvTimeout(&transport, 10000);

    var recv_buf: [4096]u8 = undefined;
    var peer_addr: ?Ipv4Address = null;
    var stun_received = false;
    var stun_attempts: usize = 0;
    const max_stun_attempts: usize = 50; // 50 * 10s = plenty of time with non-blocking

    // Use shorter timeout for polling
    setRecvTimeout(&transport, 500);

    // Also drain any ICE candidates from stdin in a non-blocking way
    while (stun_attempts < max_stun_attempts) : (stun_attempts += 1) {
        const result = transport.recv(&recv_buf) catch {
            // Timeout — check stdin for more ICE candidates
            continue;
        };

        if (result.len < 20) continue;

        // Classify packet
        const kind = dtls.classifyPacket(recv_buf[0]);
        switch (kind) {
            .stun => {
                log("received STUN packet ({d} bytes)", .{result.len});

                // Parse STUN message
                const msg = stun.Message.parse(allocator, recv_buf[0..result.len]) catch |err| {
                    log("STUN parse error: {}", .{err});
                    continue;
                };
                defer msg.deinit();

                const msg_type = msg.getType();
                if (msg_type.class == .request and msg_type.method == .binding) {
                    log("STUN binding request, sending success response", .{});

                    // Extract source address for XOR-MAPPED-ADDRESS
                    const src_ip = extractIpv4FromRecv(&result.src_addr);
                    const src_port = extractPortFromRecv(&result.src_addr);

                    // Build and send response
                    const response = buildStunResponse(
                        allocator,
                        msg.header.transaction_id,
                        src_ip,
                        src_port,
                    ) catch |err| {
                        log("failed to build STUN response: {}", .{err});
                        continue;
                    };
                    defer allocator.free(response);

                    const dest = Ipv4Address{ .addr = result.src_addr };
                    _ = transport.send(response, dest) catch |err| {
                        log("failed to send STUN response: {}", .{err});
                        continue;
                    };

                    peer_addr = Ipv4Address{ .addr = result.src_addr };
                    stun_received = true;
                    log("STUN response sent to {d}.{d}.{d}.{d}:{d}", .{
                        src_ip[0], src_ip[1], src_ip[2], src_ip[3], src_port,
                    });

                    // Continue receiving — browser may send multiple STUN checks.
                    // After first success, start DTLS phase.
                    break;
                }
            },
            .dtls => {
                log("received DTLS packet before STUN completed ({d} bytes)", .{result.len});
                // Some browsers start DTLS immediately — save the peer address
                if (peer_addr == null) {
                    peer_addr = Ipv4Address{ .addr = result.src_addr };
                    stun_received = true;
                }
                break;
            },
            else => {
                log("received unknown packet kind ({d} bytes, first byte: 0x{x})", .{ result.len, recv_buf[0] });
            },
        }
    }

    if (!stun_received) {
        log("no STUN binding request received, falling back to unencrypted RTP", .{});
        try writeStdout(io, &fmt_buf, "{{\"type\":\"status\",\"message\":\"ice-timeout-fallback\"}}\n", .{});
        // Fall through — we'll try sending RTP anyway if we know the peer
    }

    // ── Step 6: DTLS handshake ───────────────────────────────────────
    var dtls_complete = false;
    var srtp_context: ?srtp_mod.SrtpContext = null;
    defer if (srtp_context) |*ctx| ctx.deinit();

    if (peer_addr != null) dtls_block: {
        try writeStdout(io, &fmt_buf, "{{\"type\":\"status\",\"message\":\"dtls-handshake\"}}\n", .{});
        log("starting DTLS handshake (server/passive role)...", .{});

        var dtls_conn = dtls.DtlsConnection.init(&dtls_ctx, .server) catch |err| {
            log("DTLS connection init failed: {}", .{err});
            try writeStdout(io, &fmt_buf, "{{\"type\":\"status\",\"message\":\"dtls-init-failed\"}}\n", .{});
            break :dtls_block;
        };
        defer dtls_conn.deinit();

        // DTLS handshake loop
        setRecvTimeout(&transport, 2000);

        var dtls_rounds: usize = 0;
        const max_dtls_rounds: usize = 50;

        while (dtls_rounds < max_dtls_rounds) : (dtls_rounds += 1) {
            const hs_result = dtls_conn.handshake() catch |err| {
                log("DTLS handshake error: {}", .{err});
                break;
            };

            switch (hs_result) {
                .completed => {
                    log("DTLS handshake completed!", .{});
                    dtls_complete = true;

                    const key_material_raw = dtls_conn.exportKeyingMaterial() catch |err| {
                        log("SRTP key export failed: {}", .{err});
                        break;
                    };

                    const key_material = dtls.parseSrtpKeyMaterial(&key_material_raw);

                    // We are server, so we use server_write_key for sending
                    const our_key = srtp_mod.SrtpKeyMaterial{
                        .master_key = key_material.server_write_key,
                        .master_salt = key_material.server_write_salt,
                    };

                    srtp_context = srtp_mod.SrtpContext.init(
                        allocator,
                        .aes128_cm_hmac_sha1_80,
                        our_key,
                    );

                    try writeStdout(io, &fmt_buf, "{{\"type\":\"status\",\"message\":\"dtls-complete\"}}\n", .{});
                    break;
                },
                .pending => {
                    // Read outgoing DTLS data and send over UDP
                    var dtls_out: [4096]u8 = undefined;
                    while (true) {
                        const out_len = dtls_conn.getData(&dtls_out) catch break;
                        if (out_len == 0) break;

                        const dest = peer_addr.?;
                        _ = transport.send(dtls_out[0..out_len], dest) catch |err| {
                            log("failed to send DTLS data: {}", .{err});
                            break;
                        };
                        log("sent {d} bytes DTLS data", .{out_len});
                    }

                    // Wait for incoming DTLS/STUN data
                    const recv_result = transport.recv(&recv_buf) catch {
                        continue;
                    };

                    if (recv_result.len == 0) continue;

                    const pkt_kind = dtls.classifyPacket(recv_buf[0]);
                    switch (pkt_kind) {
                        .dtls => {
                            dtls_conn.feedData(recv_buf[0..recv_result.len]) catch |err| {
                                log("DTLS feed error: {}", .{err});
                                break;
                            };
                            log("fed {d} bytes to DTLS", .{recv_result.len});
                        },
                        .stun => {
                            // Respond to additional STUN checks during DTLS
                            const stun_msg = stun.Message.parse(allocator, recv_buf[0..recv_result.len]) catch continue;
                            defer stun_msg.deinit();

                            const st = stun_msg.getType();
                            if (st.class == .request and st.method == .binding) {
                                const src_ip = extractIpv4FromRecv(&recv_result.src_addr);
                                const src_port = extractPortFromRecv(&recv_result.src_addr);

                                const response = buildStunResponse(
                                    allocator,
                                    stun_msg.header.transaction_id,
                                    src_ip,
                                    src_port,
                                ) catch continue;
                                defer allocator.free(response);

                                const dest = Ipv4Address{ .addr = recv_result.src_addr };
                                _ = transport.send(response, dest) catch {};
                            }
                        },
                        else => {},
                    }
                },
                .failed => {
                    log("DTLS handshake failed", .{});
                    break;
                },
            }
        }

        if (!dtls_complete) {
            log("DTLS handshake did not complete after {d} rounds", .{dtls_rounds});
            try writeStdout(io, &fmt_buf, "{{\"type\":\"status\",\"message\":\"dtls-failed-fallback-rtp\"}}\n", .{});
        }
    } else {
        log("no peer address known, skipping DTLS", .{});
    }

    // ── Step 7: Load and resample audio ──────────────────────────────
    const pcm_48k = loadAndResamplePcm(allocator, "interop/tts-test.pcm") catch |err| {
        log("failed to load PCM: {}", .{err});
        try writeStdout(io, &fmt_buf, "{{\"type\":\"status\",\"message\":\"pcm-load-failed\"}}\n", .{});
        return err;
    };
    defer allocator.free(pcm_48k);

    const total_frames = pcm_48k.len / frame_size_48k;
    log("audio ready: {d} frames ({d}ms total)", .{ total_frames, total_frames * frame_ms });

    // ── Step 8: Encode and send audio ────────────────────────────────
    const use_srtp = dtls_complete and srtp_context != null;
    const mode_str = if (use_srtp) "srtp" else "rtp-unencrypted";
    try writeStdout(io, &fmt_buf, "{{\"type\":\"status\",\"message\":\"sending-audio\"}}\n", .{});
    log("sending audio via {s} ({d} frames)", .{ mode_str, total_frames });

    var audio_pipeline = AudioPipeline.init(sample_rate_48k, channels, audio_ssrc) catch |err| {
        log("audio pipeline init failed: {}", .{err});
        try writeStdout(io, &fmt_buf, "{{\"type\":\"audio-status\",\"frames\":0,\"bytes\":0}}\n", .{});
        return err;
    };
    defer audio_pipeline.deinit();

    var rtp_buf: [2048]u8 = undefined;
    var total_packets: usize = 0;
    var total_bytes: usize = 0;

    // Determine destination
    const dest_addr = if (peer_addr) |pa|
        pa
    else
        Ipv4Address.init(.{ 127, 0, 0, 1 }, 9999); // fallback for testing

    // Continue responding to STUN while sending audio
    setRecvTimeout(&transport, 1); // 1ms timeout for non-blocking recv

    const frames_to_send = @min(total_frames, 250); // Cap at 5 seconds
    for (0..frames_to_send) |frame_idx| {
        const offset = frame_idx * frame_size_48k;
        const pcm_frame = pcm_48k[offset .. offset + frame_size_48k];

        // Encode PCM → Opus → RTP
        const rtp_len = audio_pipeline.sendAudio(pcm_frame, &rtp_buf) catch |err| {
            log("encode error frame {d}: {}", .{ frame_idx, err });
            continue;
        };

        if (use_srtp) {
            // SRTP protect and send
            const protected = srtp_context.?.protectRtp(rtp_buf[0..rtp_len]) catch |err| {
                log("SRTP protect error frame {d}: {}", .{ frame_idx, err });
                continue;
            };
            defer allocator.free(protected);

            _ = transport.send(protected, dest_addr) catch |err| {
                log("send error frame {d}: {}", .{ frame_idx, err });
                continue;
            };
            total_bytes += protected.len;
        } else {
            // Send unencrypted RTP
            _ = transport.send(rtp_buf[0..rtp_len], dest_addr) catch |err| {
                log("send error frame {d}: {}", .{ frame_idx, err });
                continue;
            };
            total_bytes += rtp_len;
        }

        total_packets += 1;

        // Check for incoming STUN/DTLS while sending
        if (transport.recv(&recv_buf)) |recv_result| {
            if (recv_result.len >= 20) {
                const pkt_kind = dtls.classifyPacket(recv_buf[0]);
                if (pkt_kind == .stun) {
                    // Respond to STUN keepalive
                    const stun_msg = stun.Message.parse(allocator, recv_buf[0..recv_result.len]) catch continue;
                    defer stun_msg.deinit();

                    const st = stun_msg.getType();
                    if (st.class == .request and st.method == .binding) {
                        const src_ip = extractIpv4FromRecv(&recv_result.src_addr);
                        const src_port = extractPortFromRecv(&recv_result.src_addr);
                        const response = buildStunResponse(allocator, stun_msg.header.transaction_id, src_ip, src_port) catch continue;
                        defer allocator.free(response);
                        _ = transport.send(response, Ipv4Address{ .addr = recv_result.src_addr }) catch {};
                    }
                }
            }
        } else |_| {}

        // Report progress every 50 frames
        if ((frame_idx + 1) % 50 == 0) {
            try writeStdout(io, &fmt_buf, "{{\"type\":\"audio-status\",\"frames\":{d},\"bytes\":{d}}}\n", .{ total_packets, total_bytes });
        }

        // Sleep ~20ms to pace packets at real-time rate (Windows Sleep via libc)
        const win = @cImport(@cInclude("windows.h"));
        win.Sleep(20);
    }

    // Final status
    try writeStdout(io, &fmt_buf, "{{\"type\":\"audio-status\",\"frames\":{d},\"bytes\":{d}}}\n", .{ total_packets, total_bytes });
    try writeStdout(io, &fmt_buf, "{{\"type\":\"status\",\"message\":\"audio-complete\"}}\n", .{});

    log("audio sending complete: {d} packets, {d} bytes ({s})", .{ total_packets, total_bytes, mode_str });
    log("done", .{});
}
