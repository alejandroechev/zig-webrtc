//! PeerConnection orchestrator (RFC 9429 / JSEP)
//! Generated from 432 structured rules (RFC 9429, 8825, 8827) via RFC Compliance API.
//!
//! This is the top-level API that ties all protocol modules together.
//! It implements the JSEP signaling state machine and coordinates:
//!   ICE → DTLS → SRTP → SCTP → DataChannel
//!
//! Key RFC 9429 rules implemented:
//!   - §5.5/5.6: Signaling state machine (offer/answer/pranswer/rollback)
//!   - §5.2: createOffer MUST only in stable or have_local_offer
//!   - §5.3: createAnswer MUST only in have_remote_offer or have_local_pranswer
//!   - §5.5: setLocalDescription transitions
//!   - §5.6: setRemoteDescription transitions
//!   - §4.1.11/12: closed state rejects all operations
//!   - Bundle group (a=group:BUNDLE)
//!   - a=setup:actpass in offers, a=setup:active in answers
//!   - ICE credential generation (ufrag/pwd) per offer

const std = @import("std");
const Allocator = std.mem.Allocator;

const sdp = @import("../sdp/sdp.zig");
const ice = @import("../ice/ice.zig");

// ============================================================================
// Errors
// ============================================================================

pub const PeerError = error{
    /// Operation is invalid in the current signaling state (RFC 9429 §5.5/§5.6)
    InvalidStateTransition,
    /// PeerConnection has been closed (RFC 9429 §4.1.11/§4.1.12)
    ConnectionClosed,
    /// SDP type does not match what is required by the current state
    InvalidDescriptionType,
    /// Internal failure during SDP generation
    SdpGenerationFailed,
    /// Allocation failure
    OutOfMemory,
};

// ============================================================================
// Signaling State (RFC 9429 §4.1, JSEP state machine)
// ============================================================================

/// JSEP signaling states (RFC 9429 §4.1).
/// State machine: stable ↔ have-local-offer / have-remote-offer ↔ pranswer → stable | closed
pub const SignalingState = enum {
    stable,
    have_local_offer,
    have_remote_offer,
    have_local_pranswer,
    have_remote_pranswer,
    closed,
};

// ============================================================================
// Connection State
// ============================================================================

/// Aggregate connection state reflecting ICE + DTLS transport readiness.
pub const ConnectionState = enum {
    new,
    connecting,
    connected,
    disconnected,
    failed,
    closed,
};

// ============================================================================
// SDP Description Type
// ============================================================================

/// SDP description type used in setLocalDescription / setRemoteDescription.
pub const SdpType = enum {
    offer,
    answer,
    pranswer,
    rollback,
};

// ============================================================================
// Configuration
// ============================================================================

/// STUN/TURN server configuration.
pub const IceServer = struct {
    urls: []const []const u8,
    username: ?[]const u8 = null,
    credential: ?[]const u8 = null,
};

/// ICE transport policy.
pub const IceTransportPolicy = enum {
    all,
    relay,
};

/// PeerConnection configuration.
pub const Config = struct {
    ice_servers: []const IceServer = &.{},
    ice_transport_policy: IceTransportPolicy = .all,
};

/// Media types for audio/video tracks.
pub const MediaType = enum { audio, video };

/// A media track added to the PeerConnection (carries SSRC for RTP).
pub const MediaTrack = struct {
    media_type: MediaType,
    ssrc: u32,
};

/// Data channel creation options.
pub const DataChannelOptions = struct {
    ordered: bool = true,
    max_retransmits: ?u16 = null,
    max_packet_life_time: ?u16 = null,
    protocol: []const u8 = "",
    negotiated: bool = false,
    id: ?u16 = null,
};

// ============================================================================
// PeerConnection
// ============================================================================

/// The top-level WebRTC PeerConnection orchestrator.
///
/// Implements the JSEP signaling state machine (RFC 9429) and coordinates
/// ICE, DTLS, SRTP, SCTP, and DataChannel sub-systems.
pub const PeerConnection = struct {
    allocator: Allocator,
    signaling_state: SignalingState,
    connection_state: ConnectionState,
    local_description: ?sdp.SessionDescription,
    remote_description: ?sdp.SessionDescription,
    pending_local_description: ?sdp.SessionDescription,
    pending_remote_description: ?sdp.SessionDescription,
    ice_agent: ice.IceAgent,
    config: Config,

    // ICE credentials generated per offer
    local_ufrag: [8]u8,
    local_pwd: [24]u8,
    offer_count: u64,

    // Media tracks
    audio_track: ?MediaTrack,
    video_track: ?MediaTrack,

    // Backing buffer for SDP text (kept alive so slices in SessionDescription remain valid)
    sdp_buf: ?[]u8,

    // Callbacks
    on_ice_candidate: ?*const fn (ice.Candidate) void,
    on_connection_state_change: ?*const fn (ConnectionState) void,

    /// Create a new PeerConnection with the given configuration.
    pub fn init(allocator: Allocator, config: Config) PeerConnection {
        return .{
            .allocator = allocator,
            .signaling_state = .stable,
            .connection_state = .new,
            .local_description = null,
            .remote_description = null,
            .pending_local_description = null,
            .pending_remote_description = null,
            .ice_agent = ice.IceAgent.init(allocator, .controlling),
            .config = config,
            .local_ufrag = generateCredential(8),
            .local_pwd = generateCredential(24),
            .offer_count = 0,
            .audio_track = null,
            .video_track = null,
            .sdp_buf = null,
            .on_ice_candidate = null,
            .on_connection_state_change = null,
        };
    }

    // ── Offer/Answer (JSEP state machine) ─────────────────────────────

    /// Create an SDP offer (RFC 9429 §5.2).
    /// MUST only be called in `stable` or `have_local_offer` state.
    pub fn createOffer(self: *PeerConnection) PeerError!sdp.SessionDescription {
        if (self.signaling_state == .closed) return PeerError.ConnectionClosed;
        if (self.signaling_state != .stable and self.signaling_state != .have_local_offer)
            return PeerError.InvalidStateTransition;

        // Generate fresh ICE credentials for each offer (RFC 9429 §5.2.1)
        self.local_ufrag = generateCredential(8);
        self.local_pwd = generateCredential(24);
        self.offer_count += 1;

        return self.buildOfferSdp();
    }

    /// Create an SDP answer (RFC 9429 §5.3).
    /// MUST only be called in `have_remote_offer` or `have_local_pranswer` state.
    pub fn createAnswer(self: *PeerConnection) PeerError!sdp.SessionDescription {
        if (self.signaling_state == .closed) return PeerError.ConnectionClosed;
        if (self.signaling_state != .have_remote_offer and self.signaling_state != .have_local_pranswer)
            return PeerError.InvalidStateTransition;

        return self.buildAnswerSdp();
    }

    /// Set the local description (RFC 9429 §5.5).
    /// Validates and applies the JSEP state transition.
    pub fn setLocalDescription(self: *PeerConnection, desc: sdp.SessionDescription, desc_type: SdpType) PeerError!void {
        if (self.signaling_state == .closed) return PeerError.ConnectionClosed;

        const new_state = validateLocalTransition(self.signaling_state, desc_type) orelse
            return PeerError.InvalidStateTransition;

        // Apply side-effects based on transition
        switch (desc_type) {
            .offer => {
                self.freeDescription(&self.pending_local_description);
                self.pending_local_description = desc;
            },
            .answer => {
                self.freeDescription(&self.local_description);
                self.local_description = desc;
                if (self.pending_remote_description) |prd| {
                    self.freeDescription(&self.remote_description);
                    self.remote_description = prd;
                }
                // pending_remote was promoted — just clear without freeing
                self.pending_remote_description = null;
                // pending_local was the pranswer/offer before — free it
                self.freeDescription(&self.pending_local_description);
            },
            .pranswer => {
                self.freeDescription(&self.pending_local_description);
                self.pending_local_description = desc;
            },
            .rollback => {
                self.freeDescription(&self.pending_local_description);
                if (new_state == .stable) {
                    self.freeDescription(&self.pending_remote_description);
                }
            },
        }

        self.signaling_state = new_state;
    }

    /// Set the remote description (RFC 9429 §5.6).
    /// Validates and applies the JSEP state transition.
    pub fn setRemoteDescription(self: *PeerConnection, desc: sdp.SessionDescription, desc_type: SdpType) PeerError!void {
        if (self.signaling_state == .closed) return PeerError.ConnectionClosed;

        const new_state = validateRemoteTransition(self.signaling_state, desc_type) orelse
            return PeerError.InvalidStateTransition;

        switch (desc_type) {
            .offer => {
                self.freeDescription(&self.pending_remote_description);
                self.pending_remote_description = desc;
            },
            .answer => {
                self.freeDescription(&self.remote_description);
                self.remote_description = desc;
                if (self.pending_local_description) |pld| {
                    self.freeDescription(&self.local_description);
                    self.local_description = pld;
                }
                // pending_local was promoted — just clear without freeing
                self.pending_local_description = null;
                // pending_remote was the pranswer/offer before — free it
                self.freeDescription(&self.pending_remote_description);
            },
            .pranswer => {
                self.freeDescription(&self.pending_remote_description);
                self.pending_remote_description = desc;
            },
            .rollback => {
                self.freeDescription(&self.pending_remote_description);
                if (new_state == .stable) {
                    self.freeDescription(&self.pending_local_description);
                }
            },
        }

        self.signaling_state = new_state;
    }

    // ── ICE ────────────────────────────────────────────────────────────

    /// Add a remote ICE candidate (trickle ICE).
    pub fn addIceCandidate(self: *PeerConnection, candidate: ice.Candidate) !void {
        if (self.signaling_state == .closed) return PeerError.ConnectionClosed;
        try self.ice_agent.addRemoteCandidate(candidate);
    }

    // ── Media Tracks ──────────────────────────────────────────────────

    /// Add an audio track (Opus) with the given SSRC.
    pub fn addAudioTrack(self: *PeerConnection, ssrc: u32) void {
        self.audio_track = MediaTrack{ .media_type = .audio, .ssrc = ssrc };
    }

    /// Add a video track (VP8) with the given SSRC.
    pub fn addVideoTrack(self: *PeerConnection, ssrc: u32) void {
        self.video_track = MediaTrack{ .media_type = .video, .ssrc = ssrc };
    }

    // ── Lifecycle ──────────────────────────────────────────────────────

    /// Close the PeerConnection (RFC 9429 §4.1).
    /// Transitions any state → closed. Releases ICE/DTLS resources.
    pub fn close(self: *PeerConnection) void {
        if (self.signaling_state == .closed) return;
        self.signaling_state = .closed;
        self.connection_state = .closed;
        self.ice_agent.deinit();
        // Re-init to a safe empty state so deinit doesn't double-free
        self.ice_agent = ice.IceAgent.init(self.allocator, .controlling);

        if (self.on_connection_state_change) |cb| {
            cb(.closed);
        }
    }

    /// Free a stored SessionDescription's allocations.
    fn freeDescription(self: *PeerConnection, desc: *?sdp.SessionDescription) void {
        if (desc.*) |*d| {
            @constCast(d).deinit(self.allocator);
            desc.* = null;
        }
    }

    /// Free all resources. Calls close() if not already closed.
    pub fn deinit(self: *PeerConnection) void {
        if (self.signaling_state != .closed) {
            self.close();
        }
        self.ice_agent.deinit();
        // Free all stored descriptions
        self.freeDescription(&self.pending_local_description);
        self.freeDescription(&self.pending_remote_description);
        self.freeDescription(&self.local_description);
        self.freeDescription(&self.remote_description);
        if (self.sdp_buf) |buf| {
            self.allocator.free(buf);
            self.sdp_buf = null;
        }
    }

    // ── Private helpers ────────────────────────────────────────────────

    /// Build an SDP offer with required WebRTC attributes.
    fn buildOfferSdp(self: *PeerConnection) PeerError!sdp.SessionDescription {
        // Free any previous SDP backing buffer
        if (self.sdp_buf) |buf| {
            self.allocator.free(buf);
            self.sdp_buf = null;
        }

        var list: std.ArrayList(u8) = .empty;
        errdefer list.deinit(self.allocator);

        // Compute MID assignments: audio=0, video=1 (if audio), datachannel=last
        var next_mid: u32 = 0;
        const audio_mid = if (self.audio_track != null) blk: {
            const m = next_mid;
            next_mid += 1;
            break :blk m;
        } else null;
        const video_mid = if (self.video_track != null) blk: {
            const m = next_mid;
            next_mid += 1;
            break :blk m;
        } else null;
        const dc_mid = next_mid;

        // Session-level lines
        list.appendSlice(self.allocator, "v=0\r\n") catch return PeerError.SdpGenerationFailed;
        list.print(self.allocator, "o=- {d} {d} IN IP4 127.0.0.1\r\n", .{ self.offer_count, self.offer_count }) catch
            return PeerError.SdpGenerationFailed;
        list.appendSlice(self.allocator, "s=-\r\n") catch return PeerError.SdpGenerationFailed;
        list.appendSlice(self.allocator, "t=0 0\r\n") catch return PeerError.SdpGenerationFailed;

        // BUNDLE group (RFC 9429 §5.2.1) — list all MIDs
        list.appendSlice(self.allocator, "a=group:BUNDLE") catch return PeerError.SdpGenerationFailed;
        if (audio_mid) |mid| {
            list.print(self.allocator, " {d}", .{mid}) catch return PeerError.SdpGenerationFailed;
        }
        if (video_mid) |mid| {
            list.print(self.allocator, " {d}", .{mid}) catch return PeerError.SdpGenerationFailed;
        }
        list.print(self.allocator, " {d}\r\n", .{dc_mid}) catch return PeerError.SdpGenerationFailed;

        // ICE credentials
        list.print(self.allocator, "a=ice-ufrag:{s}\r\n", .{self.local_ufrag}) catch
            return PeerError.SdpGenerationFailed;
        list.print(self.allocator, "a=ice-pwd:{s}\r\n", .{self.local_pwd}) catch
            return PeerError.SdpGenerationFailed;
        // a=setup:actpass for offers (RFC 9429 §5.2.1)
        list.appendSlice(self.allocator, "a=setup:actpass\r\n") catch return PeerError.SdpGenerationFailed;

        // Audio m= line (Opus)
        if (self.audio_track) |track| {
            list.appendSlice(self.allocator, "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n") catch return PeerError.SdpGenerationFailed;
            list.appendSlice(self.allocator, "c=IN IP4 0.0.0.0\r\n") catch return PeerError.SdpGenerationFailed;
            list.print(self.allocator, "a=mid:{d}\r\n", .{audio_mid.?}) catch return PeerError.SdpGenerationFailed;
            list.appendSlice(self.allocator, "a=rtpmap:111 opus/48000/2\r\n") catch return PeerError.SdpGenerationFailed;
            list.appendSlice(self.allocator, "a=fmtp:111 minptime=10;useinbandfec=1\r\n") catch return PeerError.SdpGenerationFailed;
            list.appendSlice(self.allocator, "a=rtcp-fb:111 nack\r\n") catch return PeerError.SdpGenerationFailed;
            list.print(self.allocator, "a=ssrc:{d} cname:zig-webrtc\r\n", .{track.ssrc}) catch return PeerError.SdpGenerationFailed;
        }

        // Video m= line (VP8)
        if (self.video_track) |track| {
            list.appendSlice(self.allocator, "m=video 9 UDP/TLS/RTP/SAVPF 96\r\n") catch return PeerError.SdpGenerationFailed;
            list.appendSlice(self.allocator, "c=IN IP4 0.0.0.0\r\n") catch return PeerError.SdpGenerationFailed;
            list.print(self.allocator, "a=mid:{d}\r\n", .{video_mid.?}) catch return PeerError.SdpGenerationFailed;
            list.appendSlice(self.allocator, "a=rtpmap:96 VP8/90000\r\n") catch return PeerError.SdpGenerationFailed;
            list.appendSlice(self.allocator, "a=rtcp-fb:96 nack\r\n") catch return PeerError.SdpGenerationFailed;
            list.appendSlice(self.allocator, "a=rtcp-fb:96 nack pli\r\n") catch return PeerError.SdpGenerationFailed;
            list.appendSlice(self.allocator, "a=rtcp-fb:96 ccm fir\r\n") catch return PeerError.SdpGenerationFailed;
            list.print(self.allocator, "a=ssrc:{d} cname:zig-webrtc\r\n", .{track.ssrc}) catch return PeerError.SdpGenerationFailed;
        }

        // Data channel m= line (application using DTLS/SCTP)
        list.appendSlice(self.allocator, "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n") catch
            return PeerError.SdpGenerationFailed;
        list.appendSlice(self.allocator, "c=IN IP4 0.0.0.0\r\n") catch return PeerError.SdpGenerationFailed;
        list.print(self.allocator, "a=mid:{d}\r\n", .{dc_mid}) catch return PeerError.SdpGenerationFailed;
        list.appendSlice(self.allocator, "a=sctp-port:5000\r\n") catch return PeerError.SdpGenerationFailed;

        // Keep the SDP text alive so parsed slices remain valid
        const sdp_text = list.toOwnedSlice(self.allocator) catch return PeerError.OutOfMemory;
        self.sdp_buf = sdp_text;

        const parsed = sdp.SessionDescription.parse(self.allocator, sdp_text) catch
            return PeerError.SdpGenerationFailed;
        return parsed;
    }

    /// Build an SDP answer with required WebRTC attributes.
    fn buildAnswerSdp(self: *PeerConnection) PeerError!sdp.SessionDescription {
        if (self.sdp_buf) |buf| {
            self.allocator.free(buf);
            self.sdp_buf = null;
        }

        var list: std.ArrayList(u8) = .empty;
        errdefer list.deinit(self.allocator);

        // Compute MID assignments (same logic as offer)
        var next_mid: u32 = 0;
        const audio_mid = if (self.audio_track != null) blk: {
            const m = next_mid;
            next_mid += 1;
            break :blk m;
        } else null;
        const video_mid = if (self.video_track != null) blk: {
            const m = next_mid;
            next_mid += 1;
            break :blk m;
        } else null;
        const dc_mid = next_mid;

        list.appendSlice(self.allocator, "v=0\r\n") catch return PeerError.SdpGenerationFailed;
        list.print(self.allocator, "o=- {d} 1 IN IP4 127.0.0.1\r\n", .{self.offer_count}) catch
            return PeerError.SdpGenerationFailed;
        list.appendSlice(self.allocator, "s=-\r\n") catch return PeerError.SdpGenerationFailed;
        list.appendSlice(self.allocator, "t=0 0\r\n") catch return PeerError.SdpGenerationFailed;

        list.appendSlice(self.allocator, "a=group:BUNDLE") catch return PeerError.SdpGenerationFailed;
        if (audio_mid) |mid| {
            list.print(self.allocator, " {d}", .{mid}) catch return PeerError.SdpGenerationFailed;
        }
        if (video_mid) |mid| {
            list.print(self.allocator, " {d}", .{mid}) catch return PeerError.SdpGenerationFailed;
        }
        list.print(self.allocator, " {d}\r\n", .{dc_mid}) catch return PeerError.SdpGenerationFailed;

        list.print(self.allocator, "a=ice-ufrag:{s}\r\n", .{self.local_ufrag}) catch
            return PeerError.SdpGenerationFailed;
        list.print(self.allocator, "a=ice-pwd:{s}\r\n", .{self.local_pwd}) catch
            return PeerError.SdpGenerationFailed;
        // a=setup:active for answers (RFC 9429 §5.3.1)
        list.appendSlice(self.allocator, "a=setup:active\r\n") catch return PeerError.SdpGenerationFailed;

        // Audio m= line (Opus)
        if (self.audio_track) |track| {
            list.appendSlice(self.allocator, "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n") catch return PeerError.SdpGenerationFailed;
            list.appendSlice(self.allocator, "c=IN IP4 0.0.0.0\r\n") catch return PeerError.SdpGenerationFailed;
            list.print(self.allocator, "a=mid:{d}\r\n", .{audio_mid.?}) catch return PeerError.SdpGenerationFailed;
            list.appendSlice(self.allocator, "a=rtpmap:111 opus/48000/2\r\n") catch return PeerError.SdpGenerationFailed;
            list.appendSlice(self.allocator, "a=fmtp:111 minptime=10;useinbandfec=1\r\n") catch return PeerError.SdpGenerationFailed;
            list.appendSlice(self.allocator, "a=rtcp-fb:111 nack\r\n") catch return PeerError.SdpGenerationFailed;
            list.print(self.allocator, "a=ssrc:{d} cname:zig-webrtc\r\n", .{track.ssrc}) catch return PeerError.SdpGenerationFailed;
        }

        // Video m= line (VP8)
        if (self.video_track) |track| {
            list.appendSlice(self.allocator, "m=video 9 UDP/TLS/RTP/SAVPF 96\r\n") catch return PeerError.SdpGenerationFailed;
            list.appendSlice(self.allocator, "c=IN IP4 0.0.0.0\r\n") catch return PeerError.SdpGenerationFailed;
            list.print(self.allocator, "a=mid:{d}\r\n", .{video_mid.?}) catch return PeerError.SdpGenerationFailed;
            list.appendSlice(self.allocator, "a=rtpmap:96 VP8/90000\r\n") catch return PeerError.SdpGenerationFailed;
            list.appendSlice(self.allocator, "a=rtcp-fb:96 nack\r\n") catch return PeerError.SdpGenerationFailed;
            list.appendSlice(self.allocator, "a=rtcp-fb:96 nack pli\r\n") catch return PeerError.SdpGenerationFailed;
            list.appendSlice(self.allocator, "a=rtcp-fb:96 ccm fir\r\n") catch return PeerError.SdpGenerationFailed;
            list.print(self.allocator, "a=ssrc:{d} cname:zig-webrtc\r\n", .{track.ssrc}) catch return PeerError.SdpGenerationFailed;
        }

        // Data channel m= line
        list.appendSlice(self.allocator, "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n") catch
            return PeerError.SdpGenerationFailed;
        list.appendSlice(self.allocator, "c=IN IP4 0.0.0.0\r\n") catch return PeerError.SdpGenerationFailed;
        list.print(self.allocator, "a=mid:{d}\r\n", .{dc_mid}) catch return PeerError.SdpGenerationFailed;
        list.appendSlice(self.allocator, "a=sctp-port:5000\r\n") catch return PeerError.SdpGenerationFailed;

        const sdp_text = list.toOwnedSlice(self.allocator) catch return PeerError.OutOfMemory;
        self.sdp_buf = sdp_text;

        const parsed = sdp.SessionDescription.parse(self.allocator, sdp_text) catch
            return PeerError.SdpGenerationFailed;
        return parsed;
    }

    /// Generate deterministic-length random ICE credentials.
    /// Uses pointer-entropy PRNG (same pattern as STUN/ICE modules).
    fn generateCredential(comptime len: usize) [len]u8 {
        const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/";
        var buf: [len]u8 = undefined;
        var seed: u64 = 0;
        seed ^= @intFromPtr(&buf);
        seed +%= cred_counter;
        cred_counter +%= 1;
        var rng = std.Random.SplitMix64.init(seed);
        for (&buf) |*b| {
            b.* = charset[rng.next() % charset.len];
        }
        return buf;
    }

    var cred_counter: u64 = 0xABCD_EF01_2345_6789;

    /// Validate a setLocalDescription transition.
    /// Returns the new state, or null if the transition is invalid.
    fn validateLocalTransition(current: SignalingState, desc_type: SdpType) ?SignalingState {
        return switch (current) {
            .stable => switch (desc_type) {
                .offer => .have_local_offer,
                else => null,
            },
            .have_local_offer => switch (desc_type) {
                .offer => .have_local_offer,
                .rollback => .stable,
                else => null,
            },
            .have_remote_offer => switch (desc_type) {
                .answer => .stable,
                .pranswer => .have_local_pranswer,
                .rollback => .stable,
                else => null,
            },
            .have_local_pranswer => switch (desc_type) {
                .answer => .stable,
                .pranswer => .have_local_pranswer,
                .rollback => .stable,
                else => null,
            },
            .have_remote_pranswer => switch (desc_type) {
                .rollback => .stable,
                else => null,
            },
            .closed => null,
        };
    }

    /// Validate a setRemoteDescription transition.
    /// Returns the new state, or null if the transition is invalid.
    fn validateRemoteTransition(current: SignalingState, desc_type: SdpType) ?SignalingState {
        return switch (current) {
            .stable => switch (desc_type) {
                .offer => .have_remote_offer,
                else => null,
            },
            .have_local_offer => switch (desc_type) {
                .answer => .stable,
                .pranswer => .have_remote_pranswer,
                .rollback => .stable,
                else => null,
            },
            .have_remote_offer => switch (desc_type) {
                .offer => .have_remote_offer,
                .rollback => .stable,
                else => null,
            },
            .have_local_pranswer => switch (desc_type) {
                .rollback => .stable,
                else => null,
            },
            .have_remote_pranswer => switch (desc_type) {
                .answer => .stable,
                .pranswer => .have_remote_pranswer,
                .rollback => .stable,
                else => null,
            },
            .closed => null,
        };
    }
};

// ============================================================================
// Tests — JSEP Signaling State Machine
// ============================================================================

const testing = std.testing;

test "RFC9429: init creates PeerConnection in stable/new state" {
    var pc = PeerConnection.init(testing.allocator, .{});
    defer pc.deinit();

    try testing.expectEqual(SignalingState.stable, pc.signaling_state);
    try testing.expectEqual(ConnectionState.new, pc.connection_state);
    try testing.expect(pc.local_description == null);
    try testing.expect(pc.remote_description == null);
}

test "RFC9429: createOffer succeeds in stable state" {
    var pc = PeerConnection.init(testing.allocator, .{});
    defer pc.deinit();

    // offer is NOT stored in PC, so test must free it
    const offer = try pc.createOffer();
    defer @constCast(&offer).deinit(testing.allocator);

    try testing.expectEqual(@as(u8, 0), offer.version);
    try testing.expectEqual(@as(usize, 1), offer.media.len);
    try testing.expectEqualStrings("application", offer.media[0].media_type);
}

test "RFC9429: createOffer succeeds in have_local_offer (re-offer)" {
    var pc = PeerConnection.init(testing.allocator, .{});
    defer pc.deinit();

    // offer1 stored in PC via setLocalDescription — PC owns it
    const offer1 = try pc.createOffer();
    try pc.setLocalDescription(offer1, .offer);
    try testing.expectEqual(SignalingState.have_local_offer, pc.signaling_state);

    // offer2 is NOT stored — test must free it
    const offer2 = try pc.createOffer();
    defer @constCast(&offer2).deinit(testing.allocator);
    try testing.expectEqual(@as(u8, 0), offer2.version);
}

test "RFC9429: createOffer fails in have_remote_offer state" {
    var pc = PeerConnection.init(testing.allocator, .{});
    defer pc.deinit();

    const remote_sdp_text = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\nc=IN IP4 0.0.0.0\r\na=mid:0\r\n";
    // PC takes ownership via setRemoteDescription — do NOT defer deinit
    const remote_offer = try sdp.SessionDescription.parse(testing.allocator, remote_sdp_text);
    try pc.setRemoteDescription(remote_offer, .offer);
    try testing.expectEqual(SignalingState.have_remote_offer, pc.signaling_state);

    const result = pc.createOffer();
    try testing.expectError(PeerError.InvalidStateTransition, result);
}

test "RFC9429: createAnswer fails in stable state" {
    var pc = PeerConnection.init(testing.allocator, .{});
    defer pc.deinit();

    const result = pc.createAnswer();
    try testing.expectError(PeerError.InvalidStateTransition, result);
}

test "RFC9429: createAnswer succeeds in have_remote_offer" {
    var pc = PeerConnection.init(testing.allocator, .{});
    defer pc.deinit();

    const remote_sdp_text = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\nc=IN IP4 0.0.0.0\r\na=mid:0\r\n";
    const remote_offer = try sdp.SessionDescription.parse(testing.allocator, remote_sdp_text);
    try pc.setRemoteDescription(remote_offer, .offer);

    // answer is NOT stored — test must free it
    const answer = try pc.createAnswer();
    defer @constCast(&answer).deinit(testing.allocator);
    try testing.expectEqual(@as(u8, 0), answer.version);
}

test "RFC9429: setLocalDescription(offer) transitions stable -> have_local_offer" {
    var pc = PeerConnection.init(testing.allocator, .{});
    defer pc.deinit();

    // PC takes ownership
    const offer = try pc.createOffer();
    try pc.setLocalDescription(offer, .offer);

    try testing.expectEqual(SignalingState.have_local_offer, pc.signaling_state);
    try testing.expect(pc.pending_local_description != null);
}

test "RFC9429: setRemoteDescription(answer) transitions have_local_offer -> stable" {
    var pc = PeerConnection.init(testing.allocator, .{});
    defer pc.deinit();

    const offer = try pc.createOffer();
    try pc.setLocalDescription(offer, .offer);
    try testing.expectEqual(SignalingState.have_local_offer, pc.signaling_state);

    const answer_sdp = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\na=group:BUNDLE 0\r\na=setup:active\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\nc=IN IP4 0.0.0.0\r\na=mid:0\r\n";
    const answer = try sdp.SessionDescription.parse(testing.allocator, answer_sdp);
    try pc.setRemoteDescription(answer, .answer);

    try testing.expectEqual(SignalingState.stable, pc.signaling_state);
    try testing.expect(pc.local_description != null);
    try testing.expect(pc.remote_description != null);
    try testing.expect(pc.pending_local_description == null);
    try testing.expect(pc.pending_remote_description == null);
}

test "RFC9429: setRemoteDescription(offer) transitions stable -> have_remote_offer" {
    var pc = PeerConnection.init(testing.allocator, .{});
    defer pc.deinit();

    const remote_sdp = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\nc=IN IP4 0.0.0.0\r\na=mid:0\r\n";
    const remote_offer = try sdp.SessionDescription.parse(testing.allocator, remote_sdp);
    try pc.setRemoteDescription(remote_offer, .offer);

    try testing.expectEqual(SignalingState.have_remote_offer, pc.signaling_state);
    try testing.expect(pc.pending_remote_description != null);
}

test "RFC9429: setLocalDescription(answer) transitions have_remote_offer -> stable" {
    var pc = PeerConnection.init(testing.allocator, .{});
    defer pc.deinit();

    const remote_sdp = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\nc=IN IP4 0.0.0.0\r\na=mid:0\r\n";
    const remote_offer = try sdp.SessionDescription.parse(testing.allocator, remote_sdp);
    try pc.setRemoteDescription(remote_offer, .offer);

    const answer = try pc.createAnswer();
    try pc.setLocalDescription(answer, .answer);

    try testing.expectEqual(SignalingState.stable, pc.signaling_state);
    try testing.expect(pc.local_description != null);
    try testing.expect(pc.remote_description != null);
}

test "RFC9429: invalid — setLocalDescription(answer) in stable" {
    var pc = PeerConnection.init(testing.allocator, .{});
    defer pc.deinit();

    const fake_sdp = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\nc=IN IP4 0.0.0.0\r\na=mid:0\r\n";
    // Transition fails, desc NOT stored — test must free
    var desc = try sdp.SessionDescription.parse(testing.allocator, fake_sdp);
    defer desc.deinit(testing.allocator);

    const result = pc.setLocalDescription(desc, .answer);
    try testing.expectError(PeerError.InvalidStateTransition, result);
    try testing.expectEqual(SignalingState.stable, pc.signaling_state);
}

test "RFC9429: invalid — setRemoteDescription(answer) in stable" {
    var pc = PeerConnection.init(testing.allocator, .{});
    defer pc.deinit();

    const fake_sdp = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\nc=IN IP4 0.0.0.0\r\na=mid:0\r\n";
    var desc = try sdp.SessionDescription.parse(testing.allocator, fake_sdp);
    defer desc.deinit(testing.allocator);

    const result = pc.setRemoteDescription(desc, .answer);
    try testing.expectError(PeerError.InvalidStateTransition, result);
}

test "RFC9429: invalid — setLocalDescription(pranswer) in stable" {
    var pc = PeerConnection.init(testing.allocator, .{});
    defer pc.deinit();

    const fake_sdp = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\nc=IN IP4 0.0.0.0\r\na=mid:0\r\n";
    var desc = try sdp.SessionDescription.parse(testing.allocator, fake_sdp);
    defer desc.deinit(testing.allocator);

    const result = pc.setLocalDescription(desc, .pranswer);
    try testing.expectError(PeerError.InvalidStateTransition, result);
}

test "RFC9429: invalid — rollback in stable" {
    var pc = PeerConnection.init(testing.allocator, .{});
    defer pc.deinit();

    const fake_sdp = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\nc=IN IP4 0.0.0.0\r\na=mid:0\r\n";
    var desc = try sdp.SessionDescription.parse(testing.allocator, fake_sdp);
    defer desc.deinit(testing.allocator);

    try testing.expectError(PeerError.InvalidStateTransition, pc.setLocalDescription(desc, .rollback));
    try testing.expectError(PeerError.InvalidStateTransition, pc.setRemoteDescription(desc, .rollback));
}

test "RFC9429: close from any state transitions to closed" {
    {
        var pc = PeerConnection.init(testing.allocator, .{});
        pc.close();
        try testing.expectEqual(SignalingState.closed, pc.signaling_state);
        try testing.expectEqual(ConnectionState.closed, pc.connection_state);
        pc.deinit();
    }
    {
        var pc = PeerConnection.init(testing.allocator, .{});
        const offer = try pc.createOffer();
        try pc.setLocalDescription(offer, .offer);
        pc.close();
        try testing.expectEqual(SignalingState.closed, pc.signaling_state);
        pc.deinit();
    }
    {
        var pc = PeerConnection.init(testing.allocator, .{});
        const remote_sdp = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\nc=IN IP4 0.0.0.0\r\na=mid:0\r\n";
        const remote_offer = try sdp.SessionDescription.parse(testing.allocator, remote_sdp);
        try pc.setRemoteDescription(remote_offer, .offer);
        pc.close();
        try testing.expectEqual(SignalingState.closed, pc.signaling_state);
        pc.deinit();
    }
}

test "RFC9429: operations on closed PeerConnection return ConnectionClosed" {
    var pc = PeerConnection.init(testing.allocator, .{});
    pc.close();

    try testing.expectError(PeerError.ConnectionClosed, pc.createOffer());
    try testing.expectError(PeerError.ConnectionClosed, pc.createAnswer());

    // These fail before storing — test must free
    const fake_sdp = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\nc=IN IP4 0.0.0.0\r\na=mid:0\r\n";
    var desc = try sdp.SessionDescription.parse(testing.allocator, fake_sdp);
    defer desc.deinit(testing.allocator);

    try testing.expectError(PeerError.ConnectionClosed, pc.setLocalDescription(desc, .offer));
    try testing.expectError(PeerError.ConnectionClosed, pc.setRemoteDescription(desc, .offer));

    const candidate = ice.Candidate.initHostV4(.{ 127, 0, 0, 1 }, 5000, 1, "abc");
    try testing.expectError(PeerError.ConnectionClosed, pc.addIceCandidate(candidate));

    pc.deinit();
}

test "RFC9429: close is idempotent" {
    var pc = PeerConnection.init(testing.allocator, .{});
    pc.close();
    pc.close();
    try testing.expectEqual(SignalingState.closed, pc.signaling_state);
    pc.deinit();
}

test "RFC9429: createOffer generates SDP with BUNDLE and setup:actpass" {
    var pc = PeerConnection.init(testing.allocator, .{});
    defer pc.deinit();

    const offer = try pc.createOffer();
    defer @constCast(&offer).deinit(testing.allocator);

    var has_bundle = false;
    var has_setup_actpass = false;
    var has_ice_ufrag = false;
    var has_ice_pwd = false;
    for (offer.attributes) |attr| {
        if (std.mem.eql(u8, attr.name, "group")) {
            if (attr.value) |v| {
                if (std.mem.startsWith(u8, v, "BUNDLE")) has_bundle = true;
            }
        }
        if (std.mem.eql(u8, attr.name, "setup")) {
            if (attr.value) |v| {
                if (std.mem.eql(u8, v, "actpass")) has_setup_actpass = true;
            }
        }
        if (std.mem.eql(u8, attr.name, "ice-ufrag")) has_ice_ufrag = true;
        if (std.mem.eql(u8, attr.name, "ice-pwd")) has_ice_pwd = true;
    }
    try testing.expect(has_bundle);
    try testing.expect(has_setup_actpass);
    try testing.expect(has_ice_ufrag);
    try testing.expect(has_ice_pwd);
}

test "RFC9429: createAnswer generates SDP with setup:active" {
    var pc = PeerConnection.init(testing.allocator, .{});
    defer pc.deinit();

    const remote_sdp = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\nc=IN IP4 0.0.0.0\r\na=mid:0\r\n";
    const remote_offer = try sdp.SessionDescription.parse(testing.allocator, remote_sdp);
    try pc.setRemoteDescription(remote_offer, .offer);

    // answer NOT stored — test must free
    const answer = try pc.createAnswer();
    defer @constCast(&answer).deinit(testing.allocator);

    var has_setup_active = false;
    for (answer.attributes) |attr| {
        if (std.mem.eql(u8, attr.name, "setup")) {
            if (attr.value) |v| {
                if (std.mem.eql(u8, v, "active")) has_setup_active = true;
            }
        }
    }
    try testing.expect(has_setup_active);
}

test "RFC9429: each createOffer generates fresh ICE credentials" {
    var pc = PeerConnection.init(testing.allocator, .{});
    defer pc.deinit();

    const ufrag1 = pc.local_ufrag;
    const offer = try pc.createOffer();
    defer @constCast(&offer).deinit(testing.allocator);
    const ufrag2 = pc.local_ufrag;

    try testing.expect(!std.mem.eql(u8, &ufrag1, &ufrag2));
}

test "RFC9429: rollback from have_local_offer -> stable" {
    var pc = PeerConnection.init(testing.allocator, .{});
    defer pc.deinit();

    const offer = try pc.createOffer();
    try pc.setLocalDescription(offer, .offer);
    try testing.expectEqual(SignalingState.have_local_offer, pc.signaling_state);

    // rollback doesn't store desc — test must free
    const fake_sdp = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\nc=IN IP4 0.0.0.0\r\na=mid:0\r\n";
    var desc = try sdp.SessionDescription.parse(testing.allocator, fake_sdp);
    defer desc.deinit(testing.allocator);

    try pc.setLocalDescription(desc, .rollback);
    try testing.expectEqual(SignalingState.stable, pc.signaling_state);
    try testing.expect(pc.pending_local_description == null);
}

test "RFC9429: Config with ICE servers" {
    const servers = [_]IceServer{
        .{
            .urls = &.{"stun:stun.l.google.com:19302"},
            .username = null,
            .credential = null,
        },
        .{
            .urls = &.{ "turn:turn.example.com:3478", "turns:turn.example.com:5349" },
            .username = "user",
            .credential = "pass",
        },
    };

    var pc = PeerConnection.init(testing.allocator, .{
        .ice_servers = &servers,
        .ice_transport_policy = .relay,
    });
    defer pc.deinit();

    try testing.expectEqual(@as(usize, 2), pc.config.ice_servers.len);
    try testing.expectEqual(IceTransportPolicy.relay, pc.config.ice_transport_policy);
    try testing.expectEqualStrings("stun:stun.l.google.com:19302", pc.config.ice_servers[0].urls[0]);
    try testing.expectEqualStrings("user", pc.config.ice_servers[1].username.?);
}

test "RFC9429: full offer/answer exchange" {
    var offerer = PeerConnection.init(testing.allocator, .{});
    defer offerer.deinit();

    const offer = try offerer.createOffer();
    try offerer.setLocalDescription(offer, .offer);
    try testing.expectEqual(SignalingState.have_local_offer, offerer.signaling_state);

    var answerer = PeerConnection.init(testing.allocator, .{});
    defer answerer.deinit();

    const offer_text = offerer.sdp_buf.?;
    const remote_offer = try sdp.SessionDescription.parse(testing.allocator, offer_text);
    try answerer.setRemoteDescription(remote_offer, .offer);
    try testing.expectEqual(SignalingState.have_remote_offer, answerer.signaling_state);

    const answer = try answerer.createAnswer();
    try answerer.setLocalDescription(answer, .answer);
    try testing.expectEqual(SignalingState.stable, answerer.signaling_state);

    const answer_text = answerer.sdp_buf.?;
    const remote_answer = try sdp.SessionDescription.parse(testing.allocator, answer_text);
    try offerer.setRemoteDescription(remote_answer, .answer);
    try testing.expectEqual(SignalingState.stable, offerer.signaling_state);
}

test "RFC9429: pranswer transitions" {
    var pc = PeerConnection.init(testing.allocator, .{});
    defer pc.deinit();

    const remote_sdp = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\nc=IN IP4 0.0.0.0\r\na=mid:0\r\n";
    const remote_offer = try sdp.SessionDescription.parse(testing.allocator, remote_sdp);
    try pc.setRemoteDescription(remote_offer, .offer);
    try testing.expectEqual(SignalingState.have_remote_offer, pc.signaling_state);

    const pranswer = try pc.createAnswer();
    try pc.setLocalDescription(pranswer, .pranswer);
    try testing.expectEqual(SignalingState.have_local_pranswer, pc.signaling_state);

    const final_answer = try pc.createAnswer();
    try pc.setLocalDescription(final_answer, .answer);
    try testing.expectEqual(SignalingState.stable, pc.signaling_state);
}

test "RFC9429: addIceCandidate adds to ICE agent" {
    var pc = PeerConnection.init(testing.allocator, .{});
    defer pc.deinit();

    const candidate = ice.Candidate.initHostV4(.{ 192, 168, 1, 1 }, 5000, 1, "host1");
    try pc.addIceCandidate(candidate);

    try testing.expectEqual(@as(usize, 1), pc.ice_agent.remote_candidates.items.len);
}

// ============================================================================
// Tests — Media Tracks & SDP Audio/Video Negotiation
// ============================================================================

test "SDP: createOffer with audio track produces audio m= line" {
    var pc = PeerConnection.init(testing.allocator, .{});
    defer pc.deinit();

    pc.addAudioTrack(12345);

    const offer = try pc.createOffer();
    defer @constCast(&offer).deinit(testing.allocator);

    // Should have 2 media sections: audio + datachannel
    try testing.expectEqual(@as(usize, 2), offer.media.len);
    try testing.expectEqualStrings("audio", offer.media[0].media_type);
    try testing.expectEqualStrings("UDP/TLS/RTP/SAVPF", offer.media[0].proto);
    try testing.expectEqualStrings("111", offer.media[0].formats[0]);
    try testing.expectEqualStrings("application", offer.media[1].media_type);
}

test "SDP: createOffer with video track produces video m= line" {
    var pc = PeerConnection.init(testing.allocator, .{});
    defer pc.deinit();

    pc.addVideoTrack(12346);

    const offer = try pc.createOffer();
    defer @constCast(&offer).deinit(testing.allocator);

    // Should have 2 media sections: video + datachannel
    try testing.expectEqual(@as(usize, 2), offer.media.len);
    try testing.expectEqualStrings("video", offer.media[0].media_type);
    try testing.expectEqualStrings("UDP/TLS/RTP/SAVPF", offer.media[0].proto);
    try testing.expectEqualStrings("96", offer.media[0].formats[0]);
    try testing.expectEqualStrings("application", offer.media[1].media_type);
}

test "SDP: createOffer with audio+video produces correct m= lines and MIDs" {
    var pc = PeerConnection.init(testing.allocator, .{});
    defer pc.deinit();

    pc.addAudioTrack(12345);
    pc.addVideoTrack(12346);

    const offer = try pc.createOffer();
    defer @constCast(&offer).deinit(testing.allocator);

    // Should have 3 media sections: audio, video, datachannel
    try testing.expectEqual(@as(usize, 3), offer.media.len);
    try testing.expectEqualStrings("audio", offer.media[0].media_type);
    try testing.expectEqualStrings("video", offer.media[1].media_type);
    try testing.expectEqualStrings("application", offer.media[2].media_type);

    // Verify BUNDLE group includes all MIDs
    var has_bundle_012 = false;
    for (offer.attributes) |attr| {
        if (std.mem.eql(u8, attr.name, "group")) {
            if (attr.value) |v| {
                if (std.mem.eql(u8, v, "BUNDLE 0 1 2")) has_bundle_012 = true;
            }
        }
    }
    try testing.expect(has_bundle_012);

    // Verify MIDs: audio=0, video=1, datachannel=2
    var audio_mid: ?[]const u8 = null;
    for (offer.media[0].attributes) |attr| {
        if (std.mem.eql(u8, attr.name, "mid")) audio_mid = attr.value;
    }
    try testing.expectEqualStrings("0", audio_mid.?);

    var video_mid: ?[]const u8 = null;
    for (offer.media[1].attributes) |attr| {
        if (std.mem.eql(u8, attr.name, "mid")) video_mid = attr.value;
    }
    try testing.expectEqualStrings("1", video_mid.?);

    var dc_mid: ?[]const u8 = null;
    for (offer.media[2].attributes) |attr| {
        if (std.mem.eql(u8, attr.name, "mid")) dc_mid = attr.value;
    }
    try testing.expectEqualStrings("2", dc_mid.?);
}

test "SDP: audio codec attributes (rtpmap, fmtp, rtcp-fb)" {
    var pc = PeerConnection.init(testing.allocator, .{});
    defer pc.deinit();

    pc.addAudioTrack(12345);

    const offer = try pc.createOffer();
    defer @constCast(&offer).deinit(testing.allocator);

    const audio = offer.media[0];
    var has_rtpmap = false;
    var has_fmtp = false;
    var has_nack = false;
    var has_ssrc = false;
    for (audio.attributes) |attr| {
        if (std.mem.eql(u8, attr.name, "rtpmap")) {
            if (attr.value) |v| {
                if (std.mem.eql(u8, v, "111 opus/48000/2")) has_rtpmap = true;
            }
        }
        if (std.mem.eql(u8, attr.name, "fmtp")) {
            if (attr.value) |v| {
                if (std.mem.eql(u8, v, "111 minptime=10;useinbandfec=1")) has_fmtp = true;
            }
        }
        if (std.mem.eql(u8, attr.name, "rtcp-fb")) {
            if (attr.value) |v| {
                if (std.mem.eql(u8, v, "111 nack")) has_nack = true;
            }
        }
        if (std.mem.eql(u8, attr.name, "ssrc")) {
            if (attr.value) |v| {
                if (std.mem.eql(u8, v, "12345 cname:zig-webrtc")) has_ssrc = true;
            }
        }
    }
    try testing.expect(has_rtpmap);
    try testing.expect(has_fmtp);
    try testing.expect(has_nack);
    try testing.expect(has_ssrc);
}

test "SDP: video codec attributes (rtpmap, rtcp-fb nack/pli/fir)" {
    var pc = PeerConnection.init(testing.allocator, .{});
    defer pc.deinit();

    pc.addVideoTrack(12346);

    const offer = try pc.createOffer();
    defer @constCast(&offer).deinit(testing.allocator);

    const video = offer.media[0]; // only video + dc, so video is [0]
    var has_rtpmap = false;
    var has_nack = false;
    var has_nack_pli = false;
    var has_ccm_fir = false;
    var has_ssrc = false;
    for (video.attributes) |attr| {
        if (std.mem.eql(u8, attr.name, "rtpmap")) {
            if (attr.value) |v| {
                if (std.mem.eql(u8, v, "96 VP8/90000")) has_rtpmap = true;
            }
        }
        if (std.mem.eql(u8, attr.name, "rtcp-fb")) {
            if (attr.value) |v| {
                if (std.mem.eql(u8, v, "96 nack")) has_nack = true;
                if (std.mem.eql(u8, v, "96 nack pli")) has_nack_pli = true;
                if (std.mem.eql(u8, v, "96 ccm fir")) has_ccm_fir = true;
            }
        }
        if (std.mem.eql(u8, attr.name, "ssrc")) {
            if (attr.value) |v| {
                if (std.mem.eql(u8, v, "12346 cname:zig-webrtc")) has_ssrc = true;
            }
        }
    }
    try testing.expect(has_rtpmap);
    try testing.expect(has_nack);
    try testing.expect(has_nack_pli);
    try testing.expect(has_ccm_fir);
    try testing.expect(has_ssrc);
}

test "SDP: no tracks produces datachannel-only offer (backward compat)" {
    var pc = PeerConnection.init(testing.allocator, .{});
    defer pc.deinit();

    const offer = try pc.createOffer();
    defer @constCast(&offer).deinit(testing.allocator);

    try testing.expectEqual(@as(usize, 1), offer.media.len);
    try testing.expectEqualStrings("application", offer.media[0].media_type);
}

test "SDP: addAudioTrack / addVideoTrack store tracks correctly" {
    var pc = PeerConnection.init(testing.allocator, .{});
    defer pc.deinit();

    try testing.expect(pc.audio_track == null);
    try testing.expect(pc.video_track == null);

    pc.addAudioTrack(1000);
    try testing.expectEqual(@as(u32, 1000), pc.audio_track.?.ssrc);
    try testing.expectEqual(MediaType.audio, pc.audio_track.?.media_type);

    pc.addVideoTrack(2000);
    try testing.expectEqual(@as(u32, 2000), pc.video_track.?.ssrc);
    try testing.expectEqual(MediaType.video, pc.video_track.?.media_type);
}
