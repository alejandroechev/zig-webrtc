# zig-webrtc

A WebRTC library for Zig, built using structured RFC rules as specification.

## Status: Early Development

This library is being built as a proof of concept for using structured RFC rules as an AI grounding layer. Every protocol module is generated from the [RFC Compliance API](https://github.com/alejandroechev/rfc) which contains 2,869 structured rules from 37 WebRTC-related RFCs.

## Architecture

Modular protocol stack:
- **stun** — STUN message parsing/building (RFC 5389)
- **turn** — TURN relay client (RFC 8656)
- **ice** — ICE agent (RFC 8445)
- **sdp** — SDP parser/serializer (RFC 8866, 3264)
- **dtls** — DTLS wrapper over OpenSSL (RFC 6347)
- **srtp** — SRTP encryption (RFC 3711)
- **rtp** — RTP/RTCP parsing (RFC 3550)
- **sctp** — SCTP association (RFC 4960)
- **datachannel** — WebRTC Data Channels (RFC 8831)
- **peer** — PeerConnection orchestrator (RFC 9429)

## Dependencies

- Zig 0.14+
- OpenSSL (system library)
- libopus (optional, for audio)
- libvpx (optional, for video)

## Building

```bash
zig build
zig build test
zig build run
```
