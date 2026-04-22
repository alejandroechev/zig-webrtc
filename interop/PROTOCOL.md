# Signaling Protocol

WebSocket messages between Zig peer and browser peer.

## Messages

### Offer (Zig → Browser)
```json
{ "type": "offer", "sdp": "v=0\r\n..." }
```

### Answer (Browser → Zig)
```json
{ "type": "answer", "sdp": "v=0\r\n..." }
```

### ICE Candidate (bidirectional)
```json
{ "type": "ice-candidate", "candidate": { "candidate": "...", "sdpMid": "0", "sdpMLineIndex": 0 } }
```

## Flow
1. Zig connects to ws://localhost:8080
2. Browser connects to ws://localhost:8080
3. Zig creates offer, sends via signaling
4. Browser receives offer, creates answer, sends via signaling
5. Both exchange ICE candidates
6. ICE + DTLS completes
7. Data channel opens
8. Messages exchanged
