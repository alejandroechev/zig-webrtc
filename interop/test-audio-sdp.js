#!/usr/bin/env node
//
// test-audio-sdp.js — validates the Zig interop agent's SDP includes audio.
//
// The agent now adds an audio track (Opus) before creating the SDP offer,
// so the offer must include:
//   - m=audio ... UDP/TLS/RTP/SAVPF 111
//   - a=rtpmap:111 opus/48000/2
//   - a=fmtp:111 (Opus parameters)
//   - a=ssrc: (audio SSRC)
//   - a=mid: (BUNDLE media ID)
//   - m=application (data channel still present)
//   - a=group:BUNDLE (both audio + data channel)
//
// Additionally, verifies that after receiving an answer the agent
// initializes the audio pipeline and encodes Opus frames.

const { spawn } = require("child_process");
const WebSocket = require("ws");
const assert = require("assert");
const path = require("path");

const SIGNALING_PORT = 8080;
const TIMEOUT_MS = 30_000;

// ── Audio SDP Validation ────────────────────────────────────────────

function validateAudioSdp(sdp) {
  // Must have audio m= line
  assert(sdp.includes("m=audio"), "SDP must have audio m= line");
  assert(
    sdp.includes("UDP/TLS/RTP/SAVPF"),
    "Audio must use SAVPF profile"
  );
  assert(
    sdp.includes("a=rtpmap:111 opus/48000/2"),
    "Must offer Opus codec (PT 111)"
  );
  assert(sdp.includes("a=fmtp:111"), "Must have Opus fmtp parameters");
  assert(sdp.includes("a=mid:"), "Must have mid attribute");
  assert(sdp.includes("a=ssrc:"), "Must have SSRC");

  // Must still have data channel
  assert(sdp.includes("m=application"), "Must still have data channel m= line");

  // BUNDLE must include both audio and data channel MIDs
  assert(sdp.includes("a=group:BUNDLE"), "Must have BUNDLE group");

  // Verify BUNDLE lists multiple MIDs (audio + datachannel)
  const bundleMatch = sdp.match(/a=group:BUNDLE\s+(.+)/);
  assert(bundleMatch, "BUNDLE group must have MID list");
  const mids = bundleMatch[1].trim().split(/\s+/);
  assert(mids.length >= 2, `BUNDLE must list ≥2 MIDs (got ${mids.length})`);

  // Verify Opus-specific attributes
  assert(
    sdp.includes("a=rtcp-fb:111 nack"),
    "Must have RTCP feedback for Opus"
  );

  console.log("  ✅ Audio SDP validation passed");
}

// ── Mock SDP answer with audio ──────────────────────────────────────

function createMockAudioAnswer(offerSdp) {
  const fingerprintMatch = (offerSdp || "").match(/a=fingerprint:([^\r\n]+)/);
  const fingerprint = fingerprintMatch
    ? fingerprintMatch[1]
    : "sha-256 00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00";

  const ufrag = "mock" + Math.random().toString(36).slice(2, 8);
  const pwd = "mockpwd" + Math.random().toString(36).slice(2, 18);

  // Match the MID structure from the offer (audio=0, datachannel=1)
  return [
    "v=0",
    "o=- 9876543210 2 IN IP4 127.0.0.1",
    "s=-",
    "t=0 0",
    "a=group:BUNDLE 0 1",
    "a=msid-semantic: WMS",
    "m=audio 9 UDP/TLS/RTP/SAVPF 111",
    "c=IN IP4 0.0.0.0",
    "a=ice-ufrag:" + ufrag,
    "a=ice-pwd:" + pwd,
    "a=fingerprint:" + fingerprint,
    "a=setup:active",
    "a=mid:0",
    "a=rtpmap:111 opus/48000/2",
    "a=fmtp:111 minptime=10;useinbandfec=1",
    "m=application 9 UDP/DTLS/SCTP webrtc-datachannel",
    "c=IN IP4 0.0.0.0",
    "a=mid:1",
    "a=sctp-port:5000",
    "",
  ].join("\r\n");
}

// ── Process Management ──────────────────────────────────────────────

function startSignalingServer() {
  const proc = spawn("node", [path.join(__dirname, "signaling-server.js")], {
    stdio: ["ignore", "pipe", "pipe"],
    cwd: __dirname,
  });
  return new Promise((resolve, reject) => {
    let started = false;
    proc.stdout.on("data", (data) => {
      if (!started && data.toString().includes("localhost")) {
        started = true;
        resolve(proc);
      }
    });
    proc.on("error", reject);
    setTimeout(() => {
      if (!started) {
        started = true;
        resolve(proc);
      }
    }, 2000);
  });
}

function startZigWrapper() {
  const proc = spawn("node", [path.join(__dirname, "zig-wrapper.js")], {
    stdio: ["ignore", "pipe", "pipe"],
    cwd: path.join(__dirname, ".."),
  });
  return proc;
}

function killProc(proc) {
  if (proc && !proc.killed) {
    proc.kill();
  }
}

// ── Test ─────────────────────────────────────────────────────────────

async function runAudioSdpTest() {
  let signalingProc = null;
  let zigProc = null;
  let ws = null;

  const cleanup = () => {
    if (ws && ws.readyState <= WebSocket.OPEN) ws.close();
    killProc(zigProc);
    killProc(signalingProc);
  };

  try {
    // 1. Start signaling server
    console.log("  Starting signaling server...");
    signalingProc = await startSignalingServer();

    // 2. Start Zig agent (connects as "zig" peer)
    console.log("  Starting Zig agent...");
    zigProc = startZigWrapper();

    // Give the Zig agent time to connect
    await new Promise((r) => setTimeout(r, 2000));

    // 3. Connect as "browser" peer and validate audio SDP
    console.log("  Connecting test client as browser peer...");

    const result = await new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        reject(new Error("Timeout waiting for audio SDP exchange"));
      }, TIMEOUT_MS);

      ws = new WebSocket(`ws://localhost:${SIGNALING_PORT}?role=browser`);

      ws.on("error", (err) => {
        clearTimeout(timer);
        reject(new Error(`WebSocket error: ${err.message}`));
      });

      let offerValidated = false;
      let audioFramesEncoded = false;

      ws.on("message", (data) => {
        const msg = JSON.parse(data.toString());

        if (msg.type === "offer" && !offerValidated) {
          console.log("  Received SDP offer from Zig agent");

          // Validate audio-specific SDP content
          validateAudioSdp(msg.sdp);
          offerValidated = true;

          // Send mock answer with audio support
          const answer = createMockAudioAnswer(msg.sdp);
          console.log("  Sending mock SDP answer (with audio)...");
          ws.send(JSON.stringify({ type: "answer", sdp: answer }));
        }

        if (msg.type === "audio-status" && offerValidated) {
          console.log(`  Audio status: ${msg.message} (packets=${msg.packets}, bytes=${msg.bytes})`);

          if (msg.message === "frames-encoded" && msg.packets > 0) {
            audioFramesEncoded = true;
            console.log(`  ✅ Audio pipeline produced ${msg.packets} Opus/RTP packets (${msg.bytes} bytes)`);
          }
        }

        // The Zig agent sends a data message after processing the answer
        if (msg.type === "data" && offerValidated) {
          console.log(`  ✅ Zig agent sent data: "${msg.message}"`);

          // Wait briefly for audio-status messages to arrive
          setTimeout(() => {
            clearTimeout(timer);
            resolve({
              success: true,
              zigMessage: msg.message,
              audioEncoded: audioFramesEncoded,
            });
          }, 1000);
        }
      });
    });

    assert(result.success, "Audio SDP exchange must succeed");
    assert(result.audioEncoded, "Audio pipeline must encode at least one Opus frame");
    console.log("  ✅ Audio SDP Interop Test PASSED");
  } finally {
    cleanup();
    await new Promise((r) => setTimeout(r, 500));
  }
}

// ── Entry point ──────────────────────────────────────────────────────

if (require.main === module) {
  console.log("=== Audio SDP Interop Test ===\n");
  runAudioSdpTest()
    .then(() => {
      console.log("\n✅ Test passed");
      process.exit(0);
    })
    .catch((err) => {
      console.error(`\n❌ Test failed: ${err.message}`);
      process.exit(1);
    });
}

module.exports = { runAudioSdpTest, validateAudioSdp };
