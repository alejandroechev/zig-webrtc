#!/usr/bin/env node
//
// test-sdp-exchange.js — validates SDP offer produced by the Zig interop agent.
//
// Flow:
//   1. Start signaling server
//   2. Start Zig agent (via zig-wrapper.js)
//   3. Connect a test client to signaling as "browser" peer
//   4. Capture the SDP offer that Zig produces
//   5. Validate it's valid SDP (v=, o=, s=, m= etc.)
//   6. Send a mock answer back
//   7. Verify Zig processes it without error (status: answer-applied)
//   8. Clean up

const { spawn } = require("child_process");
const WebSocket = require("ws");
const assert = require("assert");
const path = require("path");

const SIGNALING_PORT = 8080;
const TIMEOUT_MS = 30_000;

// ── SDP Validation ──────────────────────────────────────────────────

function validateZigSdpOffer(sdp) {
  assert(sdp.includes("v=0"), "SDP must start with v=0");
  assert(sdp.includes("o="), "SDP must have o= line");
  assert(sdp.includes("s="), "SDP must have s= line");
  assert(sdp.includes("m="), "SDP must have at least one m= line");
  assert(sdp.includes("a=ice-ufrag:"), "SDP must have ICE ufrag");
  assert(sdp.includes("a=ice-pwd:"), "SDP must have ICE password");
  assert(
    sdp.includes("a=setup:actpass"),
    "Offer must have a=setup:actpass (RFC 9429)"
  );
  assert(
    sdp.includes("a=group:BUNDLE"),
    "Offer must have BUNDLE group (RFC 8843)"
  );
  console.log("  ✅ All SDP validation checks passed");
}

// ── Mock SDP answer ─────────────────────────────────────────────────

function createMockAnswer(offerSdp) {
  // Build a minimal valid SDP answer from the offer.
  // Extract ice-ufrag and ice-pwd from the offer so the answer references them.
  const ufragMatch = offerSdp.match(/a=ice-ufrag:(\S+)/);
  const pwdMatch = offerSdp.match(/a=ice-pwd:(\S+)/);
  const fingerprintMatch = offerSdp.match(/a=fingerprint:(\S+ \S+)/);

  const ufrag = "mock" + Math.random().toString(36).slice(2, 8);
  const pwd = "mockpwd" + Math.random().toString(36).slice(2, 18);
  const fingerprint = fingerprintMatch
    ? fingerprintMatch[1]
    : "sha-256 00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00";

  return [
    "v=0",
    "o=- 1234567890 2 IN IP4 127.0.0.1",
    "s=-",
    "t=0 0",
    "a=group:BUNDLE 0",
    "a=msid-semantic: WMS",
    "m=application 9 UDP/DTLS/SCTP webrtc-datachannel",
    "c=IN IP4 0.0.0.0",
    "a=ice-ufrag:" + ufrag,
    "a=ice-pwd:" + pwd,
    "a=fingerprint:" + fingerprint,
    "a=setup:active",
    "a=mid:0",
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
    proc.stderr.on("data", (data) => {
      if (!started) {
        // signaling server logs to stdout, but just in case
      }
    });
    proc.on("error", reject);
    // Also listen on stderr for the "Signaling server" line (it uses console.log → stdout)
    setTimeout(() => {
      if (!started) {
        started = true;
        resolve(proc); // assume it started
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

async function runSdpExchangeTest() {
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

    // 3. Connect as "browser" peer and wait for offer
    console.log("  Connecting test client as browser peer...");

    const result = await new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        reject(new Error("Timeout waiting for SDP exchange"));
      }, TIMEOUT_MS);

      ws = new WebSocket(`ws://localhost:${SIGNALING_PORT}?role=browser`);

      ws.on("error", (err) => {
        clearTimeout(timer);
        reject(new Error(`WebSocket error: ${err.message}`));
      });

      let offerValidated = false;

      ws.on("message", (data) => {
        const msg = JSON.parse(data.toString());

        if (msg.type === "offer" && !offerValidated) {
          console.log("  Received SDP offer from Zig agent");

          // 4. Validate the SDP
          validateZigSdpOffer(msg.sdp);
          offerValidated = true;

          // 5. Send mock answer
          const answer = createMockAnswer(msg.sdp);
          console.log("  Sending mock SDP answer...");
          ws.send(JSON.stringify({ type: "answer", sdp: answer }));
        }

        // The Zig agent sends a data message after processing the answer
        // (status messages stay in the wrapper, only offer/answer/ice/data are relayed)
        if (msg.type === "data" && offerValidated) {
          console.log(`  ✅ Zig agent sent data: "${msg.message}"`);
          clearTimeout(timer);
          resolve({ success: true, zigMessage: msg.message });
        }
      });
    });

    assert(result.success, "SDP exchange must succeed");
    console.log("  ✅ SDP Exchange Test PASSED");
  } finally {
    cleanup();
    // Give processes time to terminate
    await new Promise((r) => setTimeout(r, 500));
  }
}

// ── Entry point ──────────────────────────────────────────────────────

if (require.main === module) {
  console.log("=== SDP Exchange Validation Test ===\n");
  runSdpExchangeTest()
    .then(() => {
      console.log("\n✅ Test passed");
      process.exit(0);
    })
    .catch((err) => {
      console.error(`\n❌ Test failed: ${err.message}`);
      process.exit(1);
    });
}

module.exports = { runSdpExchangeTest, validateZigSdpOffer };
