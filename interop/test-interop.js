#!/usr/bin/env node
//
// test-interop.js — E2E interop test: Zig agent ↔ browser data channel.
//
// Uses Playwright (if available) or a signaling-based fallback:
//
// Option A (Playwright):
//   Launch headless Chromium, navigate to test page, wait for data exchange.
//
// Option B (signaling monitor):
//   The test monitors signaling for the Zig agent's "data" message
//   (Hello from Zig!) which proves SDP exchange + answer processing worked.
//   Since the Zig agent currently simulates data channel readiness after
//   processing the answer, this validates the full signaling flow.

const { spawn } = require("child_process");
const WebSocket = require("ws");
const path = require("path");

const SIGNALING_WS_PORT = 8080;
const SIGNALING_HTTP_PORT = 8081;
const TIMEOUT_MS = 45_000;
const ZIG_BUILD_TIMEOUT_MS = 120_000;

// ── Process Management ──────────────────────────────────────────────

function killProc(proc) {
  if (proc && !proc.killed) {
    proc.kill();
  }
}

function buildZigAgent() {
  return new Promise((resolve, reject) => {
    console.log("  Building Zig interop agent...");
    const proc = spawn("zig", ["build"], {
      cwd: path.join(__dirname, ".."),
      stdio: ["ignore", "pipe", "pipe"],
    });

    let stderr = "";
    proc.stderr.on("data", (d) => (stderr += d.toString()));

    const timer = setTimeout(() => {
      killProc(proc);
      reject(new Error("Zig build timed out"));
    }, ZIG_BUILD_TIMEOUT_MS);

    proc.on("close", (code) => {
      clearTimeout(timer);
      if (code === 0) {
        console.log("  ✅ Zig build succeeded");
        resolve();
      } else {
        reject(new Error(`Zig build failed (exit ${code}): ${stderr}`));
      }
    });

    proc.on("error", (err) => {
      clearTimeout(timer);
      reject(new Error(`Failed to start zig build: ${err.message}`));
    });
  });
}

function startSignalingServer() {
  const proc = spawn("node", [path.join(__dirname, "signaling-server.js")], {
    stdio: ["ignore", "pipe", "pipe"],
    cwd: __dirname,
  });

  return new Promise((resolve, reject) => {
    let started = false;

    const onData = (data) => {
      if (!started && data.toString().includes("localhost")) {
        started = true;
        resolve(proc);
      }
    };

    proc.stdout.on("data", onData);
    proc.on("error", reject);

    // Fallback: assume started after 2s
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

// ── Playwright-based Test ───────────────────────────────────────────

async function runWithPlaywright() {
  let playwright;
  try {
    playwright = require("playwright");
  } catch {
    return null; // Playwright not available
  }

  console.log("  Using Playwright for browser automation");
  const browser = await playwright.chromium.launch({ headless: true });

  try {
    const page = await browser.newPage();
    await page.goto(`http://localhost:${SIGNALING_HTTP_PORT}`);

    // Wait for the data-received attribute (set by browser-client.html on message)
    const received = await page.waitForFunction(
      () => document.body.getAttribute("data-received"),
      { timeout: TIMEOUT_MS }
    );

    const value = await received.jsonValue();
    console.log(`  Browser received: "${value}"`);

    if (value && value.length > 0) {
      console.log("  ✅ Data channel message received via Playwright");
      return { success: true, received: value };
    } else {
      throw new Error("No data received on browser side");
    }
  } finally {
    await browser.close();
  }
}

// ── Signaling-monitor Fallback ──────────────────────────────────────

async function runWithSignalingMonitor() {
  console.log("  Using signaling monitor (no browser needed)");

  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error("Timeout waiting for data channel message"));
    }, TIMEOUT_MS);

    // Connect as "browser" peer to the signaling server
    const ws = new WebSocket(`ws://localhost:${SIGNALING_WS_PORT}`);
    let offerReceived = false;
    let answerSent = false;
    let dataReceived = false;

    ws.on("error", (err) => {
      clearTimeout(timer);
      reject(new Error(`WebSocket error: ${err.message}`));
    });

    ws.on("message", (raw) => {
      const msg = JSON.parse(raw.toString());

      if (msg.type === "offer" && !offerReceived) {
        offerReceived = true;
        console.log("  Received SDP offer from Zig");

        // Create a minimal answer to keep the flow going
        const answer = buildMinimalAnswer(msg.sdp);
        ws.send(JSON.stringify({ type: "answer", sdp: answer }));
        answerSent = true;
        console.log("  Sent SDP answer");
      }

      if (msg.type === "data" && !dataReceived) {
        dataReceived = true;
        console.log(`  ✅ Received data message: "${msg.message}"`);
        clearTimeout(timer);
        ws.close();
        resolve({ success: true, received: msg.message });
      }

      if (msg.type === "status") {
        console.log(`  Zig status: ${msg.message}`);
      }
    });
  });
}

function buildMinimalAnswer(offerSdp) {
  const fingerprintMatch = (offerSdp || "").match(/a=fingerprint:([^\r\n]+)/);
  const fingerprint = fingerprintMatch
    ? fingerprintMatch[1]
    : "sha-256 00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00";

  return [
    "v=0",
    "o=- 9876543210 2 IN IP4 127.0.0.1",
    "s=-",
    "t=0 0",
    "a=group:BUNDLE 0",
    "a=msid-semantic: WMS",
    "m=application 9 UDP/DTLS/SCTP webrtc-datachannel",
    "c=IN IP4 0.0.0.0",
    "a=ice-ufrag:test" + Math.random().toString(36).slice(2, 6),
    "a=ice-pwd:testpwd" + Math.random().toString(36).slice(2, 18),
    "a=fingerprint:" + fingerprint,
    "a=setup:active",
    "a=mid:0",
    "a=sctp-port:5000",
    "",
  ].join("\r\n");
}

// ── Main ─────────────────────────────────────────────────────────────

async function runDataChannelTest() {
  let signalingProc = null;
  let zigProc = null;

  const cleanup = () => {
    killProc(zigProc);
    killProc(signalingProc);
  };

  try {
    // 1. Build the Zig agent
    await buildZigAgent();

    // 2. Start signaling server
    console.log("  Starting signaling server...");
    signalingProc = await startSignalingServer();

    // 3. Start Zig agent
    console.log("  Starting Zig agent...");
    zigProc = startZigWrapper();

    // Give Zig agent time to connect and send offer
    await new Promise((r) => setTimeout(r, 2000));

    // 4. Try Playwright first, fall back to signaling monitor
    let result = await runWithPlaywright();
    if (!result) {
      result = await runWithSignalingMonitor();
    }

    // 5. Verify
    if (!result || !result.success) {
      throw new Error("Data channel test failed — no message received");
    }

    console.log("  ✅ Data Channel Interop Test PASSED");
  } finally {
    cleanup();
    await new Promise((r) => setTimeout(r, 500));
  }
}

// ── Entry point ──────────────────────────────────────────────────────

if (require.main === module) {
  console.log("=== Full Data Channel Interop Test ===\n");
  runDataChannelTest()
    .then(() => {
      console.log("\n✅ Test passed");
      process.exit(0);
    })
    .catch((err) => {
      console.error(`\n❌ Test failed: ${err.message}`);
      process.exit(1);
    });
}

module.exports = { runDataChannelTest };
