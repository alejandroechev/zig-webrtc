#!/usr/bin/env node
//
// zig-wrapper.js — bridges the Zig interop agent's stdin/stdout to WebSocket signaling.
//
// Usage:
//   node interop/zig-wrapper.js [signaling-url]
//
// Defaults:
//   signaling-url = ws://localhost:8080
//
// The Zig agent (zig-out/bin/zig-webrtc-interop) communicates via line-delimited JSON:
//   stdout → signaling server  (offer, answer, ice-candidate, data)
//   stdin  ← signaling server  (answer, ice-candidate, data)
//   stderr → console           (agent diagnostics)

const { spawn } = require("child_process");
const WebSocket = require("ws");
const path = require("path");

const SIGNALING_URL = process.argv[2] || "ws://localhost:8080";
const ZIG_BIN = path.join(
  __dirname,
  "..",
  "zig-out",
  "bin",
  "zig-webrtc-interop.exe"
);

console.log(`[wrapper] signaling server: ${SIGNALING_URL}`);
console.log(`[wrapper] zig binary: ${ZIG_BIN}`);

// Start Zig agent
const agent = spawn(ZIG_BIN, [], {
  stdio: ["pipe", "pipe", "inherit"], // stdin=pipe, stdout=pipe, stderr=inherit
});

agent.on("error", (err) => {
  console.error(`[wrapper] failed to start agent: ${err.message}`);
  process.exit(1);
});

agent.on("exit", (code) => {
  console.log(`[wrapper] agent exited with code ${code}`);
  process.exit(code || 0);
});

// Connect to signaling server
const ws = new WebSocket(SIGNALING_URL);

ws.on("open", () => {
  console.log("[wrapper] connected to signaling server");
});

ws.on("error", (err) => {
  console.error(`[wrapper] WebSocket error: ${err.message}`);
});

ws.on("close", () => {
  console.log("[wrapper] signaling connection closed");
  agent.stdin.end();
});

// Zig stdout → signaling server
let stdoutBuffer = "";

agent.stdout.on("data", (data) => {
  stdoutBuffer += data.toString();
  const lines = stdoutBuffer.split("\n");
  // Keep incomplete last line in buffer
  stdoutBuffer = lines.pop() || "";

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;

    try {
      const msg = JSON.parse(trimmed);

      if (
        msg.type === "offer" ||
        msg.type === "answer" ||
        msg.type === "ice-candidate" ||
        msg.type === "data"
      ) {
        // Forward to signaling
        if (ws.readyState === WebSocket.OPEN) {
          ws.send(trimmed);
          console.log(`[wrapper] zig → signaling: ${msg.type}`);
        } else {
          console.warn(
            `[wrapper] WebSocket not open, dropping: ${msg.type}`
          );
        }
      } else if (msg.type === "status") {
        console.log(`[wrapper] agent status: ${msg.message}`);
      } else {
        console.log(`[wrapper] zig → unknown type: ${msg.type}`);
      }
    } catch (e) {
      console.log(`[wrapper] zig raw: ${trimmed}`);
    }
  }
});

// Signaling server → Zig stdin
ws.on("message", (data) => {
  const text = data.toString();
  try {
    const msg = JSON.parse(text);
    console.log(`[wrapper] signaling → zig: ${msg.type}`);
    agent.stdin.write(text + "\n");
  } catch (e) {
    console.warn(`[wrapper] non-JSON from signaling: ${text}`);
  }
});
