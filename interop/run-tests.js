#!/usr/bin/env node
//
// run-tests.js — orchestrates all WebRTC Zig interop tests.
//

const { runSdpExchangeTest } = require("./test-sdp-exchange");
const { runDataChannelTest } = require("./test-interop");
const { runAudioSdpTest } = require("./test-audio-sdp");
const { runAudioE2eTest } = require("./test-audio-e2e");

async function runAllTests() {
  console.log("=== WebRTC Zig Interop Tests ===\n");
  let passed = 0;
  let failed = 0;

  // Test 1: SDP Exchange Validation
  console.log("Test 1: SDP Exchange Validation");
  try {
    await runSdpExchangeTest();
    passed++;
  } catch (err) {
    console.error(`  ❌ FAILED: ${err.message}`);
    failed++;
  }

  console.log("");

  // Test 2: Full Data Channel Interop
  console.log("Test 2: Full Data Channel Interop");
  try {
    await runDataChannelTest();
    passed++;
  } catch (err) {
    console.error(`  ❌ FAILED: ${err.message}`);
    failed++;
  }

  console.log("");

  // Test 3: Audio SDP Interop (Opus codec negotiation)
  console.log("Test 3: Audio SDP Interop (Opus codec negotiation)");
  try {
    await runAudioSdpTest();
    passed++;
  } catch (err) {
    console.error(`  ❌ FAILED: ${err.message}`);
    failed++;
  }

  console.log("");

  // Test 4: Audio E2E (TTS→STT)
  console.log("Test 4: Audio E2E (TTS→STT)");
  try {
    await runAudioE2eTest();
    passed++;
  } catch (err) {
    console.error(`  ❌ FAILED: ${err.message}`);
    failed++;
  }

  // Summary
  console.log("\n" + "=".repeat(40));
  console.log(`Results: ${passed} passed, ${failed} failed`);
  console.log("=".repeat(40));

  if (failed > 0) {
    console.log("\n❌ Some tests failed");
    process.exit(1);
  } else {
    console.log("\n✅ All tests passed");
    process.exit(0);
  }
}

runAllTests().catch((err) => {
  console.error(`\n❌ Test runner error: ${err.message}`);
  process.exit(1);
});
