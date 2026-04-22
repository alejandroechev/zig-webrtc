//! Test media generators for audio pipelines.
//!
//! Provides deterministic signal sources useful for integration testing
//! without requiring real capture devices.
//!
//! NOTE: Color bar video generator requires VP8 (libvpx), currently disabled.

const std = @import("std");

// ============================================================================
// Audio: sine wave generator
// ============================================================================

/// Generate a sine-wave tone into `buf`.
///
/// `sample_rate` — samples per second (e.g. 48000).
/// `frequency`   — tone frequency in Hz (e.g. 440.0).
/// `amplitude`   — peak amplitude in the i16 range (e.g. 16000.0).
/// `phase`       — running phase in radians; updated on return so
///                 consecutive calls produce a continuous waveform.
pub fn generateSineWave(
    buf: []i16,
    sample_rate: u32,
    frequency: f32,
    amplitude: f32,
    phase: *f32,
) void {
    const sr: f32 = @floatFromInt(sample_rate);
    const phase_inc = 2.0 * std.math.pi * frequency / sr;

    for (buf) |*sample| {
        sample.* = @intFromFloat(amplitude * @sin(phase.*));
        phase.* += phase_inc;
        // Keep phase in [0, 2π) to avoid precision loss over time
        if (phase.* >= 2.0 * std.math.pi) {
            phase.* -= 2.0 * std.math.pi;
        }
    }
}

// ============================================================================
// Video: colour-bar generator (YUV420)
// ============================================================================

/// Standard colour-bar Y/U/V values (8 bars: white, yellow, cyan, green,
/// magenta, red, blue, black).
const bar_colours = [8][3]u8{
    .{ 235, 128, 128 }, // white
    .{ 210, 16, 146 }, // yellow
    .{ 170, 166, 16 }, // cyan
    .{ 145, 54, 34 }, // green
    .{ 107, 202, 222 }, // magenta
    .{ 82, 90, 240 }, // red
    .{ 41, 240, 110 }, // blue
    .{ 16, 128, 128 }, // black
};

// generateColorBars — DISABLED (requires libvpx)
// TODO: Re-enable when libvpx is rebuilt without MSVC /GL.

// ============================================================================
// Tests
// ============================================================================

test "generateSineWave produces non-silent output" {
    var buf: [960]i16 = undefined;
    var phase: f32 = 0.0;
    generateSineWave(&buf, 48000, 440.0, 16000.0, &phase);

    // Verify non-zero samples exist
    var non_zero: usize = 0;
    for (buf) |s| {
        if (s != 0) non_zero += 1;
    }
    try std.testing.expect(non_zero > buf.len / 2);

    // Phase should have advanced
    try std.testing.expect(phase > 0.0);
}
