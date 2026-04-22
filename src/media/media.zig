//! Media layer: codec pipelines and test signal generators.
//!
//! - pipeline: AudioPipeline connecting Opus codec to RTP
//! - sources:  Sine-wave generator for testing
//! - azure_tts: Azure Speech Services TTS client
//!
//! NOTE: VideoPipeline and colour-bar sources require VP8 (libvpx).
//! VP8 is currently disabled due to MSVC /GL incompatibility with Zig's linker.

pub const pipeline = @import("pipeline.zig");
// sources.zig references vpx for color bars - use audio-only parts
pub const azure_tts = @import("azure_tts.zig");

test {
    _ = pipeline;
    _ = azure_tts;
}
