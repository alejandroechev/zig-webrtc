//! Media layer: codec pipelines, test signal generators, and Azure TTS.
//!
//! - pipeline: AudioPipeline / VideoPipeline connecting codecs to RTP
//! - sources:  Sine-wave and colour-bar generators for testing
//! - azure_tts: Azure Speech Services TTS client

pub const pipeline = @import("pipeline.zig");
pub const sources = @import("sources.zig");
pub const azure_tts = @import("azure_tts.zig");

test {
    @import("std").testing.refAllDecls(@This());
}
