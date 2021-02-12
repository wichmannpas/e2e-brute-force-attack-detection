#!/usr/bin/env zeek
@load base/frameworks/notice
@load base/frameworks/sumstats

module ###COMPILED_SCRIPT_BASENAME###SimilarSizedResponsesBruteForce;

@import-static ../../common/disable_logging
@import-static ../../common/exports
@import-static ../../common/topk_packet_sizes_orig
@import-static ../../common/similar_sized
