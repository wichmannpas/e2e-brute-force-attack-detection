#!/usr/bin/env zeek
@load base/frameworks/notice
@load base/frameworks/sumstats

module ###COMPILED_SCRIPT_BASENAME###DestOrientedSimilarSizedResponsesBruteForce;

@import-static ../../common/disable_logging
@import-static ../../common/exports
@import-static ../../common/topk_packet_sizes_dest
@import-static ../../common/similar_sized
