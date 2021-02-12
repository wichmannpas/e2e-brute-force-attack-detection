#!/usr/bin/env zeek
@load base/frameworks/notice
@load base/frameworks/sumstats

module ###COMPILED_SCRIPT_BASENAME###PacketCountBruteForce;


@import-static ../../common/disable_logging

@import-static ../../common/exports
@import-static ../../common/packet_count
@import-static ../../common/count_packets_dest
