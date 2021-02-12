#!/usr/bin/env zeek
@load base/frameworks/notice
@load base/frameworks/sumstats

module ###COMPILED_SCRIPT_BASENAME###ConnectionCountBruteForce;


@import-static ../../common/disable_logging

@import-static ../../common/exports
@import-static ../../common/connection_count
@import-static ../../common/count_connections_dest
