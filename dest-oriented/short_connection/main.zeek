#!/usr/bin/env zeek
@load base/frameworks/notice
@load base/frameworks/sumstats

module ###COMPILED_SCRIPT_BASENAME###DestOrientedShortConnectionsBruteForce;


@import-static ../../common/disable_logging

@import-static ../../common/exports
@import-static ../../common/short_connection
@import-static ../../common/count_short_connections_dest
