#!/usr/bin/env zeek
module SSHDestOrientedShortConnectionsBruteForce;
export {
  # The (human-readable) name of the protocol
  const proto = "SSH";

  # The port of the service
  const service_port = 22/tcp;
}

#!/usr/bin/env zeek
@load base/frameworks/notice
@load base/frameworks/sumstats


export {
  redef enum Notice::Type += {
    Logging,
  };
}

event zeek_init() &priority=-100 {
  for (id in Log::active_streams) {
    if (id != Notice::LOG && id != Notice::ALARM_LOG) {
      Log::disable_stream(id);
    }
  }

  NOTICE([$note=Logging,
          $msg="Default logging disabled"]);
}


export {
  redef enum Notice::Type += {
    ## Indicates that a host has been identified as apparently
    ## performing a brute force attack
    Brute_Forcing,
  };

  # The length of a full (max-length) packet
  const full_packet_len = 16406;
}

export {
  # Duration of a single epoch to count
  const epoch_len = 10min;

  # The threshold for the duration for a connection to be counted as short
  const duration_threshold = 1sec;

  # The threshold for the number of short-lived connections to the same origin
  const brute_threshold = 10;
}

event zeek_init() &priority=-101 {
  # send a notice to make sure notice.log is created
  print(fmt("short-connection brute-force script loaded for proto %s (%s)", proto, service_port));
  NOTICE([$note=Brute_Forcing,
          $msg=fmt("short-connection brute-force script loaded for proto %s (%s)", proto, service_port)]);
}

event zeek_init() &priority=5 {
  local reducer = SumStats::Reducer($stream="SSHDestOrientedShortConnectionsBruteForce short connection duration observed", $apply=set(SumStats::SUM));

  SumStats::create([
    $name = "counting SSHDestOrientedShortConnectionsBruteForce short connection durations", $epoch = epoch_len, $reducers = set(reducer),
    $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) = {
      local sum = result["SSHDestOrientedShortConnectionsBruteForce short connection duration observed"]$sum;
      if (sum >= brute_threshold) {
        NOTICE([$note=Brute_Forcing,
                $msg=fmt("%s appears to be brute-forcing/brute-forced %s (seen %f short connections).", key$host, proto, sum),
                $src=key$host]);
      }
    }]);
}

event connection_state_remove(c: connection) {
  # ignore non-service packets
  if (c$id$resp_p != service_port) return;
  # ignore not-short connection
  if (c$duration > duration_threshold) return;

  SumStats::observe("SSHDestOrientedShortConnectionsBruteForce short connection duration observed",
    SumStats::Key($host=c$id$resp_h),
    SumStats::Observation($num=1));
}


