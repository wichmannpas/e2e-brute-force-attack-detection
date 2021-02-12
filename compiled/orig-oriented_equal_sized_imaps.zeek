#!/usr/bin/env zeek
module IMAPSEqualSizedResponsesBruteForce;

export {
  # The (human-readable) name of the protocol
  const proto = "IMAPS";

  # The port of the service
  const service_port = 993/tcp;
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

event tcp_packet(c: connection, is_orig: bool, flags: string, seq: count, ack: count, len: count, payload: string) {
  # ignore non-service packets
  if (c$id$resp_p != service_port) return;
  # ignore request packets, only treat responses
  if (is_orig) return;
  # ignore empty packets and packets of full length (huge transmissions cause several full-length packets)
  if (len == full_packet_len || len == 0) return;

  SumStats::observe("IMAPSEqualSizedResponsesBruteForce response size observed",
    SumStats::Key($host=c$id$orig_h),
    SumStats::Observation($num=len));
}

export {
  # Duration of a single epoch to count
  const epoch_len = 10min;

  # The threshold for the number of equal-sized responses to the same origin
  const brute_threshold = 750;
}

event zeek_init() &priority=5 {
  local reducer = SumStats::Reducer($stream="IMAPSEqualSizedResponsesBruteForce response size observed", $apply=set(SumStats::TOPK));

  SumStats::create([
    $name = "counting IMAPSEqualSizedResponsesBruteForce response sizes", $epoch = epoch_len, $reducers = set(reducer),
    $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) = {
      local topk = result["IMAPSEqualSizedResponsesBruteForce response size observed"]$topk;
      local top: vector of SumStats::Observation = topk_get_top(topk, 10);
      for (v in top) {
        local c = topk_count(topk, top[v]);
        if (c < brute_threshold) break;
        local epsilon = topk_epsilon(topk, top[v]);
        NOTICE([$note=Brute_Forcing,
                $msg=fmt("%s appears to be brute-forcing/brute-forced %s (seen %d[+-%d] equal-sized responses of TCP size %d).", key$host, proto, c, epsilon, top[v]$num),
                $src=key$host]);
      }}]);
}

event zeek_init() &priority=-101 {
  # send a notice to make sure notice.log is created
  print(fmt("equal-sized brute-force script loaded for proto %s (%s)", proto, service_port));
  NOTICE([$note=Brute_Forcing,
          $msg=fmt("equal-sized brute-force script loaded for proto %s (%s)", proto, service_port)]);
}


