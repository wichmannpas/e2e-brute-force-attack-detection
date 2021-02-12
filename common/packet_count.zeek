export {
  # Duration of a single epoch to count
  const epoch_len = 10min;

  # The threshold for the number of packets with the same origin/destination
  const brute_threshold = 10;
}

event zeek_init() &priority=-101 {
  # send a notice to make sure notice.log is created
  print(fmt("packet-count brute-force script loaded for proto %s (%s)", proto, service_port));
  NOTICE([$note=Brute_Forcing,
          $msg=fmt("packet-count brute-force script loaded for proto %s (%s)", proto, service_port)]);
}

event zeek_init() &priority=5 {
  local reducer = SumStats::Reducer($stream="###MODULE_NAME### packet observed", $apply=set(SumStats::SUM));

  SumStats::create([
    $name = "counting ###MODULE_NAME### packets", $epoch = epoch_len, $reducers = set(reducer),
    $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) = {
      local sum = result["###MODULE_NAME### packet observed"]$sum;
      if (sum >= brute_threshold) {
        NOTICE([$note=Brute_Forcing,
                $msg=fmt("%s appears to be brute-forcing/brute-forced %s (seen %f packets).", key$host, proto, sum),
                $src=key$host]);
      }
    }]);
}
