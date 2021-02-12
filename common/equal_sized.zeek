export {
  # Duration of a single epoch to count
  const epoch_len = 10min;

  # The threshold for the number of equal-sized responses to the same origin
  const brute_threshold = 750;
}

event zeek_init() &priority=5 {
  local reducer = SumStats::Reducer($stream="###MODULE_NAME### response size observed", $apply=set(SumStats::TOPK));

  SumStats::create([
    $name = "counting ###MODULE_NAME### response sizes", $epoch = epoch_len, $reducers = set(reducer),
    $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) = {
      local topk = result["###MODULE_NAME### response size observed"]$topk;
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
