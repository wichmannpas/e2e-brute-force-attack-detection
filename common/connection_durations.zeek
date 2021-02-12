@load base/frameworks/sumstats

const epoch_len = 70min;

event zeek_init() &priority=5 {
  local reducer = SumStats::Reducer($stream="connection duration observed", $apply=set(SumStats::TOPK));

  SumStats::create([
    $name = "connection durations", $epoch = epoch_len, $reducers = set(reducer),
    $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) = {
      local topk = result["connection duration observed"]$topk;
      local top: vector of SumStats::Observation = topk_get_top(topk, 1000);
      for (v in top) {
        local duration = top[v]$num / 10.0;
        print(fmt("%s: %dx %f", key$host, topk_count(topk, top[v]), duration));
      }
    }]);
}

event connection_state_remove(c: connection) {
  # ignore non-service packets
  #if (c$id$resp_p != 21/tcp) return;

  SumStats::observe("connection duration observed",
    SumStats::Key($host=c$id$orig_h),
    SumStats::Observation($num=double_to_count(10 * interval_to_double(c$duration))));
}
