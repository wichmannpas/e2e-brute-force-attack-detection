event connection_state_remove(c: connection) {
  # ignore non-service packets
  if (c$id$resp_p != service_port) return;

  SumStats::observe("###MODULE_NAME### connection observed",
    SumStats::Key($host=c$id$orig_h),
    SumStats::Observation($num=1));
}
