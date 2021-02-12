event connection_state_remove(c: connection) {
  # ignore non-service packets
  if (c$id$resp_p != service_port) return;
  # ignore not-short connection
  if (c$duration > duration_threshold) return;

  SumStats::observe("###MODULE_NAME### short connection duration observed",
    SumStats::Key($host=c$id$resp_h),
    SumStats::Observation($num=1));
}
