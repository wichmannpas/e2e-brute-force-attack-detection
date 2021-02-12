event tcp_packet(c: connection, is_orig: bool, flags: string, seq: count, ack: count, len: count, payload: string) {
  # ignore non-service packets
  if (c$id$resp_p != service_port) return;

  SumStats::observe("###MODULE_NAME### packet observed",
    SumStats::Key($host=c$id$orig_h),
    SumStats::Observation($num=1));
}
