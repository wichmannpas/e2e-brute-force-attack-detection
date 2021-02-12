event tcp_packet(c: connection, is_orig: bool, flags: string, seq: count, ack: count, len: count, payload: string) {
  # ignore non-service packets
  if (c$id$resp_p != service_port) return;
  # ignore request packets, only treat responses
  if (is_orig) return;
  # ignore empty packets and packets of full length (huge transmissions cause several full-length packets)
  if (len == full_packet_len || len == 0) return;

  SumStats::observe("###MODULE_NAME### response size observed",
    SumStats::Key($host=c$id$orig_h),
    SumStats::Observation($num=len));
}
