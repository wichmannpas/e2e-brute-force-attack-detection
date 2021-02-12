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
