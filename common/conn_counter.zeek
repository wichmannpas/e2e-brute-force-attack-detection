export {
  redef enum Log::ID += { CONN_COUNT };

  type Conn_Log_Info: record {
    ts: time        &log;
    conn_count: count &log;
  };

  global conn_count = 0;
}

event zeek_init() &priority=-101 {
  Log::create_stream(CONN_COUNT, [$columns=Conn_Log_Info, $path="conn_count"]);
}

event dump_conn_counter() {
  local rec: Conn_Log_Info = [$ts=network_time(), $conn_count=conn_count];
  Log::write(CONN_COUNT, rec);
  conn_count = 0;
  schedule 60min { dump_conn_counter() };
}

event zeek_init() {
  schedule 60min { dump_conn_counter() };
}

event connection_EOF(c: connection, is_orig: bool) {
  conn_count += 1;
}
