export {
  redef enum Notice::Type += {
    ## Indicates that a host has been identified as apparently
    ## performing a brute force attack
    Brute_Forcing,
  };

  # The length of a full (max-length) packet
  const full_packet_len = 16406;
}
