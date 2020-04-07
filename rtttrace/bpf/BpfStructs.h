#pragma once

#ifdef __cplusplus
/* include sys/socket.h for struct sockaddr_storage; it seems BCC
 * provides this automagically */
#include <sys/socket.h>

namespace paths {
namespace rtttrace {
namespace bpf {
#endif

#define RTTTRACE_MAX_PACKET_EXPORT 72

struct event_hdr {
  uint64_t ev_tstamp_ns;
  uint64_t conn_tstamp_ns;
  struct sockaddr_storage src;
  struct sockaddr_storage dst;
};

struct rtt_event {
  struct event_hdr header;

  struct {
    uint32_t seq;
    uint32_t end_seq;
    uint32_t packet_num;
    uint64_t xmit_timestamp_us;
    uint64_t now_timestamp_us;
    uint32_t rtt_us;
    uint32_t tcp_packets_in_flight;
    uint32_t tx_bytes_in_flight;
    uint32_t tx_packets_in_flight;
    uint32_t pcount;
    uint32_t tx_delivered;
    uint64_t tx_delivered_mstamp;
    uint64_t tx_first_tx_mstamp;
    uint8_t flags;
    uint8_t fully_acked;
    uint8_t sacked;
  } scb;

  struct {
    uint32_t delivered;
    uint32_t establish_snd_una;
    uint32_t mdev_us;
    uint32_t mss_cache;
    uint64_t mstamp;
    uint32_t rto;
    uint32_t min_rtt_us;
    uint32_t rttvar_us;
    uint32_t sacked_out;
    uint32_t snd_una;
    uint32_t srtt_us;
  } tcp;

  struct {
    uint16_t calls;
    uint16_t skbs_with_acked_pcount_zero;
    uint16_t skbs_not_first_ack;
    uint16_t skbs_retransmitted;
    uint16_t unexported_packets;
  } stats;

};

#ifdef __cplusplus
} // namespace bpf
} // namespace rtttrace
} // namespace paths
#endif
