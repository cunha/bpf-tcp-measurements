#pragma once

#ifdef __cplusplus
/* include sys/socket.h for struct sockaddr_storage; it seems BCC
 * provides this automagically */
#include <sys/socket.h>

namespace paths {
namespace ackevents {
namespace bpf {
#endif

#define EV_SOURCE_UNSET                  0x0
#define EV_SOURCE_TCP_CLOSE              0x1
#define EV_SOURCE_TCP_RATE_SKB_DELIVERED 0x2
#define EV_SOURCE_TCP_TRIM_HEAD          0x4

struct event_hdr {
  uint64_t ev_tstamp_ns;
  uint64_t conn_tstamp_ns;
  struct sockaddr_storage src;
  struct sockaddr_storage dst;
};

struct ack_event {
  struct event_hdr header;

  struct {
    uint32_t by_stats;
    uint32_t by_seqnum;
  } fstloss;

  uint32_t established_snd_una;
  uint32_t prior_snd_una;
  uint32_t seq;
  uint32_t end_seq;

  uint32_t segments_lost;        // number of segments lost.
  uint32_t non_spurious_retrans; // retrans - number of segments retransmitted

  uint32_t dsack_recovered;
  uint32_t timestamp_recovered;
  uint32_t dsack_and_timestamp_recovered;
  uint32_t dsack_or_timestamp_recovered;
  uint32_t fake_dsack_recovery_induced_by_lost_tlp;

  struct {
    uint32_t delivered;
    uint32_t lost;
    uint32_t total_retrans;
    uint32_t srtt_us;
    uint32_t mdev_us;
    uint32_t min_rtt_us;
    uint32_t snd_cwnd;
    uint32_t mss_cache;
    uint32_t rto;
  } tcp;

  struct {
    uint16_t calls_from_rate_skb;
    uint16_t calls_from_trim_head;
    uint16_t calls_with_mstamp_zero;
    uint16_t tcpcb_sacked_retrans;
    uint16_t tcpcb_retrans;
    uint16_t spurious_tlp_retrans;
    uint16_t trim_from_ack;
    uint16_t trim_from_rtx;
  } stats;

#ifdef EVDEBUG
  struct {
    uint8_t event_source;
    uint16_t pcount;
    uint16_t tcp_gso_size;
    uint32_t sacked_out;
    uint32_t tcp_snd_una;
    uint32_t tx_delivered;
    uint16_t tx_first_tx_mstamp;
    uint64_t tx_delivered_mstamp;
    uint32_t tlp_high_seq;
    uint8_t sacked;
    uint8_t tcp_flags;
  } debug;
#endif

  struct {
    bool cached;
    uint32_t seq;
    uint32_t end_seq;
  } trim;

};

#ifdef __cplusplus
} // namespace bpf
} // namespace ackevents
} // namespace paths
#endif
