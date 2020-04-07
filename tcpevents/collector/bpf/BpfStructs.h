#pragma once

#ifdef __cplusplus
#include "CppEnums.h"
namespace paths {
namespace tcpevents {
namespace bpf {
#else
typedef uint8_t InetSockState;
typedef uint8_t TcpCaState;
typedef uint32_t TcpCaEvent;
#endif

#ifndef __cplusplus
enum tcp_event_type_e {
#else
FATAL_RICH_ENUM_CLASS(
    tcp_event_type_e,
#endif
  INET_SOCK_SET_STATE,
  TCP_SET_CA_STATE,
  TCP_CA_EVENT,
  TCP_RATE_CHECK_APP_LIMITED,
  TCP_RATE_CHECK_APP_LIMITED_RET,
#ifndef __cplusplus
};
#else
);
#endif

#define LTS_REASON_NORMAL_RECOVERY 0x1
#define LTS_REASON_TLP_CONFIRMED 0x2
#define LTS_REASON_LOSS_WITH_PARTIAL_ACKS 0x4

#define LTS_ERR_MISSED_TRANSITION (1<<0)
#define LTS_ERR_WRONG_HIGH_SEQ (1<<1)
#define LTS_ERR_LOSS_WITH_INFINTE_SSTHRESH (1<<2)
#define LTS_ERR_PRIOR_SSHTHRESH_ZERO_IN_RECOVERY (1<<3)
#define LTS_ERR_RECOVERY_TO_RECOVERY (1<<4)

union endpoint_t {
  struct sockaddr_in sin;
  struct sockaddr_in6 sin6;
};

struct tcp_event_header_t {
  uint64_t ev_tstamp_ns;
  uint64_t conn_tstamp_ns;
  enum tcp_event_type_e type;
  union endpoint_t src;
  union endpoint_t dst;
};

/**
 * State information exported from existing kernel structures.
 */
struct tcp_event_states_t {
  //////////////////////////////////////////////////
  // from struct sock
  // see include/net/sock.h
  //////////////////////////////////////////////////
  InetSockState skt_state; /* INET connection / socket state */

  //////////////////////////////////////////////////
  // from inet_connection_sock
  // see include/net/inet_connection_sock.h
  //////////////////////////////////////////////////
  TcpCaState ca_state; /* Congestion control state */
};

/**
 * Stats exported from existing kernel structures.
 *
 * Many of these statistics are zeroed during state changes and therefore do
 * not reflect behavior over the lifetime of the connection. Research the stat
 * before attempting to use it.
 *
 * For information on these fields, see:
 *   - include/linux/tcp.h (https://git.io/fpPSt)
 *   - include/net/inet_connection_sock.h (https://git.io/fpPyQ)
 *   - include/net/sock.h (https://git.io/fpPyd)
 *   - include/uapi/linux/tcp.h (https://git.io/fpPyA)
 *   - net/ipv4/tcp.c (https://git.io/fpPSv)
 */
struct tcp_event_stats_t {
  //////////////////////////////////////////////////
  // from struct tcp_sock
  // see include/linux/tcp.h (https://git.io/fpPSt)
  //   - struct tcp_sock
  //
  // see include/uapi/linux/tcp.h (https://git.io/fpPyA)
  //   - struct tcp_info
  // see net/ipv4/tcp.c (https://git.io/fpPSv)
  //   - tcp_get_info function
  //////////////////////////////////////////////////
  uint32_t srtt_us; /* smoothed RTT in microseconds */
  uint32_t mdev_us; /* smoothed median RTT variance in microseconds */
  uint32_t rttvar_us; /* max mdev_us over last CWND */
  uint32_t min_rtt_us; /* minimum RTT observed over window in microseconds
                        * window length = sysctl.tcp_min_rtt_wlen */
  uint32_t min_rtt_us_on_establish;

  uint32_t snd_ssthresh; /* Slow start size threshold */
  uint32_t snd_cwnd; /* Sending congestion window */

  // uint32_t snd_cwnd_cnt; /* Linear increase counter, used to slow down rate
  //                         * of increase once we exceed slow start threshold */
  // uint32_t snd_cwnd_clamp; /* Maximum size that snd_cwnd can grow to */
  // uint32_t snd_cwnd_used; /* Used as a highwater mark for how much of the
  //                          * congestion window is in use. It is used to adjust
  //                          * snd_cwnd down when the link is limited by the
  //                          * application rather than the network.
  //                          * Set in tcp_cwnd_validate. */
  // uint32_t snd_cwnd_stamp; /* Timestamp when the cwnd was last adjusted
  //                           * (set in tcp_cong_avoid after .cong_avoid call) */
  // bool is_cwnd_limited; /* Forward progress limited by snd_cwnd? */

  // uint32_t prior_cwnd; /* snd_cwnd saved at recovery start */
  // uint32_t prior_ssthresh; /* snd_ssthresh saved at recovery start */
  // uint32_t high_seq; /* snd_nxt at onset of congestion	*/
  // uint32_t prr_delivered; /* Number of newly delivered packets in Recovery. */
  // uint32_t prr_out; /* Total number of pkts sent during Recovery. */

  uint32_t segs_in; /* RFC4898 tcpEStatsPerfSegsIn */
  uint32_t segs_out; /* RFC4898 tcpEStatsPerfSegsOut */
  uint32_t data_segs_in; /* RFC4898 tcpEStatsPerfDataSegsIn */
  uint32_t data_segs_out; /* RFC4898 tcpEStatsPerfDataSegsOut */
  uint32_t total_retrans; /* Total retransmits for entire connection */

  uint64_t bytes_received; /* RFC4898 tcpEStatsAppHCThruOctetsReceived */
  uint64_t bytes_acked; /* RFC4898 tcpEStatsAppHCThruOctetsAcked */
  uint64_t bytes_retrans; /* RFC4898 tcpEStatsPerfOctetsRetrans
                           * Total data bytes retransmitted */

  uint32_t delivered; /* Total data packets delivered incl. rexmits */
  uint32_t delivered_ce; /* Like the above but only ECE marked packets */
  uint64_t first_tx_mstamp; /* Start of window send phase */
  uint64_t delivered_mstamp; /* Time we reached "delivered" */

  uint32_t mss_cache; /* Cached effective mss, not including SACKS */

  // uint32_t rate_delivered; /* saved rate sample: packets delivered */
  // uint32_t rate_interval_us; /* saved rate sample: time elapsed */
  // bool rate_app_limited; /* rate_{delivered,interval_us} limited? */

  // uint32_t app_limited_until; /* app limited until "delivered" = this val
  //                              * The sample stored in rate_ may have been
  //                              * captured during a non-application limited
  //                              * window; use rate_app_limited to determine */

  // notsent_bytes calculated as write_seq - snd_nxt
  // uint32_t write_seq; /* Tail(+1) of data held in tcp send buffer */
  // uint32_t snd_nxt; /* Next sequence we send */
  // uint32_t snd_una; /* First byte we want an ack for */
  // uint32_t snd_sml; /* Last byte of most recently transmitted small packet */

  // see tcp_packets_in_flight for example of how to use *_out
  // uint32_t packets_out; /* Packets which are "in flight" */
  // uint32_t retrans_out; /* Retransmitted packets out */
  // uint32_t sacked_out; /* SACK'd packets */
  // uint32_t lost_out; /* Lost packets */
  uint32_t lost; /* Total data packets lost incl. rexmits */

  // uint32_t reordering; /* Packet reordering metric. */
  // uint32_t reord_seen; /* number of data packet reordering events */

  // uint32_t max_packets_out; /* Max packets_out in last window */
  // uint32_t max_packets_seq; /* Right edge of max_packets_out flight */

  // uint32_t rcv_wnd; /* Current receiver window */

  uint64_t chrono_busy; /* Busy sending data */
  uint64_t chrono_rwnd_limited; /* Stalled by insufficient receive window */
  uint64_t chrono_sndbuf_limited; /* Stalled by insufficient send buffer */

  //////////////////////////////////////////////////
  // from struct tcp_rack
  // see include/linux/tcp.h (https://git.io/fpPSt)
  //   - struct tcp_sock::tcp_rack
  //
  // info of the most recently (s)acked skb
  //////////////////////////////////////////////////
  // uint64_t rack_mstamp; /* (Re)sent time of the skb */
  // uint64_t rack_rtt_us; /* Associated RTT */
  // uint32_t rack_end_seq; /* Ending TCP sequence of the skb */
  // uint32_t rack_last_delivered; /* tp->delivered at last reo_wnd adj */

  //////////////////////////////////////////////////
  // from struct sock
  // see include/net/sock.h
  //////////////////////////////////////////////////
  uint32_t pacing_status; /* Pacing status (requested, handled by sch_fq)
                           * (see enum sk_pacing) */
  uint64_t pacing_rate; /* Pacing rate in bps (if supported by scheduler) */
  uint64_t max_pacing_rate; /* Maximum pacing rate (%SO_MAX_PACING_RATE) */

  int sndbuf; /* Size of send buffer in bytes */
  int rcvbuf; /* Size of receive buffer in bytes */

  int sk_shutdown; /* Mask of %SEND_SHUTDOWN and/or %RCV_SHUTDOWN */
  int sk_err; /* Last error (useful if other side sends reset)
               * (e.g., ECONNREFUSED, EPIPE, ECONNRESET) */
  int sk_err_soft; /* Errors that don't cause failure but are the cause
                    * of a persistent failure not just 'timed out' */

  // TODO(bschlinker): Add sk_stamp
  // ktime_t sk_stamp; /* Time stamp of last packet received */

  //////////////////////////////////////////////////
  // from inet_connection_sock
  // see include/net/inet_connection_sock.h
  //////////////////////////////////////////////////
  uint32_t rto; /* Retransmit timeout */

  //////////////////////////////////////////////////
  // custom tracking of connection start time
  //////////////////////////////////////////////////
  uint64_t start_us; /* BPF socket creation time, in us */
  uint64_t bytes_per_ns;  /* bytes_acked / (ts_us - start_us) */

  //////////////////////////////////////////////////
  // custom tracking of first loss
  //////////////////////////////////////////////////
  uint8_t fstloss_tracked;
  uint16_t fstloss_packet;  /* delivered - sacked_out */
  uint8_t fstloss_reason;  /* enum LossTrackReason */
  uint8_t fstloss_error;  /* enum LossTrackError */
  uint8_t fstloss_done;  /* either 0 or 1 */
  uint8_t fstloss_stats_set_loss_count;
  uint8_t fstloss_stats_undo_count;
  uint8_t fstloss_stats_undone_undo_marker;
  uint8_t fstloss_stats_undone_mtu_probing;
  uint8_t fstloss_stats_undone_ssthresh_infinite;
  uint8_t fstloss_stats_transitions_loss_to_loss;
  uint8_t fstloss_stats_transitions_open_to_open;
  uint8_t fstloss_stats_transitions_recovery_to_loss;
  uint8_t fstloss_stats_transitions_after_done;
  uint8_t fstloss_stats_recovery_to_loss_with_partial_acks;

  uint16_t ca_state_changes_count;
  uint16_t ca_state_changes_open_disorder;
  uint16_t ca_state_changes_cwr;
  uint16_t ca_state_changes_recovery;
  uint16_t ca_state_changes_loss;

  uint8_t cc_algo;
};

/**
 * State information for events triggered on stage changes.
 */
struct tcp_event_state_change_t {
  union {
    InetSockState skt_state;
    TcpCaState ca_state;
  } old_state;

  union {
    InetSockState skt_state;
    TcpCaState ca_state;
  } new_state;
};

/**
 * Extra information for events.
 */
union tcp_event_details_t {
  struct tcp_event_state_change_t state_change;
  TcpCaEvent ca_event;
};

struct tcp_event_t {
  struct tcp_event_header_t header;
  struct tcp_event_states_t states;
  struct tcp_event_stats_t stats;
  union tcp_event_details_t details;
};

#ifdef __cplusplus
} // namespace bpf
} // namespace tcpevents
} // namespace paths
#endif
