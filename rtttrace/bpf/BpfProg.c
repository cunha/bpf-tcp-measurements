#include <bcc/proto.h>
#include <linux/socket.h>
#include <linux/tcp.h>
#include <net/sock.h>
#include <net/tcp.h>

#define UINT8_MAX 0xFF
#define UINT16_MAX 0xFFFF
#define UINT32_MAX 0xFFFFFFFFU
#define INCMAX(v, limit) if((v) < (u16)(limit)) { (v)++; }

/* We generate a random byte on socket initialization to allow control
 * of sampling rates (tcp_sock->cd_random_byte). In this code, we only
 * track sockets whose random_byte is lower than RANDOM_BYTE_MAX.
 * RANDOM_BYTE_MAX should be passed as a parameter to BCC. The default
 * behavior is to track all sockets. */
#ifndef RANDOM_SAMPLE_MAX
#define RANDOM_SAMPLE_MAX UINT16_MAX
#endif

#include "BpfStructs.h"

#define _(var, src) bpf_probe_read(&var, sizeof(var), (void*)&src);

#define _minmax_get(var, src)     \
  {                        \
    struct minmax mm;      \
    _(mm, src);            \
    var = minmax_get(&mm); \
  }

BPF_PERF_OUTPUT(events);

BPF_HASH(ht, struct sock*, struct rtt_event, UINT16_MAX);

static int event_hdr_init(struct event_hdr* evh, const struct sock *sk)
{
  struct inet_sock* inet = inet_sk(sk);
  struct tcp_sock *tp = tcp_sk(sk);
  evh->ev_tstamp_ns = bpf_ktime_get_ns();
  _(evh->conn_tstamp_ns, tp->cd_init_clock_ns);
  _(evh->src.ss_family, sk->sk_family);
  _(evh->dst.ss_family, sk->sk_family);
  if (sk->sk_family == AF_INET) {
    struct sockaddr_in* src = (struct sockaddr_in*)&evh->src;
    struct sockaddr_in* dst = (struct sockaddr_in*)&evh->dst;
    _(src->sin_port, inet->inet_sport);
    _(dst->sin_port, inet->inet_dport);
    _(src->sin_addr, inet->inet_saddr);
    _(dst->sin_addr, inet->inet_daddr);
  } else if (sk->sk_family == AF_INET6) {
    struct sockaddr_in6* src = (struct sockaddr_in6*)&evh->src;
    struct sockaddr_in6* dst = (struct sockaddr_in6*)&evh->dst;
    _(src->sin6_port, inet->inet_sport);
    _(dst->sin6_port, inet->inet_dport);
    _(src->sin6_addr, sk->sk_v6_rcv_saddr);
    _(dst->sin6_addr, sk->sk_v6_daddr);
  } else {
    return -1;
  }
  return 0;
}

static bool tcp_sock_is_tracked(const struct sock *sk)
{
  struct tcp_sock *tp = tcp_sk(sk);
  return tp->cd_random_u16 <= RANDOM_SAMPLE_MAX;
}

static u64 local_tcp_skb_timestamp_us(const struct sk_buff *skb)
{
  return div_u64(skb->skb_mstamp_ns, NSEC_PER_USEC);
}

static u32 local_tcp_stamp_us_delta(u64 t1, u64 t0)
{
  s64 diff = (s64)t1 - (s64)t0;
	return diff < 0 ? 0 : diff;
}

/*****************************************************************************
 * kprobes
 *****************************************************************************/
int
on_tcp_destroy_sock(struct tracepoint__tcp__tcp_destroy_sock* attrs) {
  struct sock* sk = (struct sock*)attrs->skaddr;
  if (!tcp_sock_is_tracked(sk)) { return 0; }
  ht.delete(&sk);
  return 0;
}

int
on_inet_sock_set_state(struct tracepoint__sock__inet_sock_set_state* attrs) {
  if (attrs->protocol != IPPROTO_TCP) {
    return 0;
  }

  struct sock* sk = (struct sock*)attrs->skaddr;
  struct tcp_sock* tp = tcp_sk(sk);

  if (!tcp_sock_is_tracked(sk)) { return 0; }

  if (attrs->newstate == TCP_ESTABLISHED) {
    struct rtt_event ev = { 0 };
    if (event_hdr_init(&ev.header, sk) < 0) { return 0; }
    _(ev.tcp.establish_snd_una, tp->snd_una);
    ht.update(&sk, &ev);
  }

  return 0;
}

int on_tcp_skb_acked(struct tracepoint__tcp__tcp_skb_acked* attrs)
{
  const struct sock* sk = (struct sock*)attrs->skaddr;
  if (!tcp_sock_is_tracked(sk)) { return 0; }

  const struct inet_connection_sock* icsk = inet_csk(sk);
  const struct tcp_sock *tp = tcp_sk(sk);
  const struct sk_buff *skb = (struct sk_buff *)attrs->skbaddr;
  const struct tcp_skb_cb *scb = TCP_SKB_CB(skb);

  struct rtt_event *ev = ht.lookup((struct sock **)&sk);
  if (!ev) { return 0; }
  INCMAX(ev->stats.calls, UINT16_MAX);

  bool fully_acked = attrs->fully_acked;

  u32 acked_pcount = attrs->acked_pcount;
  if (acked_pcount == 0) {
    // The kernel only updates RTT when acked_pcount > 1, we do the same.
    INCMAX(ev->stats.skbs_with_acked_pcount_zero, UINT16_MAX);
    return 0;
  }

  bool is_first_ack = attrs->first_acked;
  if (!is_first_ack) {
    // Only compute RTT for the first packet in a batch. This prevents
    // computing RTT for packets acknowledged out of order.
    INCMAX(ev->stats.skbs_not_first_ack, UINT16_MAX);
    return 0;
  }

  if(scb->sacked & TCPCB_RETRANS) {
    // Never look at RTT measurements from retransmitted packets.
    INCMAX(ev->stats.skbs_retransmitted, UINT16_MAX);
    return 0;
  }

  if (fully_acked) {
    _(ev->scb.seq, scb->seq);
    _(ev->scb.end_seq, scb->end_seq);
  } else {
    _(ev->scb.seq, attrs->orig_seq);
    _(ev->scb.end_seq, tp->snd_una);
  }

  u64 bytes = ((s64)UINT32_MAX - ev->tcp.establish_snd_una + 1 + ev->scb.seq)
      % (s64)UINT32_MAX;
  u32 packet_num = bytes / tp->mss_cache;
  ev->scb.packet_num = packet_num;

  u32 scb_tx_bytes_in_flight =
#ifndef BCC_SEC
      BPF_CORE_READ_BITFIELD_PROBED(scb, tx.in_flight);
#else
      (*(u32*)(&scb->tx)) & 0xffffff;
#endif

  // tx_bytes_in_flight is computed based on tx.in_flight, which the
  // kernel keeps for rate delivery computation. We also export
  // tcp_packets_in_flight, which is the kernels computation used in the
  // congestion control algorithm. These could be different if packets
  // are delivered out-of-order because of how they are computed
  // (tx.in_flight does not consider SACK'd packets).
  u32 tx_bytes_in_flight = scb_tx_bytes_in_flight - (scb->end_seq - scb->seq);
  u32 tx_packets_in_flight = tx_bytes_in_flight / tp->mss_cache;
  u32 tcp_packets_in_flight = scb->packets_in_flight;

  // We do export an event if any estimation of the number of packets in
  // flight is less than 2. We do not check for zero to avoid small
  // errors (e.g., due to the kernel sending an SKB with pcount == 2).
  if (tx_packets_in_flight >= 2 && tcp_packets_in_flight >= 2
      && packet_num > RTTTRACE_MAX_PACKET_EXPORT) {
    INCMAX(ev->stats.unexported_packets, UINT16_MAX);
    return 0;
  }

  u64 xmit_timestamp_us = local_tcp_skb_timestamp_us(skb);
  u32 rtt_us = local_tcp_stamp_us_delta(tp->tcp_mstamp, xmit_timestamp_us);

  ev->scb.xmit_timestamp_us = xmit_timestamp_us;
  ev->scb.now_timestamp_us = tp->tcp_mstamp;
  ev->scb.rtt_us = rtt_us;
  ev->scb.tcp_packets_in_flight = tcp_packets_in_flight;
  ev->scb.tx_bytes_in_flight = tx_bytes_in_flight;
  ev->scb.tx_packets_in_flight = tx_packets_in_flight;

  ev->scb.pcount = acked_pcount;
  _(ev->scb.tx_delivered, scb->tx.delivered);
  _(ev->scb.tx_delivered_mstamp, scb->tx.delivered_mstamp);
  _(ev->scb.tx_first_tx_mstamp, scb->tx.first_tx_mstamp);
  _(ev->scb.flags, scb->tcp_flags);
  ev->scb.fully_acked = (u8)fully_acked;
  _(ev->scb.sacked, scb->sacked);

  _(ev->tcp.delivered, tp->delivered);
  _(ev->tcp.mdev_us, tp->mdev_us);
  ev->tcp.mdev_us >>= 2;
  _(ev->tcp.mss_cache, tp->mss_cache);
  _(ev->tcp.mstamp, tp->tcp_mstamp);
  _(ev->tcp.rto, icsk->icsk_rto);
  _minmax_get(ev->tcp.min_rtt_us, tp->rtt_min);
  _(ev->tcp.rttvar_us, tp->rttvar_us);
  ev->tcp.rttvar_us >>= 2;
  _(ev->tcp.sacked_out, tp->sacked_out);
  _(ev->tcp.snd_una, tp->snd_una);
  _(ev->tcp.srtt_us, tp->srtt_us);
  ev->tcp.srtt_us >>= 3;

  events.perf_submit((void *)attrs, ev, sizeof(*ev));

  return 0;
}
