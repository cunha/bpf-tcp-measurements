#include <bcc/proto.h>
#include <linux/socket.h>
#include <linux/tcp.h>
#include <net/sock.h>
#include <net/tcp.h>

#define UINT8_MAX 0xFF
#define UINT16_MAX 0xFFFF
#define UINT32_MAX 0xFFFFFFFFU
#define INCMAX(v, limit) if((v) < (u16)(limit)) { (v)++; }

/* Known cases where this program fails to identify spurious
 * retransmissions (more may exist):
 *
 * 1. Say packet 1 is delayed. Many other packets, with higher
 *    timestamps, make it to the destination. If the kernel retransmits
 *    packet 1 in between other packets that have the same timestamp,
 *    the cumulative ACK may have a timestamp that is the same as that
 *    of the retransmitted packet, which prevents us from flagging
 *    timestamp_recovered.
 *
 * 2. A DSACK that arrives after a packet has been cumulatively acked
 *    (as in the case above) will not trigger a call to
 *    tcp_rate_skb_delivered, and thus will not flag dsack_recovered.
 *    More generally, we only identify dsack_recovered that occur while
 *    a packet is not cumulatively acked.
 *
 * Limitations:
 *
 * 1. The function may be called multiple times for the same segment.  A
 *    segment may be joined with other segments in the rtx queue after
 *    being acked (leading to increased pcounts); this leads to pcount >
 *    1.  We do not understand these two processes completely, and also
 *    do not know how skb->sacked is updated when skbs are joined in the
 *    rtx queue.
 *
 * 2. The lost_lower_bound captures the number of segments for which
 *    skb->sacked values indicate retransmission and no recovery. It may
 *    be too low if segments that are retransmitted multiple times are
 *    processed by the function only once, and may be too high if a
 *    segment is processed multiple times.
 *
 * 3. An skb can be retransmitted three or more times. If the last two 
 *    transmissions are not lost, we wil flag the skb as timestamp_recovered 
 *    as the confirmed packet (second-to-last transmission) was sent before 
 *    the last retransmission. (The last transmission was spurious, and we 
 *    detect that with the timestamp, but all prior losses are missed. We note 
 *    that the kernel does not care about this error, as it halves the cwnd 
 *    every time it retransmits a packet.)
 *
 */

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

BPF_HASH(ht, struct sock*, struct ack_event, UINT16_MAX);

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

static bool tcp_sock_is_tracked(struct sock *sk)
{
  struct tcp_sock *tp = tcp_sk(sk);
  return tp->cd_random_u16 <= RANDOM_SAMPLE_MAX;
}

static u32 local_tcp_skb_timestamp(const struct sk_buff *skb)
{
  return div_u64(skb->skb_mstamp_ns, NSEC_PER_SEC / TCP_TS_HZ);
}

static int local_tcp_skb_pcount(const struct sk_buff *skb)
{
  struct tcp_skb_cb *scb = TCP_SKB_CB(skb);
  /* Kernel function returns int, but tcp_gso_segs is u16 */
  u16 pcount;
  bpf_probe_read(&pcount, sizeof(pcount), &(scb->tcp_gso_segs));
  return pcount;
}

static bool get_saw_tstamp(const struct tcp_sock *tp)
{
  u16 bitfield;
  // There should be no padding as all fields up to the point are u32
  u8* ptr = (u8*)&(tp->rx_opt.rcv_tsecr);
  ptr += sizeof(tp->rx_opt.rcv_tsecr);
  bpf_probe_read(&bitfield, sizeof(bitfield), ptr);
  // https://elixir.bootlin.com/linux/latest/source/include/linux/tcp.h#L87
  // We get the *last* bit because i386/amd64 is little-endian.
  // Of course, this doesn't work on big-endian machines.
  return (bool)(bitfield & (0x01));
}

/* Copied from the kernel because it is a static function. */
static bool tcp_tsopt_ecr_before(const struct tcp_sock *tp, u32 when)
{
  bool saw_tstamp = get_saw_tstamp(tp);
  u32 rcv_tsecr;
  bpf_probe_read(&rcv_tsecr, sizeof(rcv_tsecr), &(tp->rx_opt.rcv_tsecr));
  // return saw_tstamp && tp->rx_opt.rcv_tsecr &&
  //    before(tp->rx_opt.rcv_tsecr, when);
  return saw_tstamp && rcv_tsecr && before(rcv_tsecr, when);
}

static bool tcp_skb_spurious_retrans(u8 sacked,
    const struct tcp_sock *tp,
    const struct sk_buff *skb)
{
  return (sacked & TCPCB_RETRANS) &&
      tcp_tsopt_ecr_before(tp, local_tcp_skb_timestamp(skb));
}

static void fill_in_tcp_data(struct ack_event *ev, const struct sock *sk)
{
  const struct tcp_sock* tp = tcp_sk(sk);
  const struct inet_connection_sock* icsk = inet_csk(sk);
  _(ev->tcp.delivered, tp->delivered);
  _(ev->tcp.lost, tp->lost);
  _(ev->tcp.total_retrans, tp->total_retrans);
  _(ev->tcp.srtt_us, tp->srtt_us);
  ev->tcp.srtt_us >>= 3;
  _(ev->tcp.mdev_us, tp->mdev_us);
  ev->tcp.mdev_us >>= 2;
  _minmax_get(ev->tcp.min_rtt_us, tp->rtt_min);
  _(ev->tcp.snd_cwnd, tp->snd_cwnd);
  _(ev->tcp.mss_cache, tp->mss_cache);
  _(ev->tcp.rto, icsk->icsk_rto);
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
    struct ack_event ev = { 0 };
    if (event_hdr_init(&ev.header, sk) < 0) { return 0; }
    _(ev.established_snd_una, tp->snd_una);
    ht.update(&sk, &ev);
  } else if (attrs->newstate == TCP_CLOSE) {
    struct ack_event *ev = ht.lookup(&sk);
    if (!ev) { return 0; }

    ev->non_spurious_retrans = tp->total_retrans - 
      ev->dsack_or_timestamp_recovered;

    fill_in_tcp_data(ev, sk);

    ev->seq = 0;
    ev->end_seq = 0;
#ifdef EVDEBUG
    ev->debug.event_source = EV_SOURCE_TCP_CLOSE;
    ev->debug.pcount = 0;
    ev->debug.tcp_gso_size = 0;
    ev->debug.sacked = 0;
    ev->debug.sacked_out = 0;
    ev->debug.tcp_flags = 0;
    ev->debug.tx_delivered = 0;
    ev->debug.tx_first_tx_mstamp = 0;
    ev->debug.tx_delivered_mstamp = 0;
    ev->debug.tlp_high_seq = 0;
#endif

    events.perf_submit((void *)attrs, ev, sizeof(*ev));
  }

  return 0;
}

int on_tcp_skb_acked(struct tracepoint__tcp__tcp_skb_acked* attrs)
{
  struct sock* sk = (struct sock*)attrs->skaddr;
  if (!tcp_sock_is_tracked(sk)) { return 0; }

  struct tcp_sock *tp = tcp_sk(sk);
  struct sk_buff *skb = (struct sk_buff *)attrs->skbaddr;
  struct tcp_skb_cb *scb = TCP_SKB_CB(skb);

  struct ack_event *ev = ht.lookup(&sk);
  if (!ev) { return 0; }
  INCMAX(ev->stats.calls, UINT16_MAX);

  // skb already sacked:
  // https://github.com/torvalds/linux/blob/v5.4/net/ipv4/tcp_rate.c#L101-L106
  if(!scb->tx.delivered_mstamp) {
    INCMAX(ev->stats.calls_with_mstamp_zero, UINT16_MAX);
    // We do not return as this function does not get called for SACKs
    // return 0;
  }

  bool fully_acked = attrs->fully_acked;
  u32 acked_pcount = attrs->acked_pcount;
  int pcount = local_tcp_skb_pcount(skb);

  if (fully_acked) {
    _(ev->seq, scb->seq);
    _(ev->end_seq, scb->end_seq);
  } else {
    _(ev->seq, attrs->orig_seq);
    _(ev->end_seq, tp->snd_una);
  }

  if(scb->sacked & TCPCB_RETRANS) {
    INCMAX(ev->stats.tcpcb_retrans, UINT16_MAX);
    if(scb->sacked & TCPCB_SACKED_RETRANS) {
      INCMAX(ev->stats.tcpcb_sacked_retrans, UINT16_MAX);
    }

    // There was a retransmission and it was ruled unnecessary by timestamps.
    // Packet needs to be cumulatively acked
    // https://github.com/torvalds/linux/blob/v5.4/net/ipv4/tcp_input.c#L3095-L3107
    bool timestamp_recovered = tcp_skb_spurious_retrans(scb->sacked, tp, skb);

    if (fully_acked && scb->end_seq > tp->snd_una) {
      INCMAX(ev->stats.fully_acked_after_snd_una, UINT16_MAX);
    }

    if(scb->sacked & TCPCB_EVER_RETRANS && timestamp_recovered
        && tp->tlp_high_seq == scb->end_seq) {
      // There was a spurius retransmission due to TLP. To
      // detect if it was spurious we need to check if the ack
      // is from the original packet or from the probe.
      INCMAX(ev->stats.spurious_tlp_retrans, UINT16_MAX);
    }

    // Retransmission ruled unecessary by a dsack
    bool dsack_recovered = !(scb->sacked & TCPCB_SACKED_RETRANS);
    // When experiencing TLP we may lose the probe packet and the ACK
    // is going to come with sacked without TCPCB_SACKED_RETRANS. We have
    // to undo this dsack.
    if(scb->sacked & TCPCB_EVER_RETRANS && !timestamp_recovered &&
        tp->tlp_high_seq == scb->end_seq && dsack_recovered) {

      INCMAX(ev->fake_dsack_recovery_induced_by_lost_tlp, UINT32_MAX);
      dsack_recovered = false;
    }

    ev->dsack_recovered += dsack_recovered;
    ev->timestamp_recovered += timestamp_recovered;
    ev->dsack_and_timestamp_recovered += (dsack_recovered &&
        timestamp_recovered);
    ev->dsack_or_timestamp_recovered += (dsack_recovered ||
        timestamp_recovered);

    if(!dsack_recovered && !timestamp_recovered) {
      ev->segments_lost += 1;
      if(!ev->fstloss.detected) {
        ev->fstloss.detected = true;
        ev->fstloss.by_stats = (tp->delivered - tp->sacked_out) - 
          ev->dsack_or_timestamp_recovered;

        int pkt_count = 0;
        if(ev->seq >= ev->established_snd_una) {
          pkt_count = (ev->seq - ev->established_snd_una) / tp->mss_cache;
        }
        else {
          pkt_count = ((UINT32_MAX - ev->established_snd_una) + ev->seq) 
            / tp->mss_cache;
        }
        ev->fstloss.by_seqnum = pkt_count + 1;
      }
    }

  }

#ifdef EVDEBUG
  fill_in_tcp_data(ev, sk);

  ev->debug.event_source = EV_SOURCE_SKB_ACKED;
  _(ev->debug.pcount, acked_pcount);
  _(ev->debug.tcp_gso_size, scb->tcp_gso_size);
  _(ev->debug.sacked_out, tp->sacked_out);
  _(ev->debug.tcp_snd_una, tp->snd_una);
  ev->debug.fully_acked = (u8)fully_acked;
  _(ev->debug.tx_delivered, scb->tx.delivered);
  _(ev->debug.tx_first_tx_mstamp, scb->tx.first_tx_mstamp);
  _(ev->debug.tx_delivered_mstamp, scb->tx.delivered_mstamp);
  _(ev->debug.tlp_high_seq, tp->tlp_high_seq);
  _(ev->debug.sacked, scb->sacked);
  _(ev->debug.tcp_flags, scb->tcp_flags);

  events.perf_submit((void *)attrs, ev, sizeof(*ev));
#endif

  return 0;
}
