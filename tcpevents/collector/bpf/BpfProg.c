#include <bcc/proto.h>
#include <linux/socket.h>
#include <linux/tcp.h>
#include <linux/win_minmax.h>
#include <net/sock.h>
#include <net/tcp.h>

#include "BpfStructs.h"
#include "BpfPrivateStructs.h"

/* We generate a random byte on socket initialization to allow control
 * of sampling rates (tcp_sock->cd_random_byte). In this code, we only
 * track sockets whose random_byte is lower than RANDOM_BYTE_MAX.
 * RANDOM_BYTE_MAX should be passed as a parameter to BCC. The default
 * behavior is to track all sockets. */
#ifndef RANDOM_SAMPLE_MAX
#define RANDOM_SAMPLE_MAX UINT16_MAX
#endif

/* Because errors can acumulate over the lifetime of a connection, we
 * keep track of events and stats only up to the point where
 * MAX_TRACKED_PACKET packets have been transmitted in the connection. */
#ifndef MAX_TRACKED_PACKET
#define MAX_TRACKED_PACKET 64
#endif

#define _(var, src) bpf_probe_read(&var, sizeof(var), (void*)&src);

#define _minmax_get(var, src)     \
  {                        \
    struct minmax mm;      \
    _(mm, src);            \
    var = minmax_get(&mm); \
  }

#define INCMAX(v, limit) if((v) < (u16)(limit)) { (v)++; }

// Perf buffer for exporting TCP events
BPF_PERF_OUTPUT(events);

BPF_HASH(ht, struct sock*, struct connection_stats, UINT16_MAX);

/*****************************************************************************
 * helper functions
 *****************************************************************************/
static bool tcp_sock_is_tracked(struct sock *sk) {
  struct tcp_sock *tp = tcp_sk(sk);
  return tp->cd_random_u16 <= RANDOM_SAMPLE_MAX;
}

static u8 get_ca_state(struct inet_connection_sock* icsk) {
  u8* bitset_ptr = ((u8*)(&icsk->icsk_retransmits)) - 1;
  u8 bitset;
  bpf_probe_read(&bitset, sizeof(bitset), (void*)bitset_ptr);
  return bitset & 0x3F;
}

static uint8_t
get_cc_algo(struct connection_stats *cs, struct sock *sk) {
  if(cs->cc_algo == TCP_CA_NAME_UNSET) {
    char cmp[TCP_CA_NAME_MAX+1];
    struct inet_connection_sock* icsk = inet_csk(sk);
    bpf_probe_read_str(cmp, sizeof(cmp), &icsk->icsk_ca_ops->name);
    char cubic[] = "cubic";
    char bbr[] = "bbr";
    int i = 0;
    for(; i < 5 && cubic[i] == cmp[i]; i++);
    if(i == 5) {
      cs->cc_algo = TCP_CA_NAME_CUBIC;
    } else {
      for(i = 0; i < 3 && bbr[i] == cmp[i]; i++);
      if(i == 3) {
        cs->cc_algo = TCP_CA_NAME_BBR;
      } else {
        cs->cc_algo = TCP_CA_NAME_UNKNOWN;
      }
    }
  }
  return cs->cc_algo;
}

static void
count_ca_state_changes(struct connection_stats *cs,
    struct sock *sk,
    u8 old_state,
    u8 new_state) {
  INCMAX(cs->ca_state_changes.count, UINT16_MAX);
  switch (new_state) {
    case TCP_CA_Open:
    case TCP_CA_Disorder:
      INCMAX(cs->ca_state_changes.tcp_ca_open_disorder, UINT16_MAX);
    break;
    case TCP_CA_CWR:
      INCMAX(cs->ca_state_changes.tcp_ca_cwr, UINT16_MAX);
    break;
    case TCP_CA_Recovery:
      INCMAX(cs->ca_state_changes.tcp_ca_recovery, UINT16_MAX);
    break;
    case TCP_CA_Loss:
      INCMAX(cs->ca_state_changes.tcp_ca_loss, UINT16_MAX);
    break;
  }
}

static void
lts_set_loss(struct loss_track_state *lts, u8 reason) {
  if(!lts->first_loss_reason) {
    INCMAX(lts->stats.set_loss_count, UINT8_MAX);
    lts->first_lost_packet = lts->enter.first_lost_packet;
    lts->first_loss_reason = reason;
  }
}

static void
lts_reset(struct loss_track_state *lts) {
  lts->enter.snd_nxt = 0;
  lts->enter.snd_una = 0;
  lts->enter.prior_ssthresh = 0;
  lts->enter.first_lost_packet = 0;
}

static void
lts_undo(struct loss_track_state *lts) {
  INCMAX(lts->stats.undo_count, UINT8_MAX);
  lts_reset(lts);
  lts->first_lost_packet = 0;
  lts->first_loss_reason = 0;
}

static void
lts_save(struct loss_track_state *lts, struct sock *sk) {
  struct tcp_sock* tsk = tcp_sk(sk);
  u32 fstloss = tsk->delivered - tsk->sacked_out;
  if(fstloss > UINT16_MAX) { fstloss = UINT16_MAX; }
  lts->enter.snd_nxt = tsk->snd_nxt;
  lts->enter.snd_una = tsk->snd_una;
  lts->enter.prior_ssthresh = tsk->prior_ssthresh;
  lts->enter.first_lost_packet = fstloss;
}

static void
lts_set_error(struct loss_track_state *lts, u8 reason) {
  lts_reset(lts);
  lts->error = reason;
}

static void
lts_handle_open(struct connection_stats *cs,
    struct loss_track_state *lts,
    struct sock *sk,
    u8 old_state,
    u8 new_state) {
  if(old_state <= TCP_CA_Disorder) {
    /* Nothing to do unless recovering from loss. */
    INCMAX(lts->stats.transitions_open_to_open, UINT8_MAX);
    lts_reset(lts);
    return;
  }

  if(lts->enter.prior_ssthresh == 0) {
    // This "loss" event was due to MTU probing, ignoring.
    INCMAX(lts->stats.undone_mtu_probing, UINT8_MAX);
    lts_reset(lts);
    return;
  }

  struct tcp_sock* tsk = tcp_sk(sk);
  if(lts->enter.snd_nxt != tsk->high_seq) {
    /* This check prevents us from confusing multiple CA_Loss events
     * (e.g., when we get Open->Loss, miss Loss->Open, miss Open->Loss,
     * and get Loss->Open). In this case we missed track of the first
     * loss and ignore the connection. However, this is a conservative:
     * The kernel updates tsk->high_seq every time it enters CA_Loss and
     * whenever F-RTO/SACKs identify spurious retransmissions:
     * enter_snd_next may be different from tsk->high_seq even if we are
     * still in the same loss event.
     * https://github.com/torvalds/linux/blob/v5.4/net/ipv4/tcp_input.c#L2687
     */
    lts_set_error(lts, LTS_ERR_WRONG_HIGH_SEQ);
    return;
  }

  if((old_state == TCP_CA_Recovery || old_state == TCP_CA_Loss)
      && tsk->undo_marker == 0) {
    /* We're coming in from a loss state without error and all
     * retransmissions were undone. Condition ensures we do not enter
     * here if coming from CWR. */
    INCMAX(lts->stats.undone_undo_marker, UINT8_MAX);
    lts_reset(lts);
    return;
  }

  if(get_cc_algo(cs, sk) == TCP_CA_NAME_CUBIC
      && tsk->snd_ssthresh == TCP_INFINITE_SSTHRESH) {
    /* Return early, as there is no loss; lts->first_loss_reason must have
     * been reset in track_losses() already. */
    if(lts->first_loss_reason) {
      lts_set_error(lts, LTS_ERR_LOSS_WITH_INFINTE_SSTHRESH);
      return;
    }
    lts_reset(lts);
    return;
  }

  lts_set_loss(lts, LTS_REASON_NORMAL_RECOVERY);
  lts_reset(lts);
}

static void
track_losses(struct connection_stats *cs,
    struct loss_track_state *lts,
    struct sock *sk,
    u8 old_state,
    u8 new_state) {
  if(lts->error) {
    return;
  }
  struct tcp_sock* tsk = tcp_sk(sk);
  struct inet_connection_sock* icsk = inet_csk(sk);
  if(tsk->delivered - tsk->sacked_out > MAX_TRACKED_PACKET &&
      lts->enter.first_lost_packet == 0) {
    /* Stop tracking if we're past MAX_TRACKED_PACKET and not already
     * tracking any loss. This requires we call lts_reset() whenever we
     * stop tracking a loss episode. */
    lts->done = 1;
  }
  if(lts->done) {
    /* Nothing to do after we're done with tracking the first loss. */
    INCMAX(lts->stats.transitions_after_done, UINT8_MAX);
    return;
  }
  if(old_state != lts->old_state) {
    lts_set_error(lts, LTS_ERR_MISSED_TRANSITION);
    return;
  }
  lts->old_state = new_state;

  if(get_cc_algo(cs, sk) == TCP_CA_NAME_CUBIC
      && tsk->snd_ssthresh == TCP_INFINITE_SSTHRESH
      && lts->first_loss_reason) {
    /* We had confirmed loss, but it has been undone. As this check is
     * after the lts->done check, we may fail to check for undos that
     * happen after we transition to open (undos that happen before or
     * on the transition to CA_Open never call lts_set_loss() and are
     * not a problem). We can quantify the frequency of these "undos
     * after CA_Open" events by checking the value of this counter. */
    INCMAX(lts->stats.undone_ssthresh_infinite, UINT8_MAX);
    lts_undo(lts);
  }

  switch(new_state) {
  case TCP_CA_Open:
  case TCP_CA_Disorder:
    lts_handle_open(cs, lts, sk, old_state, new_state);
    break;
  case TCP_CA_CWR:
    // This is a TLP-confirmed loss.  The kernel switches right
    // back to Open and never undoes TLP-confirmed losses.
    lts_save(lts, sk);
    lts_set_loss(lts, LTS_REASON_TLP_CONFIRMED);
    break;
  case TCP_CA_Recovery:
    if(old_state == TCP_CA_Recovery) {
      // We think transitions from recovery to recovery should not happen.
      lts_set_error(lts, LTS_ERR_RECOVERY_TO_RECOVERY);
      return;
    }
    if(tsk->prior_ssthresh == 0) {
      // we use prior_sshthresh == 0 to identify losses due to MTU
      // probing. however, tcp_enter_recovery() also sets
      // prior_sshthresh = 0, and then proceeds to set it back to
      // current_sshthresh() whenever we're not already in CWR. It seems
      // we should rarely be in CWR when calling tcp_enter_recovery(),
      // as there are no recovery-to-recovery transitions.
      // https://github.com/torvalds/linux/blob/v5.4/net/ipv4/tcp_input.c#L2651
      lts_set_error(lts, LTS_ERR_PRIOR_SSHTHRESH_ZERO_IN_RECOVERY);
      return;
    }
    // FALLTHROUGH
  case TCP_CA_Loss:
    /* If old_state == TCP_CA_Recovery || TCP_CA_Loss, we are reentering
     * the loss event (e.g., RTO of a retransmitted packet). Cannot
     * overwrite state, need to keep track of the first packet that put
     * it in Recovery or Loss. */
    if(old_state == TCP_CA_Recovery) {
      /* old_state == TCP_CA_Recovery does NOT fall through from above */
      INCMAX(lts->stats.transitions_recovery_to_loss, UINT8_MAX);
      if(tsk->snd_una != lts->enter.snd_una ||
        tsk->snd_nxt != lts->enter.snd_nxt) {
        INCMAX(lts->stats.recovery_to_loss_with_partial_acks, UINT8_MAX);
      }
    } else if(old_state == TCP_CA_Loss) {
      INCMAX(lts->stats.transitions_loss_to_loss, UINT8_MAX);
      if(tsk->snd_una != lts->enter.snd_una ||
          tsk->snd_nxt != lts->enter.snd_nxt) {
        /* We are re-entering loss, but the window has moved since we
         * saved the loss state. Some of the packets assumed lost were
         * received, but the connection cannot yet move into CA_Open
         * because some packets are still lost. Here we conservatively
         * charge loss to the first packet we observed when we first
         * transition into loss. */
        lts_set_loss(lts, LTS_REASON_LOSS_WITH_PARTIAL_ACKS);
        lts_reset(lts);
      }
    } else {
      /* New loss event, save state for tracking. */
      lts_save(lts, sk);
    }
    break;
  }
}

static void
handle_tcp_establish(struct sock* sk) {
  if (!tcp_sock_is_tracked(sk)) { return; }
  struct tcp_sock* tsk = tcp_sk(sk);

  struct connection_stats cs = { 0 };

  cs.start_us = bpf_ktime_get_ns() / 1000;
  _minmax_get(cs.minrtt_on_establish, tsk->rtt_min);
  cs.cc_algo = TCP_CA_NAME_UNSET;  /* unnecessary, but being explicit */

  ht.update(&sk, &cs);
}

/*****************************************************************************
 * perf buffer/event handling
 *****************************************************************************/
static void
send_stats_event(void* ctx, struct sock* sk, struct tcp_event_t* event) {
  struct tcp_sock* tsk = tcp_sk(sk);
  struct inet_sock* inet = inet_sk(sk);
  struct inet_connection_sock* icsk = inet_csk(sk);
  struct connection_stats *cs = ht.lookup(&sk);
  if (!cs) { return; }

  // header
  event->header.ev_tstamp_ns = bpf_ktime_get_ns();
  event->header.conn_tstamp_ns = tsk->cd_init_clock_ns;

  {
    struct sockaddr* src = (struct sockaddr*)&event->header.src;
    struct sockaddr* dst = (struct sockaddr*)&event->header.dst;
    _(src->sa_family, sk->sk_family);
    _(dst->sa_family, sk->sk_family);
  }

  if (sk->sk_family == AF_INET) {
    struct sockaddr_in* src = (struct sockaddr_in*)&event->header.src;
    struct sockaddr_in* dst = (struct sockaddr_in*)&event->header.dst;
    _(src->sin_port, inet->inet_sport);
    _(dst->sin_port, inet->inet_dport);
    _(src->sin_addr, inet->inet_saddr);
    _(dst->sin_addr, inet->inet_daddr);
  } else if (sk->sk_family == AF_INET6) {
    struct sockaddr_in6* src = (struct sockaddr_in6*)&event->header.src;
    struct sockaddr_in6* dst = (struct sockaddr_in6*)&event->header.dst;
    _(src->sin6_port, inet->inet_sport);
    _(dst->sin6_port, inet->inet_dport);
    _(src->sin6_addr, sk->sk_v6_rcv_saddr);
    _(dst->sin6_addr, sk->sk_v6_daddr);
  } else {
    return;
  }

  // state info
  _(event->states.skt_state, sk->sk_state);
  event->states.ca_state = get_ca_state(icsk);

  // stats

  //////////////////////////////////////////////////
  // from struct tcp_sock
  // see include/linux/tcp.h
  //////////////////////////////////////////////////
  _(event->stats.srtt_us, tsk->srtt_us);
  event->stats.srtt_us = event->stats.srtt_us >> 3;
  _(event->stats.mdev_us, tsk->mdev_us);
  event->stats.mdev_us >>= 2;
  _(event->stats.rttvar_us, tsk->rttvar_us);
  event->stats.rttvar_us >>= 2;

  _minmax_get(event->stats.min_rtt_us, tsk->rtt_min);
  event->stats.min_rtt_us_on_establish = cs->minrtt_on_establish;

  _(event->stats.snd_ssthresh, tsk->snd_ssthresh);
  _(event->stats.snd_cwnd, tsk->snd_cwnd);

  _(event->stats.segs_in, tsk->segs_in);
  _(event->stats.segs_out, tsk->segs_out);
  _(event->stats.data_segs_in, tsk->data_segs_in);
  _(event->stats.data_segs_out, tsk->data_segs_out);
  _(event->stats.total_retrans, tsk->total_retrans);

  _(event->stats.bytes_received, tsk->bytes_received);
  _(event->stats.bytes_acked, tsk->bytes_acked);
  _(event->stats.bytes_retrans, tsk->bytes_retrans);

  _(event->stats.delivered, tsk->delivered);
  _(event->stats.delivered_ce, tsk->delivered_ce);
  _(event->stats.first_tx_mstamp, tsk->first_tx_mstamp);
  _(event->stats.delivered_mstamp, tsk->delivered_mstamp);

  _(event->stats.mss_cache, tsk->mss_cache);

  _(event->stats.lost, tsk->lost);

  {
    // TODO: Improve to handle all chrono types and account for chrono_start
    uint32_t chrono_stats[__TCP_CHRONO_MAX];
    _(chrono_stats, tsk->chrono_stat);

    event->stats.chrono_busy = chrono_stats[TCP_CHRONO_BUSY - 1];
    event->stats.chrono_rwnd_limited =
        chrono_stats[TCP_CHRONO_RWND_LIMITED - 1];
    event->stats.chrono_sndbuf_limited =
        chrono_stats[TCP_CHRONO_SNDBUF_LIMITED - 1];

    event->stats.chrono_busy *= USEC_PER_SEC / HZ;
    event->stats.chrono_rwnd_limited *= USEC_PER_SEC / HZ;
    event->stats.chrono_sndbuf_limited *= USEC_PER_SEC / HZ;
  }

  //////////////////////////////////////////////////
  // from struct sock
  // see include/net/sock.h
  //////////////////////////////////////////////////
  _(event->stats.pacing_status, sk->sk_pacing_status);
  _(event->stats.pacing_rate, sk->sk_pacing_rate);
  _(event->stats.max_pacing_rate, sk->sk_max_pacing_rate);

  _(event->stats.sndbuf, sk->sk_sndbuf);
  _(event->stats.rcvbuf, sk->sk_rcvbuf);

  _(event->stats.sk_shutdown, sk->sk_shutdown);
  _(event->stats.sk_err, sk->sk_err);
  _(event->stats.sk_err_soft, sk->sk_err_soft);

  //////////////////////////////////////////////////
  // from inet_connection_sock
  // see include/net/inet_connection_sock.h
  //////////////////////////////////////////////////
  _(event->stats.rto, icsk->icsk_rto);

  // custom tracking of socket start time and throughput
  {
    u64 tstamp_us = bpf_ktime_get_ns() / 1000;
    u64 duration = (tstamp_us > cs->start_us) ? (tstamp_us - cs->start_us) : 1;
    event->stats.start_us = cs->start_us;
    event->stats.bytes_per_ns = 1000 * event->stats.bytes_acked / duration;
  }

  // loss_track_state
  {
    struct loss_track_state *lts = &(cs->loss_track_state);
    event->stats.cc_algo = cs->cc_algo;
    event->stats.fstloss_tracked = 1;
    event->stats.fstloss_packet = lts->first_lost_packet;
    event->stats.fstloss_reason = lts->first_loss_reason;
    event->stats.fstloss_error = lts->error;
    event->stats.fstloss_done = lts->done;
    event->stats.fstloss_stats_set_loss_count = lts->stats.set_loss_count;
    event->stats.fstloss_stats_undo_count = lts->stats.undo_count;
    event->stats.fstloss_stats_undone_undo_marker =
        lts->stats.undone_undo_marker;
    event->stats.fstloss_stats_undone_mtu_probing =
        lts->stats.undone_mtu_probing;
    event->stats.fstloss_stats_undone_ssthresh_infinite =
        lts->stats.undone_ssthresh_infinite;
    event->stats.fstloss_stats_transitions_loss_to_loss =
        lts->stats.transitions_loss_to_loss;
    event->stats.fstloss_stats_transitions_open_to_open =
        lts->stats.transitions_open_to_open;
    event->stats.fstloss_stats_transitions_recovery_to_loss =
        lts->stats.transitions_recovery_to_loss;
    event->stats.fstloss_stats_transitions_after_done =
        lts->stats.transitions_after_done;
    event->stats.fstloss_stats_recovery_to_loss_with_partial_acks =
        lts->stats.recovery_to_loss_with_partial_acks;
  }

  // ca_state_changes
  {
    event->stats.ca_state_changes_count = cs->ca_state_changes.count;
    event->stats.ca_state_changes_open_disorder =
        cs->ca_state_changes.tcp_ca_open_disorder;
    event->stats.ca_state_changes_cwr = cs->ca_state_changes.tcp_ca_cwr;
    event->stats.ca_state_changes_recovery =
        cs->ca_state_changes.tcp_ca_recovery;
    event->stats.ca_state_changes_loss = cs->ca_state_changes.tcp_ca_loss;
  }

  events.perf_submit(ctx, event, sizeof(*event));
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
    handle_tcp_establish(sk);
  }

  if (attrs->newstate != TCP_CLOSE) {
    /* Reduce the number of events sent to user space. */
    return 0;
  }

  struct tcp_event_t event = {};
  event.header.type = INET_SOCK_SET_STATE;
  event.details.state_change.old_state.skt_state = attrs->oldstate;
  event.details.state_change.new_state.skt_state = attrs->newstate;
  send_stats_event((void*)attrs, sk, &event);

  return 0;
}

int
on_tcp_set_ca_state(struct pt_regs* ctx, struct sock* sk, u8 new_state) {
  if (!tcp_sock_is_tracked(sk)) { return 0; }
  struct inet_connection_sock* icsk = inet_csk(sk);
  u8 old_state = get_ca_state(icsk);
  struct connection_stats *cs = ht.lookup(&sk);
  if (!cs) { return 0; }

  count_ca_state_changes(cs, sk, old_state, new_state);
  track_losses(cs, &(cs->loss_track_state), sk, old_state, new_state);

  return 0;
}
