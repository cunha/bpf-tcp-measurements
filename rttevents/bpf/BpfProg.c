#include <bcc/proto.h>
#include <linux/socket.h>
#include <linux/tcp.h>
#include <linux/win_minmax.h>
#include <net/sock.h>
#include <net/tcp.h>

#define UINT8_MAX 0xFF
#define UINT16_MAX 0xFFFF
#define UINT32_MAX 0xFFFFFFFFU
// #define INCMAX(v, limit) if((v) < (u16)(limit)) { (v)++; }

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

BPF_PERF_OUTPUT(events);

static int event_hdr_init(struct event_hdr* evh, const struct sock *sk) {
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

static bool tcp_sock_is_tracked(struct sock *sk) {
	struct tcp_sock *tp = tcp_sk(sk);
	return tp->cd_random_u16 <= RANDOM_SAMPLE_MAX;
}

int on_tcp_cong_control(struct tracepoint__tcp__tcp_cong_control* attrs) {
	struct sock* sk = (struct sock*)attrs->skaddr;
	if (!tcp_sock_is_tracked(sk)) { return 0; }

	struct tcp_sock *tp = tcp_sk(sk);
	struct rate_sample *rs = (struct rate_sample*)attrs->rsaddr;
	struct rtt_event ev = {};
	if(event_hdr_init(&ev.header, sk) < 0) {
		return 0;
	}
	_(ev.rtt_us, rs->rtt_us);
	_(ev.bytes_acked, tp->bytes_acked);
	_(ev.packets_out, tp->packets_out);
	_(ev.snd_nxt, tp->snd_nxt);
	events.perf_submit((void *)attrs, &ev, sizeof(ev));
	return 0;
}