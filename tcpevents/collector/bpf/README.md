

## BPF Development Notes

#### Reference Sites
http://www.brendangregg.com/blog/2018-03-22/tcp-tracepoints.html

#### Showing available tracepoints for tcp with perf
````
sudo perf list 'tcp:*' 'sock:inet*'

List of pre-defined events (to be used in -e):

  tcp:tcp_destroy_sock                               [Tracepoint event]
  tcp:tcp_probe                                      [Tracepoint event]
  tcp:tcp_rcv_space_adjust                           [Tracepoint event]
  tcp:tcp_receive_reset                              [Tracepoint event]
  tcp:tcp_retransmit_skb                             [Tracepoint event]
  tcp:tcp_retransmit_synack                          [Tracepoint event]
  tcp:tcp_send_reset                                 [Tracepoint event]


Metric Groups:

  sock:inet_sock_set_state                           [Tracepoint event]


Metric Groups:
```

```
$ sudo tplist-bpfcc -v 'sock:*'
...
sock:inet_sock_set_state
    const void * skaddr;
    int oldstate;
    int newstate;
    __u16 sport;
    __u16 dport;
    __u16 family;
    __u8 protocol;
    __u8 saddr[4];
    __u8 daddr[4];
    __u8 saddr_v6[16];
    __u8 daddr_v6[16];
```

```
$ sudo tplist-bpfcc -v 'tcp:*'
tcp:tcp_retransmit_skb
    const void * skbaddr;
    const void * skaddr;
    __u16 sport;
    __u16 dport;
    __u8 saddr[4];
    __u8 daddr[4];
    __u8 saddr_v6[16];
    __u8 daddr_v6[16];
tcp:tcp_send_reset
    const void * skbaddr;
    const void * skaddr;
    __u16 sport;
    __u16 dport;
    __u8 saddr[4];
    __u8 daddr[4];
    __u8 saddr_v6[16];
    __u8 daddr_v6[16];
tcp:tcp_receive_reset
    const void * skaddr;
    __u16 sport;
    __u16 dport;
    __u8 saddr[4];
    __u8 daddr[4];
    __u8 saddr_v6[16];
    __u8 daddr_v6[16];
    __u64 sock_cookie;
tcp:tcp_destroy_sock
    const void * skaddr;
    __u16 sport;
    __u16 dport;
    __u8 saddr[4];
    __u8 daddr[4];
    __u8 saddr_v6[16];
    __u8 daddr_v6[16];
    __u64 sock_cookie;
tcp:tcp_rcv_space_adjust
    const void * skaddr;
    __u16 sport;
    __u16 dport;
    __u8 saddr[4];
    __u8 daddr[4];
    __u8 saddr_v6[16];
    __u8 daddr_v6[16];
    __u64 sock_cookie;
tcp:tcp_retransmit_synack
    const void * skaddr;
    const void * req;
    __u16 sport;
    __u16 dport;
    __u8 saddr[4];
    __u8 daddr[4];
    __u8 saddr_v6[16];
    __u8 daddr_v6[16];
tcp:tcp_probe
    __u8 saddr[sizeof(struct sockaddr_in6)];
    __u8 daddr[sizeof(struct sockaddr_in6)];
    __u16 sport;
    __u16 dport;
    __u32 mark;
    __u16 data_len;
    __u32 snd_nxt;
    __u32 snd_una;
    __u32 snd_cwnd;
    __u32 ssthresh;
    __u32 snd_wnd;
    __u32 srtt;
    __u32 rcv_wnd;
    __u64 sock_cookie;
```

// TODO: Track losses inside the kernel. Refs:
//
// https://github.com/torvalds/linux/blob/219d54332a09e8d8741c1e1982f5eae56099de85/net/ipv4/tcp_input.c#L1122
// add counter of undoable_retransmissions whenever we decrement undo_retrans
̉//
// https://github.com/torvalds/linux/blob/v5.4/net/ipv4/tcp_input.c#L2429
// all retransmissions since last event were unecessary, add to undoable_retransmissions