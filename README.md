# TCP BPF monitors

The TCP monitors use BPF to hook into several kernel locations and
track information from TCP and store it in a database.

## Installation and dependencies

### Build tools

``` {bash}
apt install -y \
    autoconf \
    automake \
    binutils-dev \
    build-essential \
    clang \
    clang-format \
    clang-tidy \
    clang-tools \
    cmake \
    g++ \
    git \
    libc++-dev \
    libc++1 \
    libclang1 \
    libssl-dev \
    libtool \
    lld \
    make \
    pkg-config \
    python-dev
```

### Libraries

``` {bash}
apt install -y \
    libboost-all-dev \
    libdouble-conversion-dev \
    libevent-dev \
    libgflags-dev \
    libgoogle-glog-dev \
    libiberty-dev \
    libjemalloc-dev \
    liblz4-dev \
    liblzma-dev \
    libmnl0 \
    libmnl-dev \
    libmstch-dev \
    libnl-route-3-200 \
    libnl-route-3-dev \
    libnl-nf-3-200 \
    libnl-nf-3-dev \
    libsnappy-dev \
    libsodium-dev \
    libssl-dev \
    libzstd1 \
    libzstd-dev \
    zlib1g-dev
```

### Installing BCC

We currently pull BCC from Sid (see below).

``` {bash}
apt install -y \
    bpfcc-tools \
    libbpfcc \
    libbpfcc-dev \
    python3-bpfcc
```

We also need kernel headers:

``` {bash}
apt install -y \
  linux-base \
  linux-headers-amd64
```

## Kernel patching

``` {bash}
apt build-dep linux
# apt source linux --- this may get you a different kernel version
apt install linux-source-5.3 --- update for the current kernel version
cd /usr/src
tar Jxf linux-source-5.2.tar.xz
cd linux-source-5.2
patch -p1 < $EMUREPO/src/kernel/tcp_cong_tracepoint.patch
cp /boot/config-$(uname -r) ./.config
```

You will need to remove the signing keys by removing the line with
`CONFIG_SYSTEM_TRUSTED_KEYS`. Then continue with the configuration and building process

``` {bash}
make oldconfig
# make -j6 vmlinux
make -j6 deb-pkg LOCALVERSION=-custom
```

### Generating a patch

To generate a patch, use `diff -aur SOURCE CHANGED`, preferrably before running any compilation tasks in either `SOURCE` or `CHANGED` to avoid complaints about missing/new files.

## Kernel changes

We add a tracepoint on the `tcp_cong_control` function to be able to get all RTT estimations made by the kernel during the lifetime of a connection.

The `rs->rtt_us` field is initialized inside `tcp_ack_update_rtt`.
`rs->rtt_us` is not updated (and possibly not even read) from its
initialization until its use by BBR in `tcp_cong_control` (CUBIC does
not use `struct rate_sample` at all).

`rs->rtt_us` is initialized with either `seq_rtt_us` or `ca_rtt_us`,
depending on their values. `seq_rtt_us` is used to compute the TCP
retransmission timeout; when an ACK covers multiple segments,
`seq_rtt_us` is the interval between the *first* acknowledged segment
and the ACK. `ca_rtt_us` is used for estimating the minimum RTT; when an
ACK covers multiple segments, `ca_rtt_us` is the interval between the
*last* acknowledged segment and the ACK.

``` {c}
    seq_rtt_us = tcp_stamp_us_delta(tp->tcp_mstamp, first_ackt);
    ca_rtt_us = tcp_stamp_us_delta(tp->tcp_mstamp, last_ackt);
```

Notes on `tcp_clean_rtx_queue`: The kernel first computes `seq_rtt_us`
and `ca_rtt_us` based on each segment's send timestamp and the ACK
receive timestamp. Both are set to `-1` if the ACK is for a
retransmitted segment. Alternate estimates can be obtained when SACKs
are used; in these cases the kernel updates `ca_rtt_us` with the SACK
estimate, but updates `seq_rtt_us` only for retransmitted segments.

Notes on `tcp_ack_update_rtt`: When a segment is retransmitted and SACK is not used, the kernel falls back to `TSecr`.

### Tips

* Generate a patch with `diff -aur /usr/src/linux-source-XXX ./linux-source-XXX > trace_tcp_cong_control.patch`

## Reference Materials

https://github.com/facebook/fboss/tree/master/common
https://github.com/facebook/fboss/blob/master/fboss/agent/Main.cpp
https://github.com/facebook/fbzmq/blob/master/fbzmq/examples/server/ZmqServerMain.cpp
