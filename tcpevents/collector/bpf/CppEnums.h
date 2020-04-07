#pragma once

#ifndef __cplusplus
#error This file should only be included in C++
#endif

#include <fatal/type/enum.h>

namespace paths {
namespace tcpevents {

/**
 * Socket States.
 *
 * Must remain in sync with kernel include/net/tcp_states.h
 */
enum class InetSockState : uint8_t {
  TCP_ESTABLISHED = 1,
  TCP_SYN_SENT,
  TCP_SYN_RECV,
  TCP_FIN_WAIT1,
  TCP_FIN_WAIT2,
  TCP_TIME_WAIT,
  TCP_CLOSE,
  TCP_CLOSE_WAIT,
  TCP_LAST_ACK,
  TCP_LISTEN,
  TCP_CLOSING, /* Now a valid state */
  TCP_NEW_SYN_RECV,

  TCP_MAX_STATES /* Leave at the end! */
};

FATAL_EXPORT_RICH_ENUM(
    InetSockState,
    TCP_ESTABLISHED,
    TCP_SYN_SENT,
    TCP_SYN_RECV,
    TCP_FIN_WAIT1,
    TCP_FIN_WAIT2,
    TCP_TIME_WAIT,
    TCP_CLOSE,
    TCP_CLOSE_WAIT,
    TCP_LAST_ACK,
    TCP_LISTEN,
    TCP_CLOSING,
    TCP_NEW_SYN_RECV,
    TCP_MAX_STATES);

/**
 * TCP Congestion Avoidance States.
 *
 * Must remain in sync with kernel include/uapi/linux/tcp.h
 */
enum class TcpCaState : uint8_t {
  TCP_CA_Open = 0,
  TCP_CA_Disorder = 1,
  TCP_CA_CWR = 2,
  TCP_CA_Recovery = 3,
  TCP_CA_Loss = 4
};

FATAL_EXPORT_RICH_ENUM(
    TcpCaState,
    TCP_CA_Open,
    TCP_CA_Disorder,
    TCP_CA_CWR,
    TCP_CA_Recovery,
    TCP_CA_Loss);

/**
 *  Events passed to congestion control interface
 *
 * Must remain in sync with kernel include/net/tcp.h
 */
enum class TcpCaEvent {
  CA_EVENT_TX_START, /* first transmit when no packets in flight */
  CA_EVENT_CWND_RESTART, /* congestion window restart */
  CA_EVENT_COMPLETE_CWR, /* end of congestion recovery */
  CA_EVENT_LOSS, /* loss timeout */
  CA_EVENT_ECN_NO_CE, /* ECT set, but not CE marked */
  CA_EVENT_ECN_IS_CE, /* received CE marked IP packet */
  CA_EVENT_DELAYED_ACK, /* Delayed ack is sent */
  CA_EVENT_NON_DELAYED_ACK,
};

FATAL_EXPORT_RICH_ENUM(
    TcpCaEvent,
    CA_EVENT_TX_START,
    CA_EVENT_CWND_RESTART,
    CA_EVENT_COMPLETE_CWR,
    CA_EVENT_LOSS,
    CA_EVENT_ECN_NO_CE,
    CA_EVENT_ECN_IS_CE,
    CA_EVENT_DELAYED_ACK,
    CA_EVENT_NON_DELAYED_ACK);

} // namespace tcpevents
} // namespace paths
