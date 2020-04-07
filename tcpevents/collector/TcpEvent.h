#pragma once

#include <fatal/type/enum.h>
#include <folly/SocketAddress.h>
#include <src/tcpevents/collector/bpf/BpfStructs.h>
#include <chrono>
#include <map>
#include <set>
#include <unordered_set>

namespace paths {
namespace tcpevents {

/**
 * TcpEvent object that wraps raw events received from eBPF in kernel.
 */
struct TcpEvent {
  using Type = bpf::tcp_event_type_e;

  // TODO(bschlinker): Change constructor to be tryToTcpEvent, since some of the
  // construction process can throw (although unlikely...)
  TcpEvent(const bpf::tcp_event_t& rawEvent);

  /**
   * Build a string representation of the TcpEvent.
   *
   * If statsToInclude is specified, only the stats in the vector will be
   * included in the generated string.
   */
  std::string toString(
      folly::Optional<std::unordered_set<std::string>> statsToIncludeOpt =
          folly::none) const;

  /**
   * Get all fields in a map (field name -> field value).
   *
   * Used std::map to provide ordering.
   */
  std::map<std::string, std::string> getFieldMap() const;

  /**
   * Get all header information in a map (header field name -> field value).
   *
   * Used std::map to provide ordering.
   */
  std::map<std::string, std::string> getHeaderMap() const;

  /**
   * Get all state information in a map (state name -> state value).
   *
   * Used std::map to provide ordering.
   */
  std::map<std::string, std::string> getStateMap() const;

  /**
   * Get all event details map (detail field name -> field value).
   *
   * Returns empty map if the event does not have any details.
   * Used std::map to provide ordering.
   *
   * TODO(bschlinker): Always return all fields in detail map.
   */
  std::map<std::string, std::string> getDetailMap() const;

  /**
   * Get all stat information in a map (stat name -> stat value).
   *
   * Used std::map to provide ordering.
   */
  std::map<std::string, std::string> getStatMap() const;

  /**
   * Get all registered header field names.
   */
  static std::vector<std::string> getHeaderFieldNames();

  /**
   * Get all registered state field names.
   */
  static std::vector<std::string> getStateFieldNames();

  /**
   * Get all registered detail field names.
   */
  static std::vector<std::string> getDetailFieldNames();

  /**
   * Get all registered stat field names.
   */
  static std::vector<std::string> getStatFieldNames();

  /**
   * Get the event type as a string.
   *
   * If the event type is not known (likely ABI mismatch), returns folly::none.
   */
  folly::Optional<const char*> getTypeAsStr() const;

  /**
   * Get the event socket state as a string.
   *
   * If the state is not known (likely ABI mismatch), returns folly::none.
   */
  folly::Optional<const char*> getInetSockStateAsStr() const;

  /**
   * Get the event TCP congestion avoidance state as a string.
   *
   * If the state is not known (likely ABI mismatch), returns folly::none.
   */
  folly::Optional<const char*> getTcpCaStateAsStr() const;

  // Timestamps in microseconds
  const std::chrono::nanoseconds event_ts;
  const std::chrono::nanoseconds conn_ts;

  // Event type
  const bpf::tcp_event_type_e type;

  // Event details
  const bpf::tcp_event_details_t details;

  // Raw Stats from original C structure
  const bpf::tcp_event_stats_t rawStats;

  // Socket state
  const InetSockState sockState;

  // TCP congestion avoidance state
  const TcpCaState tcpCaState;

  // Source IP address and port
  const folly::SocketAddress src;

  // Destination IP address and port
  const folly::SocketAddress dst;
};

} // namespace tcpevents
} // namespace paths
