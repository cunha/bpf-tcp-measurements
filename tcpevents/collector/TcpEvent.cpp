#include "TcpEvent.h"

#include <boost/variant.hpp>
#include <folly/Format.h>
#include <folly/Overload.h>
#include <folly/gen/Base.h>
#include <gflags/gflags.h>
#include <glog/logging.h>

using folly::gen::as;
using folly::gen::filter;
using folly::gen::fromConst;

namespace {

const char* kEventStrSeparator = "---";
const char* kUnknownEnumType = "UNKNOWN_ENUM";

folly::SocketAddress
toSocketAddress(const paths::tcpevents::bpf::endpoint_t& endpoint) {
  folly::SocketAddress socketAddress;
  socketAddress.setFromSockaddr((struct sockaddr*)&endpoint);
  socketAddress.tryConvertToIPv4();
  return socketAddress;
}

template <typename T>
folly::Optional<const char*>
fatalEnumToOptStr(T e) {
  const auto charPtr = fatal::enum_to_string(e, kUnknownEnumType);
  if (charPtr) {
    return charPtr;
  }
  return folly::none;
}

template <typename T>
const char*
fatalEnumToStr(T e) {
  return fatal::enum_to_string(e, kUnknownEnumType);
}

struct RegisteredStat {
  RegisteredStat(
      const char* name,
      const int paths::tcpevents::bpf::tcp_event_stats_t::*mPtr)
      : name(name), mPtr(mPtr) {}
  RegisteredStat(
      const char* name,
      const uint8_t paths::tcpevents::bpf::tcp_event_stats_t::*mPtr)
      : name(name), mPtr(mPtr) {}
  RegisteredStat(
      const char* name,
      const uint16_t paths::tcpevents::bpf::tcp_event_stats_t::*mPtr)
      : name(name), mPtr(mPtr) {}
  RegisteredStat(
      const char* name,
      const uint32_t paths::tcpevents::bpf::tcp_event_stats_t::*mPtr)
      : name(name), mPtr(mPtr) {}
  RegisteredStat(
      const char* name,
      const uint64_t paths::tcpevents::bpf::tcp_event_stats_t::*mPtr)
      : name(name), mPtr(mPtr) {}
  RegisteredStat(
      const char* name,
      const bool paths::tcpevents::bpf::tcp_event_stats_t::*mPtr)
      : name(name), mPtr(mPtr) {}

  std::string
  statToStr(const paths::tcpevents::bpf::tcp_event_stats_t& stats) const {
    return folly::variant_match(
        mPtr,
        [&stats](const int paths::tcpevents::bpf::tcp_event_stats_t::*s) {
          return folly::sformat("{}", stats.*s);
        },
        [&stats](const uint8_t paths::tcpevents::bpf::tcp_event_stats_t::*s) {
          return folly::sformat("{}", stats.*s);
        },
        [&stats](const uint16_t paths::tcpevents::bpf::tcp_event_stats_t::*s) {
          return folly::sformat("{}", stats.*s);
        },
        [&stats](const uint32_t paths::tcpevents::bpf::tcp_event_stats_t::*s) {
          return folly::sformat("{}", stats.*s);
        },
        [&stats](const uint64_t paths::tcpevents::bpf::tcp_event_stats_t::*s) {
          return folly::sformat("{}", stats.*s);
        },
        [&stats](const bool paths::tcpevents::bpf::tcp_event_stats_t::*s) {
          return folly::sformat("{}", stats.*s);
        });
  }

  const char* name;
  const boost::variant<
      const int paths::tcpevents::bpf::tcp_event_stats_t::*,
      const uint8_t paths::tcpevents::bpf::tcp_event_stats_t::*,
      const uint16_t paths::tcpevents::bpf::tcp_event_stats_t::*,
      const uint32_t paths::tcpevents::bpf::tcp_event_stats_t::*,
      const uint64_t paths::tcpevents::bpf::tcp_event_stats_t::*,
      const bool paths::tcpevents::bpf::tcp_event_stats_t::*>
      mPtr;
};

#define _stat(stat) \
  RegisteredStat(#stat, &paths::tcpevents::bpf::tcp_event_stats_t::stat)

static std::vector<RegisteredStat> registeredStats = {
    _stat(srtt_us),
    _stat(mdev_us),
    _stat(rttvar_us),
    _stat(min_rtt_us),
    _stat(min_rtt_us_on_establish),
    _stat(snd_cwnd),
    _stat(snd_ssthresh),
    // _stat(snd_cwnd_cnt),
    // _stat(snd_cwnd_clamp),
    // _stat(snd_cwnd_used),
    // _stat(snd_cwnd_stamp),
    // _stat(is_cwnd_limited),
    // _stat(prior_cwnd),
    // _stat(prior_ssthresh),
    // _stat(high_seq),
    // _stat(prr_delivered),
    // _stat(prr_out),
    _stat(segs_in),
    _stat(segs_out),
    _stat(data_segs_in),
    _stat(data_segs_out),
    _stat(total_retrans),
    _stat(bytes_received),
    _stat(bytes_acked),
    _stat(bytes_retrans),
    _stat(delivered),
    _stat(delivered_ce),
    _stat(first_tx_mstamp),
    _stat(delivered_mstamp),
    _stat(mss_cache),
    // _stat(rate_delivered),
    // _stat(rate_interval_us),
    // _stat(rate_app_limited),
    // _stat(app_limited_until),
    // _stat(write_seq),
    // _stat(snd_nxt),
    // _stat(snd_una),
    // _stat(snd_sml),
    // _stat(packets_out),
    // _stat(retrans_out),
    // _stat(sacked_out),
    // _stat(lost_out),
    _stat(lost),
    // _stat(reordering),
    // _stat(reord_seen),
    // _stat(max_packets_out),
    // _stat(max_packets_seq),
    // _stat(rcv_wnd),
    _stat(chrono_busy),
    _stat(chrono_rwnd_limited),
    _stat(chrono_sndbuf_limited),
    // _stat(rack_mstamp),
    // _stat(rack_rtt_us),
    // _stat(rack_end_seq),
    // _stat(rack_last_delivered),
    _stat(pacing_status),
    _stat(pacing_rate),
    _stat(max_pacing_rate),
    _stat(sndbuf),
    _stat(rcvbuf),
    _stat(sk_shutdown),
    _stat(sk_err),
    _stat(sk_err_soft),
    _stat(rto),
    _stat(start_us),
    _stat(bytes_per_ns),

    _stat(cc_algo),
    _stat(fstloss_tracked),
    _stat(fstloss_packet),
    _stat(fstloss_reason),
    _stat(fstloss_done),
    _stat(fstloss_stats_set_loss_count),
    _stat(fstloss_stats_undo_count),
    _stat(fstloss_stats_undone_undo_marker),
    _stat(fstloss_stats_undone_mtu_probing),
    _stat(fstloss_stats_undone_ssthresh_infinite),
    _stat(fstloss_stats_transitions_loss_to_loss),
    _stat(fstloss_stats_transitions_open_to_open),
    _stat(fstloss_stats_transitions_recovery_to_loss),
    _stat(fstloss_stats_transitions_after_done),
    _stat(fstloss_stats_recovery_to_loss_with_partial_acks),

    _stat(ca_state_changes_count),
    _stat(ca_state_changes_open_disorder),
    _stat(ca_state_changes_cwr),
    _stat(ca_state_changes_recovery),
    _stat(ca_state_changes_loss),

};

// TODO(bschlinker): Register these fields
const std::vector<std::string> kHeaderFields(
    {"event_ns", "conn_ns", "src", "dst", "event_type", "event_type_name"});
const std::vector<std::string> kStateFields(
    {"skt_state", "skt_state_name", "ca_state", "ca_state_name"});
const std::vector<std::string> kDetailFields({"old_skt_state",
                                              "old_skt_state_name",
                                              "new_skt_state",
                                              "new_skt_state_name",
                                              "old_ca_state",
                                              "old_ca_state_name",
                                              "new_ca_state",
                                              "new_ca_state_name",
                                              "ca_event",
                                              "ca_event_name"});

} // namespace

namespace paths {
namespace tcpevents {

TcpEvent::TcpEvent(const bpf::tcp_event_t& rawEvent)
    : event_ts(rawEvent.header.ev_tstamp_ns),
      conn_ts(rawEvent.header.conn_tstamp_ns),
      type(rawEvent.header.type),
      details(rawEvent.details),
      rawStats(rawEvent.stats),
      sockState(rawEvent.states.skt_state),
      tcpCaState(rawEvent.states.ca_state),
      src(toSocketAddress(rawEvent.header.src)),
      dst(toSocketAddress(rawEvent.header.dst)) {}

std::string
TcpEvent::toString(
    folly::Optional<std::unordered_set<std::string>> statsToIncludeOpt) const {
  std::vector<std::string> strsToPrint;

  // add the header
  strsToPrint.push_back(folly::sformat(
      "TcpEvent for flow {} -> {}:", src.describe(), dst.describe()));

  // add header fields
  const auto headerFields = getHeaderMap();
  for (const auto& kv : headerFields) {
    strsToPrint.push_back(folly::sformat("{} = {}", kv.first, kv.second));
  }

  // separator lambda
  const auto addSeparator = [&strsToPrint](const std::string& name) {
    strsToPrint.emplace_back(folly::sformat(
        "{} {} {}", kEventStrSeparator, name, kEventStrSeparator));
  };

  // add state fields
  addSeparator("state");
  const auto stateFields = getStateMap();
  for (const auto& kv : stateFields) {
    strsToPrint.push_back(folly::sformat("{} = {}", kv.first, kv.second));
  }

  // add detail fields
  const auto detailFields = getDetailMap();
  if (detailFields.size()) {
    addSeparator("detail");
    for (const auto& kv : detailFields) {
      strsToPrint.push_back(folly::sformat("{} = {}", kv.first, kv.second));
    }
  }

  // add stat fields
  const auto statFields = fromConst(getStatMap()) |
      filter([&statsToIncludeOpt](const auto& kv) {
                            return (not statsToIncludeOpt.has_value()) or
                                (statsToIncludeOpt.value().count(kv.first));
                          }) |
      as<std::map<std::string, std::string>>();
  if (statFields.size()) {
    addSeparator("stat");
    for (const auto& kv : statFields) {
      strsToPrint.push_back(folly::sformat("{} = {}", kv.first, kv.second));
    }
  }

  return folly::join("\n\t", strsToPrint);
}

folly::Optional<const char*>
TcpEvent::getTypeAsStr() const {
  return fatalEnumToOptStr(type);
}

folly::Optional<const char*>
TcpEvent::getInetSockStateAsStr() const {
  return fatalEnumToOptStr(sockState);
}

folly::Optional<const char*>
TcpEvent::getTcpCaStateAsStr() const {
  return fatalEnumToOptStr(tcpCaState);
}

std::map<std::string, std::string>
TcpEvent::getFieldMap() const {
  std::map<std::string, std::string> result;
  result.merge(getHeaderMap());
  result.merge(getStateMap());
  result.merge(getDetailMap());
  result.merge(getStatMap());
  return result;
}

std::map<std::string, std::string>
TcpEvent::getHeaderMap() const {
  std::map<std::string, std::string> result;
  result.emplace(
      "event_ns",
      std::to_string(
          std::chrono::duration_cast<std::chrono::nanoseconds>(event_ts).count()));
  result.emplace(
      "conn_ns",
      std::to_string(
          std::chrono::duration_cast<std::chrono::nanoseconds>(conn_ts).count()));
  result.emplace("src", src.describe());
  result.emplace("dst", dst.describe());
  result.emplace("event_type", std::to_string(int(type)));
  result.emplace("event_type_name", fatalEnumToStr(type));
  return result;
}

std::map<std::string, std::string>
TcpEvent::getStateMap() const {
  std::map<std::string, std::string> result;
  result.emplace("skt_state", std::to_string((int)sockState));
  result.emplace("skt_state_name", fatalEnumToStr(sockState));
  result.emplace("ca_state", std::to_string((int)tcpCaState));
  result.emplace("ca_state_name", fatalEnumToStr(tcpCaState));
  return result;
}

std::map<std::string, std::string>
TcpEvent::getDetailMap() const {
  std::map<std::string, std::string> result;

  switch (type) {
  case bpf::tcp_event_type_e::INET_SOCK_SET_STATE: {
    const auto oldState = details.state_change.old_state.skt_state;
    const auto newState = details.state_change.new_state.skt_state;
    result.emplace("old_skt_state", std::to_string((int)oldState));
    result.emplace("old_skt_state_name", fatalEnumToStr(oldState));
    result.emplace("new_skt_state", std::to_string((int)newState));
    result.emplace("new_skt_state_name", fatalEnumToStr(newState));
    break;
  }
  case bpf::tcp_event_type_e::TCP_SET_CA_STATE: {
    const auto oldState = details.state_change.old_state.ca_state;
    const auto newState = details.state_change.new_state.ca_state;
    result.emplace("old_ca_state", std::to_string((int)oldState));
    result.emplace("old_ca_state_name", fatalEnumToStr(oldState));
    result.emplace("new_ca_state", std::to_string((int)newState));
    result.emplace("new_ca_state_name", fatalEnumToStr(newState));
    break;
  }
  case bpf::tcp_event_type_e::TCP_CA_EVENT: {
    const auto caEvent = details.ca_event;
    result.emplace("ca_event", std::to_string((int)caEvent));
    result.emplace("ca_event_name", fatalEnumToStr(caEvent));
    break;
  }
  default:
    break;
  };

  return result;
}

std::map<std::string, std::string>
TcpEvent::getStatMap() const {
  std::map<std::string, std::string> result;
  for (const auto& rStat : registeredStats) {
    result.emplace(rStat.name, folly::sformat("{}", rStat.statToStr(rawStats)));
  }
  return result;
}

std::vector<std::string>
TcpEvent::getHeaderFieldNames() {
  return kHeaderFields;
}

std::vector<std::string>
TcpEvent::getDetailFieldNames() {
  return kDetailFields;
}

std::vector<std::string>
TcpEvent::getStateFieldNames() {
  return kStateFields;
}

std::vector<std::string>
TcpEvent::getStatFieldNames() {
  std::vector<std::string> result;
  for (const auto& rStat : registeredStats) {
    result.push_back(rStat.name);
  }
  return result;
}

} // namespace tcpevents
} // namespace paths
