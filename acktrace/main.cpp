#include <src/common/Init.h>
#include <src/common/SignalHandler.h>
#include <src/acktrace/AckTraceCollector.h>
#include <src/acktrace/bpf/BpfStructs.h>

#include <iostream>
#include <thread>
#include <vector>

#include <folly/FileUtil.h>
#include <folly/File.h>
#include <folly/Format.h>
#include <folly/SocketAddress.h>
#include <folly/gen/Base.h>
#include <folly/gen/String.h>

#include <gflags/gflags.h>
#include <glog/logging.h>

static bool
ValidateClientPrefix(const char *flagname, const std::string& pfx) {
  const auto cidrnetExpect = folly::IPAddress::tryCreateNetwork(pfx);
  if(cidrnetExpect.hasError()) {
    LOG(ERROR) << folly::format("{} is not a prefix", flagname);
    return false;
  }
  return true;
}

DEFINE_string(
    export_file_path,
    "",
    "Path of file to export events to [stdout].");
DEFINE_string(client_prefix, "10.0.0.0/9", "Prefix of monitored clients");
DEFINE_validator(client_prefix, &ValidateClientPrefix);

using namespace paths::acktrace;

using folly::gen::as;
using folly::gen::eachTo;
using folly::gen::filter;
using folly::gen::fromConst;
using folly::gen::map;
using folly::gen::order;
using folly::gen::split;
using folly::gen::unsplit;

folly::SocketAddress toSocketAddress(const struct sockaddr_storage* sas) {
  folly::SocketAddress socketAddress;
  socketAddress.setFromSockaddr((struct sockaddr*)sas);
  socketAddress.tryConvertToIPv4();
  return socketAddress;
}

void writeToOutput(folly::Optional<folly::File>& outputFileOpt, const std::string& line) {
  if (outputFileOpt.hasValue()) {
    const auto& outputFile = outputFileOpt.value();
    CHECK_EQ(
        line.size(),
        folly::writeFull(outputFile.fd(), line.data(), line.size())
    );
    CHECK_EQ(1, folly::writeFull(outputFile.fd(), "\n", 1));
  } else {
      std::cout << line << std::endl;
  }
}

class BaseCsvExporter : public AckTraceCollector::CallbackHandler {
public:
  BaseCsvExporter(folly::Optional<folly::File>&& output_file_, std::string monitored_prefix);
  void handleEvent(const struct bpf::ack_event& event);
private:
  folly::Optional<folly::File> output_file_;
  std::string monitored_prefix_;
};

BaseCsvExporter::BaseCsvExporter(
    folly::Optional<folly::File>&& output_file,
    std::string monitored_prefix)
  : output_file_(std::move(output_file)), monitored_prefix_(monitored_prefix) {
  LOG(INFO) << folly::format("Monitoring events to clients in prefix {}", monitored_prefix_);
  std::vector<std::string> row;

  // header
  row.push_back("ev_tstamp_ns");
  row.push_back("conn_tstamp_ns");
  row.push_back("src");
  row.push_back("dst");

  // ackevent
  row.push_back("first_lost_packet_by_stats");
  row.push_back("first_lost_packet_by_seqnum");

  row.push_back("segments_lost");
  row.push_back("non_spurious_retrans");
  row.push_back("dsack_recovered");
  row.push_back("timestamp_recovered");
  row.push_back("dsack_and_timestamp_recovered");
  row.push_back("dsack_or_timestamp_recovered");
  row.push_back("fake_dsack_recovery_induced_by_lost_tlp");

  // tcp info
  row.push_back("delivered");
  row.push_back("lost");
  row.push_back("total_retrans");
  row.push_back("srtt_us");
  row.push_back("mdev_us");
  row.push_back("min_rtt_us");
  row.push_back("snd_cwnd");
  row.push_back("mss_cache");
  row.push_back("rto");

  // ackevent stats
  row.push_back("calls");
  row.push_back("calls_with_mstamp_zero");
  row.push_back("tcpcb_sacked_retrans");
  row.push_back("tcpcb_retrans");
  row.push_back("spurious_tlp_retrans");
  row.push_back("fully_acked_after_snd_una");

#ifdef EVDEBUG
  row.push_back("established_snd_una");
  row.push_back("seq");
  row.push_back("end_seq");

  row.push_back("event_source");
  row.push_back("pcount");
  row.push_back("tcp_gso_size");
  row.push_back("sacked_out");
  row.push_back("tcp_snd_una");
  row.push_back("fully_acked");
  row.push_back("tx_delivered");
  row.push_back("tx_first_tx_mstamp");
  row.push_back("tx_delivered_mstamp");
  row.push_back("tlp_high_seq");
  row.push_back("sacked");
  row.push_back("tcp_flags");
#endif

  writeToOutput(output_file_, folly::join(",", row));
}

void BaseCsvExporter::handleEvent(const struct bpf::ack_event& ev) {
  folly::SocketAddress dst = toSocketAddress(&ev.header.dst);
  if(!dst.getIPAddress().inSubnet(monitored_prefix_)) {
    return;
  }
  std::vector<std::string> row;

  // header
  row.push_back(std::to_string(ev.header.ev_tstamp_ns));
  row.push_back(std::to_string(ev.header.conn_tstamp_ns));
  row.push_back(toSocketAddress(&ev.header.src).describe());
  row.push_back(dst.describe());

  // ackevent
  row.push_back(std::to_string(ev.fstloss.by_stats));
  row.push_back(std::to_string(ev.fstloss.by_seqnum));

  row.push_back(std::to_string(ev.segments_lost));
  row.push_back(std::to_string(ev.non_spurious_retrans));
  row.push_back(std::to_string(ev.dsack_recovered));
  row.push_back(std::to_string(ev.timestamp_recovered));
  row.push_back(std::to_string(ev.dsack_and_timestamp_recovered));
  row.push_back(std::to_string(ev.dsack_or_timestamp_recovered));
  row.push_back(std::to_string(ev.fake_dsack_recovery_induced_by_lost_tlp));

  // tcp info
  row.push_back(std::to_string(ev.tcp.delivered));
  row.push_back(std::to_string(ev.tcp.lost));
  row.push_back(std::to_string(ev.tcp.total_retrans));
  row.push_back(std::to_string(ev.tcp.srtt_us));
  row.push_back(std::to_string(ev.tcp.mdev_us));
  row.push_back(std::to_string(ev.tcp.min_rtt_us));
  row.push_back(std::to_string(ev.tcp.snd_cwnd));
  row.push_back(std::to_string(ev.tcp.mss_cache));
  row.push_back(std::to_string(ev.tcp.rto));

  // ackevent stats
  row.push_back(std::to_string(ev.stats.calls));
  row.push_back(std::to_string(ev.stats.calls_with_mstamp_zero));
  row.push_back(std::to_string(ev.stats.tcpcb_sacked_retrans));
  row.push_back(std::to_string(ev.stats.tcpcb_retrans));
  row.push_back(std::to_string(ev.stats.spurious_tlp_retrans));
  row.push_back(std::to_string(ev.stats.fully_acked_after_snd_una));

#ifdef EVDEBUG
  row.push_back(std::to_string(ev.established_snd_una));
  row.push_back(std::to_string(ev.seq));
  row.push_back(std::to_string(ev.end_seq));

  if (ev.debug.event_source == EV_SOURCE_UNSET) {
    row.push_back("ev_source_unset");
  } else if(ev.debug.event_source == EV_SOURCE_TCP_CLOSE) {
    row.push_back("ev_source_tcp_close");
  } else if(ev.debug.event_source == EV_SOURCE_SKB_ACKED) {
    row.push_back("ev_source_skb_acked");
  } else {
    row.push_back("ev_source_unknown");
  }
  row.push_back(std::to_string(ev.debug.pcount));
  row.push_back(std::to_string(ev.debug.tcp_gso_size));
  row.push_back(std::to_string(ev.debug.sacked_out));
  row.push_back(std::to_string(ev.debug.tcp_snd_una));
  row.push_back(std::to_string(ev.debug.fully_acked));
  row.push_back(std::to_string(ev.debug.tx_delivered));
  row.push_back(std::to_string(ev.debug.tx_first_tx_mstamp));
  row.push_back(std::to_string(ev.debug.tx_delivered_mstamp));
  row.push_back(std::to_string(ev.debug.tlp_high_seq));
  row.push_back(std::to_string(ev.debug.sacked));
  row.push_back(std::to_string(ev.debug.tcp_flags));
#endif

  writeToOutput(output_file_, folly::join(",", row));
}

int main(int argc, char* argv[]) {
  paths::init(argc, argv);

  // setup export file, if declared
  folly::Optional<folly::File> exportFile;
  if (FLAGS_export_file_path.size()) {
    const auto path = FLAGS_export_file_path;
    auto fileExpect = folly::File::makeFile(path, O_WRONLY | O_TRUNC | O_CREAT);
    if (fileExpect.hasError()) {
      LOG(FATAL) << folly::sformat(
          "Unable to open file {} for export, error = {}",
          path,
          folly::exceptionStr(fileExpect.error()));
    } else {
      LOG(ERROR) << folly::sformat("Opened file {} for export", path);
      exportFile = std::move(fileExpect.value());
    }
  }

  const std::shared_ptr<BaseCsvExporter> handler =
      std::make_shared<BaseCsvExporter>(std::move(exportFile), FLAGS_client_prefix);
  AckTraceCollector collector(handler);

  // setup shutdown handler
  const auto stopServices = [&]() { collector.stop(); };
  folly::EventBase eventBase;
  paths::common::ShutdownSignalHandler signalHandler(&eventBase, stopServices);

  // run the collector, wait for termination signal
  std::thread threadObj([&] {
    eventBase.waitUntilRunning();
    collector.run();
    LOG(INFO) << "AckTraceCollector::run() returned, shutting down";
    eventBase.terminateLoopSoon();
  });
  eventBase.loopForever();
  threadObj.join();

  LOG(INFO) << "Done";
  return 0;
}
