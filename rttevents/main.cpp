#include <src/common/Init.h>
#include <src/common/SignalHandler.h>
#include <src/rttevents/RttEventCollector.h>
#include <src/rttevents/bpf/BpfStructs.h>

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

using namespace paths::rttevents;

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

class BaseCsvExporter : public RttEventCollector::CallbackHandler {
public:
  BaseCsvExporter(folly::Optional<folly::File>&& output_file_, std::string monitored_prefix);
  void handleEvent(const struct bpf::rtt_event& event);
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
  row.push_back("ev_tstamp_ns");
  row.push_back("conn_tstamp_ns");
  row.push_back("src");
  row.push_back("dst");
  row.push_back("rtt_us");
  row.push_back("bytes_acked");
  row.push_back("packets_out");
  row.push_back("snd_nxt");
  writeToOutput(output_file_, folly::join(",", row));
}

void BaseCsvExporter::handleEvent(const struct bpf::rtt_event& ev) {
  folly::SocketAddress dst = toSocketAddress(&ev.header.dst);
  if(!dst.getIPAddress().inSubnet(monitored_prefix_)) {
    return;
  }
  std::vector<std::string> row;
  row.push_back(std::to_string(ev.header.ev_tstamp_ns));
  row.push_back(std::to_string(ev.header.conn_tstamp_ns));
  row.push_back(toSocketAddress(&ev.header.src).describe());
  row.push_back(dst.describe());
  row.push_back(std::to_string(ev.rtt_us));
  row.push_back(std::to_string(ev.bytes_acked));
  row.push_back(std::to_string(ev.packets_out));
  row.push_back(std::to_string(ev.snd_nxt));
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
  RttEventCollector collector(handler);

  // setup shutdown handler
  const auto stopServices = [&]() { collector.stop(); };
  folly::EventBase eventBase;
  paths::common::ShutdownSignalHandler signalHandler(&eventBase, stopServices);

  // run the collector, wait for termination signal
  std::thread threadObj([&] {
    eventBase.waitUntilRunning();
    collector.run();
    LOG(INFO) << "TcpEventCollector::run() returned, shutting down";
    eventBase.terminateLoopSoon();
  });
  eventBase.loopForever();
  threadObj.join();

  LOG(INFO) << "Done";
  return 0;
}
