#include <src/common/Init.h>
#include <src/common/SignalHandler.h>
#include <src/tcpevents/collector/TcpEventCollector.h>
#include <src/tcpevents/testclient/BaseTcpEventHandler.h>
#include <thread>
#include <vector>

#include <folly/File.h>
#include <folly/Format.h>
#include <folly/gen/Base.h>
#include <folly/gen/String.h>

static bool
ValidateClientPrefix(const char *flagname, const std::string& pfx) {
  const auto cidrnetExpect = folly::IPAddress::tryCreateNetwork(pfx);
  if(cidrnetExpect.hasError()) {
    LOG(ERROR) << folly::format("{} is not a prefix", flagname);
    return false;
  }
  return true;
}

DEFINE_string(export_mode, "txt", "Export mode (options: csv, json, txt)");
DEFINE_string(
    export_file_path,
    "",
    "Path of file to export events to. "
    "If not set, events are exported to stdout");
DEFINE_string(
    stats_to_print,
    "all",
    "List of stats to print for each event, defined as a comma separated list. "
    "Set to 'all' (default) to print all stats");
DEFINE_string(client_prefix, "10.0.0.0/9", "Prefix of monitored clients");
DEFINE_validator(client_prefix, &ValidateClientPrefix);

using namespace paths::tcpevents;

using folly::gen::as;
using folly::gen::eachTo;
using folly::gen::filter;
using folly::gen::fromConst;
using folly::gen::map;
using folly::gen::order;
using folly::gen::split;
using folly::gen::unsplit;

int
main(int argc, char* argv[]) {
  paths::init(argc, argv);

  folly::Optional<std::unordered_set<std::string>> statsToPrintOpt;
  if (FLAGS_stats_to_print != "all") {
    statsToPrintOpt = split(FLAGS_stats_to_print, ',') |
        map([](const auto& str) { return trimWhitespace(str); }) |
        eachTo<std::string>() |
        filter([](const auto& str) { return str.size(); }) | order |
        as<std::unordered_set<std::string>>();
    LOG(INFO) << folly::sformat(
        "Printing ONLY stats passed via --stats_to_print: ({})",
        fromConst(statsToPrintOpt.value()) | unsplit(','));
  } else {
    LOG(INFO) << "All stats will be printed (use --stats_to_print to filter)";
  }

  // TODO(bschlinker): Make it possible to set enabled events from command line
  // const std::unordered_set<TcpEvent::Type> enabledEvents(
  //     {TcpEvent::Type::INET_SOCK_SET_STATE, TcpEvent::Type::TCP_SET_CA_STATE});

  const std::unordered_set<TcpEvent::Type> enabledEvents(
      {TcpEvent::Type::INET_SOCK_SET_STATE, TcpEvent::Type::TCP_SET_CA_STATE});


  // determine the export mode
  // TODO(bschlinker): Use fatal rich enum to map command line to enum
  TcpEventExporterType exportMode;
  if (FLAGS_export_mode == "csv") {
    exportMode = TcpEventExporterType::CSV;
  } else if (FLAGS_export_mode == "json") {
    exportMode = TcpEventExporterType::JSON;
  } else if (FLAGS_export_mode == "txt") {
    exportMode = TcpEventExporterType::TXT;
  } else {
    LOG(ERROR) << folly::sformat(
        "Export format {} not known, defaulting to txt", FLAGS_export_mode);
    exportMode = TcpEventExporterType::TXT;
  }

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

  // init the handler
  const auto exporter = TcpEventExporter::createExporter(
      exportMode, std::move(exportFile), statsToPrintOpt);
  const auto handler = std::make_shared<BaseTcpEventHandler>(exporter, FLAGS_client_prefix);
  TcpEventCollector collector(enabledEvents, handler);

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
