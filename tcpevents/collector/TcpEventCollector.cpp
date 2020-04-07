#include "TcpEventCollector.h"

#include <folly/FileUtil.h>
#include <folly/Format.h>
#include <gflags/gflags.h>
#include <glog/logging.h>
#include <experimental/filesystem>
#include <iostream>
#include <vector>

namespace fs = std::experimental::filesystem;

static bool
ValidatePath(const char* flagname, const std::string& flagPath) {
  if (flagPath.empty()) {
    LOG(INFO) << folly::format("Flag --{} must be set", flagname);
    return false;
  }

  // check that the path exists
  fs::path path(flagPath);
  if (not fs::exists(path)) {
    LOG(INFO) << folly::format(
        "Path set by --{} ({}) does not exist", flagname, flagPath);
    return false;
  }

  return true;
}

static bool
ValidateFilePath(const char* flagname, const std::string& flagPath) {
  if (flagPath.empty()) {
    LOG(INFO) << folly::format("Flag --{} must be set", flagname);
    return false;
  }

  // check that the path exists
  fs::path path(flagPath);
  if (not fs::exists(path)) {
    LOG(INFO) << folly::format(
        "Path set by --{} ({}) does not exist", flagname, flagPath);
    return false;
  }

  // if it's a real file, it should have a size
  try {
    fs::file_size(flagPath);
  } catch (fs::filesystem_error& e) {
    LOG(INFO) << folly::format(
        "Path set by --{} ({}) is not valid: {}", flagname, flagPath, e.what());
    return false;
  }

  return true;
}

static bool
ValidateSamplingRate(const char* flagname, double sampling_rate) {
  if (sampling_rate <= 0 || sampling_rate > 1) {
    LOG(ERROR) << folly::format("0 < sampling_rate <= 1 required");
    return false;
  }
  return true;
}

DEFINE_string(
    path_bpf_include_headers,
    "",
    "Header path or file to be included when the BPF program is built");
DEFINE_string(path_bpf_source, "", "Path to the BPF .c source file");
DEFINE_string(
    kbuild_modname,
    "tcpevents",
    "Value to use for KBUILD_MODNAME during compilation");
DEFINE_double(
    bpf_connection_sampling_rate,
    1.0,
    "BPF connection sampling rate (will be rounded to multiples of 1/65535)");
DEFINE_validator(path_bpf_include_headers, &ValidatePath);
DEFINE_validator(path_bpf_source, &ValidateFilePath);
DEFINE_validator(bpf_connection_sampling_rate, &ValidateSamplingRate);

namespace {

void
handleRawPerfEvent(void* cb_cookie, void* data, int data_size) {
  paths::tcpevents::TcpEventCollector* collector =
      static_cast<paths::tcpevents::TcpEventCollector*>(cb_cookie);
  collector->handlePerfEvent(data, data_size);
}

void
handleRawLostPerfEvents(void* cb_cookie, uint64_t lost) {
  paths::tcpevents::TcpEventCollector* collector =
      static_cast<paths::tcpevents::TcpEventCollector*>(cb_cookie);
  collector->handleLostPerfEvents(lost);
}

} // namespace

namespace paths {
namespace tcpevents {

TcpEventCollector::TcpEventCollector(
    const std::unordered_set<TcpEvent::Type>& enabledEvents,
    const std::shared_ptr<CallbackHandler>& cbHandler)
    : enabledEvents_(enabledEvents), cbHandler_(cbHandler), running_(false),
      events_cnt_(0), lost_events_cnt_(0) {}

bool
TcpEventCollector::run() {
  running_ = true;
  LOG(INFO) << "TcpEventCollector starting";

  fs::path pathToBpfHeaders(FLAGS_path_bpf_include_headers);
  fs::path pathToBpfSource(FLAGS_path_bpf_source);
  LOG(INFO) << folly::format(
      "Path to BPF headers = {}", fs::absolute(pathToBpfHeaders).c_str());
  LOG(INFO) << folly::format(
      "Path to BPF source = {}", fs::absolute(pathToBpfSource).c_str());
  LOG(INFO) << folly::format(
      "Size of BPF source file = {} bytes", fs::file_size(pathToBpfSource));

  std::vector<std::string> cflags = {};
  cflags.emplace_back(
      folly::sformat("-I{}", fs::absolute(pathToBpfHeaders).c_str()));
  cflags.emplace_back(
      folly::sformat("-DKBUILD_MODNAME=\"{}\"", FLAGS_kbuild_modname));

  if (FLAGS_bpf_connection_sampling_rate < 1.0) {
    unsigned random_max = static_cast<unsigned>(UINT16_MAX * FLAGS_bpf_connection_sampling_rate);
    assert(random_max <= UINT16_MAX);
    if (random_max == 0) {
      LOG(WARNING) << folly::format("sampling_rate too low, setting to 1/{}", UINT16_MAX);
      random_max = 1;
    }
    cflags.emplace_back(
      folly::sformat("-DRANDOM_SAMPLE_MAX={}", random_max)
    );
  }

  std::string fileContents;
  if (not folly::readFile(
          fs::absolute(pathToBpfSource).c_str(), fileContents)) {
    LOG(ERROR) << folly::format(
        "Could not read BPF source from {}",
        pathToBpfSource.filename().c_str());
    running_.store(false);
    return false;
  }
  LOG(INFO) << folly::format(
      "Read BPF source from {}", pathToBpfSource.filename().c_str());

  // load the BPF program
  {
    LOG(INFO) << folly::format(
        "Compiling and loading {} with flags {}",
        pathToBpfSource.filename().c_str(),
        folly::join(", ", cflags));
    const auto bpfSourceFilename = pathToBpfSource.filename().c_str();
    auto r = ebpf_.init(fileContents, cflags);
    if (r.code() != 0) {
      LOG(ERROR) << folly::format(
          "Error loading BPF program {}: {}", bpfSourceFilename, r.msg());
      running_.store(false);
      return false;
    }
    LOG(INFO) << folly::format("Loaded BPF program {}", bpfSourceFilename);
  }

  // setup tracepoint for tcp:tcp_destroy_sock
  // we always set up this tracepoint to support other events
  {
    const std::string tracepoint = "tcp:tcp_destroy_sock";
    const std::string fn = "on_tcp_destroy_sock";
    auto r = ebpf_.attach_tracepoint(tracepoint, fn);
    if (r.code() != 0) {
      LOG(ERROR) << folly::format(
          "Error attaching BPF function {} to tracepoint {}: {}",
          fn,
          tracepoint,
          r.msg());
      running_.store(false);
      return false;
    }
    LOG(INFO) << folly::format(
        "Attached BPF function {} to tracepoint {}", fn, tracepoint);
  }

  // setup tracepoint for sock:inet_sock_set_state
  // we always set up this tracepoint to support other events
  //
  // TODO(bschlinker): Add support for disabling inet_sock_set_state EVENTS
  // (likely via compile flag)
  {
    const std::string tracepoint = "sock:inet_sock_set_state";
    const std::string fn = "on_inet_sock_set_state";
    auto r = ebpf_.attach_tracepoint(tracepoint, fn);
    if (r.code() != 0) {
      LOG(ERROR) << folly::format(
          "Error attaching BPF function {} to tracepoint {}: {}",
          fn,
          tracepoint,
          r.msg());
      running_.store(false);
      return false;
    }
    LOG(INFO) << folly::format(
        "Attached BPF function {} to tracepoint {}", fn, tracepoint);
  }

  // setup kprobe for tcp_set_ca_state (via bictcp_state)
  if (enabledEvents_.count(TcpEvent::Type::TCP_SET_CA_STATE)) {
    for (const auto& kprobe : {"bictcp_state", "bbr_set_state"}) {
      const std::string fn = "on_tcp_set_ca_state";
      auto r = ebpf_.attach_kprobe(kprobe, fn, 0, BPF_PROBE_ENTRY);
      if (r.code() != 0) {
        LOG(ERROR) << folly::format(
            "Error attaching BPF function {} to kprobe {}: {}",
            fn,
            kprobe,
            r.msg());
      } else {
        LOG(INFO) << folly::format(
            "Attached BPF function {} to kprobe {}", fn, kprobe);
      }
    }
  }


  // open the perf buffer
  const auto perfBuffName = "events";
  {
    auto r = ebpf_.open_perf_buffer(
        perfBuffName,
        &handleRawPerfEvent,
        &handleRawLostPerfEvents,
        (void*)this,
        8);
    if (r.code() != 0) {
      LOG(ERROR) << folly::format(
          "Error opening perf buffer {}: {}", perfBuffName, r.msg());
      running_.store(false);
      return false;
    }
  }

  // poll events from the perf buffer
  LOG(INFO) << folly::format(
      "Waiting for TcpEvents from perf buffer {}", perfBuffName);
  while (running_.load()) {
    ebpf_.poll_perf_buffer(perfBuffName, 1000);
  }
  LOG(INFO) << "Exited perf buffer poll loop";
  LOG(INFO) << folly::format("TcpEvents {} total ({} lost)", events_cnt_, lost_events_cnt_);
  return true;
}

void
TcpEventCollector::stop() {
  LOG(INFO) << "TcpEventCollector stopping";
  running_ = false;
}

bool
TcpEventCollector::isRunning() const {
  return running_.load();
}

void
TcpEventCollector::handlePerfEvent(const void* data, const int data_size) {
  // TODO(bschlinker): Sanity check that data_size == sizeof(tcp_event_t)
  events_cnt_++;
  const bpf::tcp_event_t* rawEvent = static_cast<const bpf::tcp_event_t*>(data);
  auto e = std::make_unique<TcpEvent>(*rawEvent);
  cbHandler_->handleTcpEvent(std::move(e));
}

void
TcpEventCollector::handleLostPerfEvents(const uint64_t lost) {
  LOG(WARNING) << folly::format("Lost {} events", lost);
  lost_events_cnt_ += lost;
}

} // namespace tcpevents
} // namespace paths
