#include "RttTraceCollector.h"

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
  if (sampling_rate < 0 || sampling_rate > 1) {
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
    "rtttrace",
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
  paths::rtttrace::RttTraceCollector* collector =
      static_cast<paths::rtttrace::RttTraceCollector*>(cb_cookie);
  collector->handlePerfEvent(data, data_size);
}

void
handleRawLostPerfEvents(void* cb_cookie, uint64_t lost) {
  paths::rtttrace::RttTraceCollector* collector =
      static_cast<paths::rtttrace::RttTraceCollector*>(cb_cookie);
  collector->handleLostPerfEvents(lost);
}

} // namespace

namespace paths {
namespace rtttrace {

RttTraceCollector::RttTraceCollector(const std::shared_ptr<CallbackHandler>& cbHandler)
    : cbHandler_(cbHandler), running_(false), events_(0), lost_events_(0) {}

bool
RttTraceCollector::run() {
  running_ = true;
  LOG(INFO) << "RttTraceCollector starting";

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
#ifdef EVDEBUG
  cflags.emplace_back("-DEVDEBUG");
#endif

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
    const auto bpfSourceFilename = pathToBpfSource.filename().c_str();
    LOG(INFO) << folly::format(
        "Compiling and loading {} with flags {}",
        bpfSourceFilename,
        folly::join(" ", cflags));
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

  {
    const std::string tracepoint = "tcp:tcp_skb_acked";
    const std::string fn = "on_tcp_skb_acked";
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

  const auto perfBuffName = "events";
  {
    auto r = ebpf_.open_perf_buffer(
        perfBuffName,
        &handleRawPerfEvent,
        &handleRawLostPerfEvents,
        (void*)this,
        64);
    if (r.code() != 0) {
      LOG(ERROR) << folly::format(
          "Error opening perf buffer {}: {}", perfBuffName, r.msg());
      running_.store(false);
      return false;
    }
  }

  // poll events from the perf buffer
  LOG(INFO) << folly::format(
      "Waiting for RttTrace events from perf buffer {}", perfBuffName);
  while (running_.load()) {
    ebpf_.poll_perf_buffer(perfBuffName, 1000);
  }
  LOG(INFO) << "Exited perf buffer poll loop";
  return true;
}

void
RttTraceCollector::stop() {
  LOG(INFO) << folly::format(
      "RttTraceCollector stopping: {} events ({} lost)",
      events_.load(),
      lost_events_.load());
  running_.store(false);
}

bool
RttTraceCollector::isRunning() const {
  return running_.load();
}

void
RttTraceCollector::handlePerfEvent(const void* data, const int data_size) {
  events_++;
  const struct bpf::rtt_event *ev = static_cast<const struct bpf::rtt_event *>(data);
  if ((unsigned)data_size < sizeof(*ev)) {
    /* use less-than instead of different-then to allow for different struct
     * packing algorithms in BCC and GCC */
    LOG(ERROR) << folly::format(
        "Received less data than required",
        data_size,
        sizeof(*ev));
  }
  cbHandler_->handleEvent(*ev);
}

void
RttTraceCollector::handleLostPerfEvents(const uint64_t lost) {
  lost_events_.fetch_add(lost);
  LOG(WARNING) << folly::format("Lost {} events", lost);
}

} // namespace rtttrace
} // namespace paths
