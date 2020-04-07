#pragma once

#include <bcc/BPF.h>
#include <atomic>
#include <memory>

#include <src/rttevents/bpf/BpfStructs.h>

namespace paths {
namespace rttevents {

class RttEventCollector {
 public:
  class CallbackHandler {
   public:
    virtual void handleEvent(const struct bpf::rtt_event& event) = 0;
  };

  RttEventCollector(const std::shared_ptr<CallbackHandler>& cbHandler);

  bool run();

  void stop();

  bool isRunning() const;

  void handlePerfEvent(const void* data, const int data_size);

  void handleLostPerfEvents(const uint64_t lost);

 private:
  const std::shared_ptr<CallbackHandler> cbHandler_;
  std::atomic<bool> running_;
  ebpf::BPF ebpf_;
  std::atomic<uint64_t> events_;
  std::atomic<uint64_t> lost_events_;
};

} // namespace rttevents
} // namespace paths
