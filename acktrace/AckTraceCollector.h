#pragma once

#include <bcc/BPF.h>
#include <atomic>
#include <memory>

#include <src/acktrace/bpf/BpfStructs.h>

namespace paths {
namespace acktrace {

class AckTraceCollector {
 public:
  class CallbackHandler {
   public:
    virtual void handleEvent(const struct bpf::ack_event& event) = 0;
  };

  AckTraceCollector(const std::shared_ptr<CallbackHandler>& cbHandler);

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

} // namespace acktrace
} // namespace paths
