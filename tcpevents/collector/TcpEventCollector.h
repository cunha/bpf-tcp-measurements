#pragma once

#include <bcc/BPF.h>
#include <src/tcpevents/collector/TcpEvent.h>
#include <atomic>
#include <memory>

namespace paths {
namespace tcpevents {

class TcpEventCollector {
 public:
  class CallbackHandler {
   public:
    virtual void handleTcpEvent(std::unique_ptr<TcpEvent> event) = 0;
  };

  TcpEventCollector(
      const std::unordered_set<TcpEvent::Type>& enabledEvents,
      const std::shared_ptr<CallbackHandler>& cbHandler);

  bool run();

  void stop();

  bool isRunning() const;

  void handlePerfEvent(const void* data, const int data_size);

  void handleLostPerfEvents(const uint64_t lost);

 private:
  const std::unordered_set<TcpEvent::Type> enabledEvents_;
  const std::shared_ptr<CallbackHandler> cbHandler_;
  std::atomic<bool> running_;
  ebpf::BPF ebpf_;
  uint64_t events_cnt_;
  uint64_t lost_events_cnt_;
};

} // namespace tcpevents
} // namespace paths
