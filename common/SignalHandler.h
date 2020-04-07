#pragma once

#include <folly/io/async/AsyncSignalHandler.h>
#include <signal.h>

namespace paths {
namespace common {

class ShutdownSignalHandler : public folly::AsyncSignalHandler {
 public:
  ShutdownSignalHandler(
      folly::EventBase* eventBase,
      const std::function<void()> stopFunc,
      const std::vector<int>& signals = {SIGINT, SIGTERM});

 private:
  void signalReceived(int signum) noexcept override;
  const std::function<void()> stopFunc_;
};

} // namespace common
} // namespace paths
