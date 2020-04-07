#include "SignalHandler.h"

#include <folly/Format.h>
#include <gflags/gflags.h>
#include <glog/logging.h>

#include <folly/io/async/EventBaseManager.h>

using folly::AsyncSignalHandler;
using folly::EventBaseManager;

namespace paths {
namespace common {

ShutdownSignalHandler::ShutdownSignalHandler(
    folly::EventBase* eventBase,
    const std::function<void()> stopFunc,
    const std::vector<int>& signals)
    : AsyncSignalHandler(eventBase), stopFunc_(stopFunc) {
  for (const int& signal : signals) {
    registerSignalHandler(signal);
  }
  LOG(INFO) << "ShutdownSignalHandler initialized";
}

void
ShutdownSignalHandler::signalReceived(int signum) noexcept {
  LOG(INFO)
      << folly::sformat("Received signal {}, running stop function", signum);
  stopFunc_();
}

} // namespace common
} // namespace paths
