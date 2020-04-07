#include "BaseTcpEventHandler.h"

#include <iostream>

#include <folly/Format.h>

namespace paths {
namespace tcpevents {

BaseTcpEventHandler::BaseTcpEventHandler(
    const std::shared_ptr<TcpEventExporter>& exporter,
    std::string monitored_prefix)
    : exporter_(exporter), monitored_prefix_(monitored_prefix) {
  LOG(INFO) << folly::format("Monitoring events to clients in prefix {}", monitored_prefix_);
}

void
BaseTcpEventHandler::handleTcpEvent(std::unique_ptr<TcpEvent> event) {
  if ((int)event->details.state_change.new_state.skt_state != TCP_CLOSE) {
    return;
  }
  if ((int)event->details.state_change.old_state.skt_state == TCP_CLOSE ||
      (int)event->details.state_change.old_state.skt_state == TCP_LISTEN) {
    return;
  }
  if(!event->dst.getIPAddress().inSubnet(monitored_prefix_)) {
    return;
  }
  exporter_->write(*event);
}

} // namespace tcpevents
} // namespace paths
