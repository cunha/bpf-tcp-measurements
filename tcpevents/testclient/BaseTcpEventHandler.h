#pragma once

#include <folly/File.h>
#include <folly/Optional.h>
#include <src/tcpevents/collector/TcpEventCollector.h>
#include <src/tcpevents/handlers/TcpEventCsvExporter.h>

namespace paths {
namespace tcpevents {

class BaseTcpEventHandler : public TcpEventCollector::CallbackHandler {
 public:
  BaseTcpEventHandler(
    const std::shared_ptr<TcpEventExporter>& exporter,
    std::string monitored_prefix);

  void handleTcpEvent(std::unique_ptr<TcpEvent> event) override;

 private:
  const std::shared_ptr<TcpEventExporter> exporter_;
  const std::string monitored_prefix_;
};

} // namespace tcpevents
} // namespace paths
