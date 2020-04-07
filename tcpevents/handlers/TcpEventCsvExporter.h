#pragma once

#include <src/tcpevents/handlers/TcpEventExporter.h>

namespace paths {
namespace tcpevents {

/**
 * Exporter for dumping TcpEvents to a CSV file.
 */
class TcpEventCsvExporter : public TcpEventExporter {
 public:
  TcpEventCsvExporter(
      folly::Optional<folly::File>&& outputFileOpt = folly::none,
      const folly::Optional<std::unordered_set<std::string>>&
          statFieldsToExportOpt = folly::none);

  TcpEventCsvExporter(
      const folly::Optional<std::unordered_set<std::string>>&
          statFieldsToExportOpt = folly::none);

  /**
   * Converts the event to CSV and then writes to the configured output.
   */
  void write(const TcpEvent& event) const override;
};

} // namespace tcpevents
} // namespace paths
