#pragma once

#include <src/tcpevents/handlers/TcpEventExporter.h>

namespace paths {
namespace tcpevents {

/**
 * Exporter for dumping TcpEvents to a plain text file.
 */
class TcpEventTxtExporter : public TcpEventExporter {
 public:
  using TcpEventExporter::TcpEventExporter;

  /**
   * Converts the event to a string and then writes to the configured output.
   */
  void write(const TcpEvent& event) const override;
};

} // namespace tcpevents
} // namespace paths
