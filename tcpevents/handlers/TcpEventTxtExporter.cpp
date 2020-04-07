#include "TcpEventTxtExporter.h"

namespace paths {
namespace tcpevents {

void
TcpEventTxtExporter::write(const TcpEvent& event) const {
  // dump the event via toString()
  writeToOutput(event.toString(std::unordered_set<std::string>(
      statFieldsToExport_.begin(), statFieldsToExport_.end())));
}

} // namespace tcpevents
} // namespace paths
