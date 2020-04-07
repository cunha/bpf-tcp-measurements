#include "TcpEventJsonExporter.h"

#include <nlohmann/json.hpp>

namespace paths {
namespace tcpevents {

void
TcpEventJsonExporter::write(const TcpEvent& event) const {
  writeToOutput(nlohmann::json(event.getFieldMap()).dump());
}

} // namespace tcpevents
} // namespace paths
