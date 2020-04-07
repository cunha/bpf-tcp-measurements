#include "TcpEventCsvExporter.h"

#include <folly/MapUtil.h>
#include <folly/String.h>

namespace paths {
namespace tcpevents {

TcpEventCsvExporter::TcpEventCsvExporter(
    folly::Optional<folly::File>&& outputFileOpt,
    const folly::Optional<std::unordered_set<std::string>>&
        statFieldsToExportOpt)
    : TcpEventExporter(std::move(outputFileOpt), statFieldsToExportOpt) {
  // write our column names
  writeToOutput(folly::join(",", fieldsToExport_));
}

TcpEventCsvExporter::TcpEventCsvExporter(
    const folly::Optional<std::unordered_set<std::string>>&
        statFieldsToExportOpt)
    : TcpEventCsvExporter(folly::none, statFieldsToExportOpt) {}

void
TcpEventCsvExporter::write(const TcpEvent& event) const {
  std::vector<std::string> row;
  const auto fieldNamesToValues = event.getFieldMap();
  for (const auto& fieldName : fieldsToExport_) {
    const auto fieldPtr = folly::get_ptr(fieldNamesToValues, fieldName);
    if (fieldPtr) {
      row.push_back(*fieldPtr);
    } else {
      row.push_back("");
    }
  }

  // dump the row
  writeToOutput(folly::join(",", row));
}

} // namespace tcpevents
} // namespace paths
