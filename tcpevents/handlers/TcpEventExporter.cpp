#include "TcpEventExporter.h"

#include <folly/FileUtil.h>
#include <folly/Format.h>
#include <folly/gen/Base.h>
#include <src/tcpevents/handlers/TcpEventCsvExporter.h>
#include <src/tcpevents/handlers/TcpEventJsonExporter.h>
#include <src/tcpevents/handlers/TcpEventTxtExporter.h>
#include <iostream>

namespace paths {
namespace tcpevents {

using folly::gen::as;
using folly::gen::fromConst;

TcpEventExporter::TcpEventExporter(
    folly::Optional<folly::File>&& outputFileOpt,
    const folly::Optional<std::unordered_set<std::string>>&
        statFieldsToExportOpt)
    : statFieldsToExport_(getStatFieldsToExport(statFieldsToExportOpt)),
      fieldsToExport_(getFieldNamesToExport(statFieldsToExport_)),
      outputFileOpt_(std::move(outputFileOpt)) {}

TcpEventExporter::TcpEventExporter(
    const folly::Optional<std::unordered_set<std::string>>&
        statFieldsToExportOpt)
    : TcpEventExporter(folly::none, statFieldsToExportOpt) {}

std::shared_ptr<TcpEventExporter>
TcpEventExporter::createExporter(
    const TcpEventExporterType& type,
    folly::Optional<folly::File>&& outputFileOpt,
    const folly::Optional<std::unordered_set<std::string>>&
        statFieldsToExportOpt) {
  switch (type) {
  case TcpEventExporterType::CSV: {
    return std::make_shared<TcpEventCsvExporter>(
        std::move(outputFileOpt), statFieldsToExportOpt);
  }
  case TcpEventExporterType::JSON: {
    return std::make_shared<TcpEventJsonExporter>(
        std::move(outputFileOpt), statFieldsToExportOpt);
  }
  case TcpEventExporterType::TXT: {
    return std::make_shared<TcpEventTxtExporter>(
        std::move(outputFileOpt), statFieldsToExportOpt);
  }
  default:
    LOG(FATAL) << folly::sformat(
        "Unsupported TcpEventExporterType {}",
        fatal::enum_to_string(type, "UNKNOWN"));
    return nullptr;
  };
}

std::shared_ptr<TcpEventExporter>
TcpEventExporter::createExporter(
    const TcpEventExporterType& type,
    const folly::Optional<std::unordered_set<std::string>>&
        statFieldsToExportOpt) {
  return createExporter(type, folly::none, statFieldsToExportOpt);
}

std::vector<std::string>
TcpEventExporter::getStatFieldsToExport(
    const folly::Optional<std::unordered_set<std::string>>&
        statFieldsToExportOpt) {
  // convert to a set to get them ordered and to allow quick checks of validity
  const auto statFieldNames =
      fromConst(TcpEvent::getStatFieldNames()) | as<std::set<std::string>>();

  // if the user provided a list of stat field names, check if they're valid
  if (statFieldsToExportOpt.hasValue()) {
    const auto& statFieldsToExport = statFieldsToExportOpt.value();

    std::vector<std::string> statFieldsToExportFiltered;
    for (const auto& statName : statFieldsToExport) {
      if (not statFieldNames.count(statName)) {
        LOG(WARNING) << folly::sformat(
            "Cannot export stat field {}, "
            "field does not exist according to TcpEvent::getStatFieldNames, "
            "ignoring field",
            statName);
      } else {
        statFieldsToExportFiltered.push_back(statName);
      }
    }
    return statFieldsToExportFiltered;
  }

  // no stat names provided, just export everything
  return std::vector(statFieldNames.begin(), statFieldNames.end());
}

std::vector<std::string>
TcpEventExporter::getFieldNamesToExport(
    const std::vector<std::string>& statFieldsToExport) {
  const auto headerFields = TcpEvent::getHeaderFieldNames();
  const auto stateFields = TcpEvent::getStateFieldNames();
  const auto detailFields = TcpEvent::getDetailFieldNames();
  const uint32_t numFields = headerFields.size() + stateFields.size() +
      detailFields.size() + statFieldsToExport.size();

  std::vector<std::string> fieldNames;
  fieldNames.reserve(numFields);
  fieldNames.insert(fieldNames.end(), headerFields.begin(), headerFields.end());
  fieldNames.insert(fieldNames.end(), stateFields.begin(), stateFields.end());
  fieldNames.insert(fieldNames.end(), detailFields.begin(), detailFields.end());
  fieldNames.insert(
      fieldNames.end(), statFieldsToExport.begin(), statFieldsToExport.end());

  CHECK_EQ(numFields, fieldNames.size());
  return fieldNames;
}

void
TcpEventExporter::writeToOutput(const std::string& line) const {
  if (outputFileOpt_.hasValue()) {
    const auto& outputFile = outputFileOpt_.value();
    CHECK_EQ(
        line.size(),
        folly::writeFull(outputFile.fd(), line.data(), line.size()));
    CHECK_EQ(1, folly::writeFull(outputFile.fd(), "\n", 1));
  } else {
    std::cout << line << std::endl;
  }
}

} // namespace tcpevents
} // namespace paths
