#pragma once

#include <gflags/gflags.h>
#include <glog/logging.h>

#include <fatal/type/enum.h>
#include <folly/File.h>
#include <src/tcpevents/collector/TcpEvent.h>

namespace paths {
namespace tcpevents {

FATAL_RICH_ENUM_CLASS(TcpEventExporterType, CSV, JSON, TXT);

/**
 * Base class for all TcpEvent exporters.
 */
class TcpEventExporter {
 public:
  TcpEventExporter(
      folly::Optional<folly::File>&& outputFileOpt = folly::none,
      const folly::Optional<std::unordered_set<std::string>>&
          statFieldsToExportOpt = folly::none);

  TcpEventExporter(
      const folly::Optional<std::unordered_set<std::string>>&
          statFieldsToExportOpt = folly::none);

  /**
   * Creates an TcpEvent exporter of the specified type that exports to a file.
   */
  static std::shared_ptr<TcpEventExporter> createExporter(
      const TcpEventExporterType& type,
      folly::Optional<folly::File>&& outputFileOpt = folly::none,
      const folly::Optional<std::unordered_set<std::string>>&
          statFieldsToExportOpt = folly::none);

  /**
   * Creates an TcpEvent exporter of the specified type that exports to stdout.
   */
  static std::shared_ptr<TcpEventExporter> createExporter(
      const TcpEventExporterType& type,
      const folly::Optional<std::unordered_set<std::string>>&
          statFieldsToExportOpt = folly::none);

  /**
   * Converts the event to CSV and then writes to the configured output.
   */
  virtual void write(const TcpEvent& event) const = 0;

  /**
   * Returns a list of stat fields to export.
   *
   * Prints warning message if a stat field in the input set is invalid /
   * unavailable. If no input is provided, returns all registered stat fields.
   */
  static std::vector<std::string> getStatFieldsToExport(
      const folly::Optional<std::unordered_set<std::string>>&
          statFieldsToExportOpt);

  /**
   * Generates ordered list of column names for export.
   */
  static std::vector<std::string> getFieldNamesToExport(
      const std::vector<std::string>& statFieldsToExport);

 protected:
  /**
   * Writes a line to the configured output.
   */
  void writeToOutput(const std::string& line) const;

  // Statistics fields to export (post-filtering)
  const std::vector<std::string> statFieldsToExport_;

  // Ordered list of fields to export
  const std::vector<std::string> fieldsToExport_;

  // File to export to (if not set, export to stdout)
  const folly::Optional<folly::File> outputFileOpt_;
};

} // namespace tcpevents
} // namespace paths
