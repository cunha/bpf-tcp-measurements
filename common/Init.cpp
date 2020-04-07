#include "Init.h"

#include <gflags/gflags.h>
#include <glog/logging.h>

namespace paths {

void
init(int argc, char* argv[]) {
  FLAGS_logtostderr = true;
  gflags::ParseCommandLineFlags(&argc, &argv, true);
  google::InitGoogleLogging(argv[0]);
  LOG(INFO) << "Common initialization completed";
}

} // namespace paths
