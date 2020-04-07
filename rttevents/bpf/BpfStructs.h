#pragma once

#ifdef __cplusplus
/* include sys/socket.h for struct sockaddr_storage; it seems BCC
 * provides this automagically */
#include <sys/socket.h>

namespace paths {
namespace rttevents {
namespace bpf {
#endif

struct event_hdr {
	uint64_t ev_tstamp_ns;
	uint64_t conn_tstamp_ns;
	struct sockaddr_storage src;
	struct sockaddr_storage dst;
};

struct rtt_event {
	struct event_hdr header;
	uint64_t rtt_us;
	uint32_t bytes_acked;
	uint32_t packets_out;
	uint32_t snd_nxt;
};

#ifdef __cplusplus
} // namespace bpf
} // namespace rttevents
} // namespace paths
#endif
