#pragma once

#define UINT8_MAX 0xFFU
#define UINT16_MAX 0xFFFFU
#define UINT32_MAX 0xFFFFFFFFU

#define TCP_CA_NAME_MAX 16
#define TCP_CA_NAME_UNSET 0
#define TCP_CA_NAME_CUBIC 1
#define TCP_CA_NAME_BBR 2
#define TCP_CA_NAME_UNKNOWN 0xFF

struct loss_track_state {
  u16 first_lost_packet;        // Assigned in lts_set_loss()
  u8 first_loss_reason;         // LTS_REASON_*, assigned in lts_set_loss()
  u8 error;                     // LTS_ERR_*, assigned in lts_set_error()
  u8 old_state;                 // Used to track missed CA transitions
  u8 done;
  struct {
    u32 snd_nxt;
    u32 snd_una;
    u32 prior_ssthresh;
    u16 first_lost_packet;      // (delivered - sacked_out)
  } enter;
  struct {
    u8 set_loss_count;
    u8 undo_count;
    u8 undone_undo_marker;
    u8 undone_mtu_probing;
    u8 undone_ssthresh_infinite;
    u8 transitions_loss_to_loss;  // Count of transitions Loss -> Loss
    u8 transitions_open_to_open;  // Count of transitions Open/Disorder -> O/D
    u8 transitions_recovery_to_loss;  // Count of transitions Recovery -> Loss
    u8 transitions_after_done;
    u8 recovery_to_loss_with_partial_acks;
  } stats;
};

struct connection_stats {
  u64 start_us;             // connection start time
  u32 minrtt_on_establish;  // minrtt observed on connection establishment
  u8 cc_algo;               // caching information from the tsk
  struct {
    u16 count;
    u16 tcp_ca_open_disorder;
    u16 tcp_ca_cwr;
    u16 tcp_ca_recovery;
    u16 tcp_ca_loss;
  } ca_state_changes;
  struct loss_track_state loss_track_state;
};
