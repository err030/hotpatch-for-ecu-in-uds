#ifndef UDS_DISPATCHER_H
#define UDS_DISPATCHER_H

#include <stdbool.h>
#include <stdint.h>

#include "uds_protocol.h"

#ifdef __cplusplus
extern "C" {
#endif

#define UDS_VALID_WRITE_DID 0x1234U
#define UDS_BENIGN_CONTROL_WRITE_DID 0x1235U
#define UDS_READ_ONLY_STATUS_DID 0x1001U
#define UDS_SEED_MASK 0xA55AU
#define UDS_SECURITY_LEVEL_CONFIG_WRITE 0x01U
#define UDS_SESSION_P2_SERVER_MAX_MS 50U
#define UDS_SESSION_P2_STAR_SERVER_MAX_MS 5000U
#define UDS_CONFIG_TABLE_MAX_ENTRIES 8U
#define UDS_CONFIG_VALUE_MAX_LENGTH 16U

typedef enum {
    UDS_SECURITY_PHASE_DEFAULT_SESSION = 0,
    UDS_SECURITY_PHASE_EXTENDED_SESSION,
    UDS_SECURITY_PHASE_SEED_ISSUED,
    UDS_SECURITY_PHASE_UNLOCKED,
    UDS_SECURITY_PHASE_LOCKED_OUT,
} uds_security_phase_t;

typedef struct {
    uint16_t did;
    bool readable;
    bool writable;
    bool requires_extended_session;
    bool requires_security_unlock;
    uint8_t required_security_level;
    uint8_t min_write_length;
    uint8_t max_write_length;
    uint8_t value_length;
    uint8_t value[UDS_CONFIG_VALUE_MAX_LENGTH];
} uds_config_entry_t;

typedef struct {
    uds_config_entry_t entries[UDS_CONFIG_TABLE_MAX_ENTRIES];
    uint8_t count;
} uds_config_table_t;

typedef struct {
    uint8_t session;
    bool security_unlocked;
    uint8_t security_level;
    bool pending_seed_valid;
    uint8_t pending_seed_level;
    uint16_t pending_seed;
    uint16_t seed_counter;
    uint8_t failed_attempts;
    uint8_t lockout_ticks_remaining;
    uint32_t periodic_task_tick;
    uint32_t session_generation;
    uint32_t unlock_generation;
} uds_session_state_t;

typedef struct {
    bool last_authorized_valid;
    uint16_t last_authorized_did;
    uint8_t last_authorized_length;
    uint8_t last_authorized_data[UDS_CONFIG_VALUE_MAX_LENGTH];
    uint32_t capture_session_generation;
    uint32_t capture_unlock_generation;
} uds_replay_guard_t;

typedef struct {
    bool write_requires_unlock;
    bool clear_unlock_on_failed_key;
    bool clear_unlock_on_session_change;
    bool allow_replay_without_unlock;
    bool quarantine_config_write_did;
    uint16_t quarantined_did;
    uint8_t max_failed_attempts;
    uint8_t lockout_duration_ticks;
} uds_dispatcher_policy_t;

typedef struct {
    uds_session_state_t session_state;
    uds_config_table_t config_table;
    uds_replay_guard_t replay_guard;
    uds_dispatcher_policy_t policy;
} uds_dispatcher_t;

void uds_dispatcher_init_strict(uds_dispatcher_t *dispatcher);
void uds_dispatcher_init_vulnerable(uds_dispatcher_t *dispatcher);
void uds_dispatcher_apply_strict_patch(uds_dispatcher_t *dispatcher);
void uds_dispatcher_activate_quarantine_policy(uds_dispatcher_t *dispatcher);
bool uds_dispatcher_quarantine_policy_active(const uds_dispatcher_t *dispatcher);
void uds_dispatcher_tick(uds_dispatcher_t *dispatcher);

uds_security_phase_t uds_dispatcher_security_phase(
    const uds_dispatcher_t *dispatcher
);

const uds_config_entry_t *uds_dispatcher_find_config_entry(
    const uds_dispatcher_t *dispatcher,
    uint16_t did
);

void uds_dispatcher_handle_request(
    uds_dispatcher_t *dispatcher,
    const uds_request_t *request,
    uds_response_t *response
);

void uds_dispatcher_handle_payload(
    uds_dispatcher_t *dispatcher,
    const uint8_t *request_payload,
    uint8_t request_length,
    uint8_t *response_payload_out,
    uint8_t *response_length_out
);

#ifdef __cplusplus
}
#endif

#endif
