#include "uds_dispatcher.h"

#include <string.h>

static void uds_config_table_init_default(uds_config_table_t *table)
{
    memset(table, 0, sizeof(*table));
    table->count = 3U;
    table->entries[0].did = UDS_VALID_WRITE_DID;
    table->entries[0].readable = true;
    table->entries[0].writable = true;
    table->entries[0].requires_extended_session = true;
    table->entries[0].requires_security_unlock = true;
    table->entries[0].required_security_level = UDS_SECURITY_LEVEL_CONFIG_WRITE;
    table->entries[0].min_write_length = 1U;
    table->entries[0].max_write_length = 4U;

    table->entries[1].did = UDS_READ_ONLY_STATUS_DID;
    table->entries[1].readable = true;
    table->entries[1].writable = false;
    table->entries[1].value_length = 2U;
    table->entries[1].value[0] = 0x42U;
    table->entries[1].value[1] = 0x10U;

    table->entries[2].did = UDS_BENIGN_CONTROL_WRITE_DID;
    table->entries[2].readable = true;
    table->entries[2].writable = true;
    table->entries[2].requires_extended_session = true;
    table->entries[2].requires_security_unlock = true;
    table->entries[2].required_security_level = UDS_SECURITY_LEVEL_CONFIG_WRITE;
    table->entries[2].min_write_length = 1U;
    table->entries[2].max_write_length = 4U;
}

static uds_config_entry_t *uds_config_table_find_mutable(
    uds_config_table_t *table,
    uint16_t did
)
{
    uint8_t index;

    if (table == NULL) {
        return NULL;
    }

    for (index = 0U; index < table->count; ++index) {
        if (table->entries[index].did == did) {
            return &table->entries[index];
        }
    }

    return NULL;
}

const uds_config_entry_t *uds_dispatcher_find_config_entry(
    const uds_dispatcher_t *dispatcher,
    uint16_t did
)
{
    uint8_t index;

    if (dispatcher == NULL) {
        return NULL;
    }

    for (index = 0U; index < dispatcher->config_table.count; ++index) {
        if (dispatcher->config_table.entries[index].did == did) {
            return &dispatcher->config_table.entries[index];
        }
    }

    return NULL;
}

static bool uds_config_entry_write(
    uds_config_entry_t *entry,
    const uint8_t *data,
    uint8_t data_length
)
{
    if (entry == NULL || data == NULL) {
        return false;
    }
    if (data_length > UDS_CONFIG_VALUE_MAX_LENGTH) {
        return false;
    }

    memset(entry->value, 0, sizeof(entry->value));
    memcpy(entry->value, data, data_length);
    entry->value_length = data_length;
    return true;
}

static void uds_session_state_init(uds_session_state_t *state)
{
    memset(state, 0, sizeof(*state));
    state->session = SESSION_DEFAULT;
    state->session_generation = 1U;
}

static void uds_replay_guard_init(uds_replay_guard_t *guard)
{
    memset(guard, 0, sizeof(*guard));
}

static void uds_replay_guard_capture_authorized_write(
    uds_replay_guard_t *guard,
    const uds_session_state_t *state,
    uint16_t did,
    const uint8_t *data,
    uint8_t data_length
)
{
    if (guard == NULL || state == NULL || data == NULL) {
        return;
    }

    guard->last_authorized_valid = true;
    guard->last_authorized_did = did;
    guard->last_authorized_length = data_length;
    memset(guard->last_authorized_data, 0, sizeof(guard->last_authorized_data));
    memcpy(guard->last_authorized_data, data, data_length);
    guard->capture_session_generation = state->session_generation;
    guard->capture_unlock_generation = state->unlock_generation;
}

static bool uds_replay_guard_matches_locked_write(
    const uds_replay_guard_t *guard,
    const uds_session_state_t *state,
    uint16_t did,
    const uint8_t *data,
    uint8_t data_length
)
{
    if (guard == NULL || state == NULL || data == NULL) {
        return false;
    }
    if (!guard->last_authorized_valid) {
        return false;
    }
    if (guard->last_authorized_did != did) {
        return false;
    }
    if (guard->last_authorized_length != data_length) {
        return false;
    }
    if (guard->capture_session_generation != state->session_generation) {
        return false;
    }
    if (guard->capture_unlock_generation != state->unlock_generation) {
        return false;
    }

    return memcmp(guard->last_authorized_data, data, data_length) == 0;
}

static void uds_replay_guard_reset(uds_replay_guard_t *guard)
{
    if (guard == NULL) {
        return;
    }

    memset(guard, 0, sizeof(*guard));
}

static uint16_t uds_expected_key_from_seed(uint16_t seed, uint8_t security_level)
{
    (void)security_level;
    return (uint16_t)(seed ^ UDS_SEED_MASK);
}

static bool uds_security_access_seed_subfunction(uint8_t subfunction)
{
    return (subfunction & 0x01U) == 0x01U;
}

static uint8_t uds_security_access_level_from_subfunction(uint8_t subfunction)
{
    if (uds_security_access_seed_subfunction(subfunction)) {
        return (uint8_t)((subfunction + 1U) >> 1);
    }

    return (uint8_t)(subfunction >> 1);
}

static bool uds_security_access_level_supported(uint8_t security_level)
{
    return security_level == UDS_SECURITY_LEVEL_CONFIG_WRITE;
}

static void uds_session_state_clear_unlock(uds_session_state_t *state)
{
    if (state == NULL) {
        return;
    }

    if (state->security_unlocked || state->security_level != 0U) {
        state->unlock_generation += 1U;
    }
    state->security_unlocked = false;
    state->security_level = 0U;
}

static void uds_dispatcher_init_common(
    uds_dispatcher_t *dispatcher,
    const uds_dispatcher_policy_t *policy
)
{
    if (dispatcher == NULL || policy == NULL) {
        return;
    }

    memset(dispatcher, 0, sizeof(*dispatcher));
    uds_session_state_init(&dispatcher->session_state);
    uds_replay_guard_init(&dispatcher->replay_guard);
    uds_config_table_init_default(&dispatcher->config_table);
    dispatcher->policy = *policy;
}

void uds_dispatcher_init_strict(uds_dispatcher_t *dispatcher)
{
    const uds_dispatcher_policy_t policy = {
        .write_requires_unlock = true,
        .clear_unlock_on_failed_key = true,
        .clear_unlock_on_session_change = true,
        .allow_replay_without_unlock = false,
        .quarantine_config_write_did = false,
        .quarantined_did = UDS_VALID_WRITE_DID,
        .max_failed_attempts = 2U,
        .lockout_duration_ticks = 3U,
    };

    uds_dispatcher_init_common(dispatcher, &policy);
}

void uds_dispatcher_init_vulnerable(uds_dispatcher_t *dispatcher)
{
    const uds_dispatcher_policy_t policy = {
        .write_requires_unlock = false,
        .clear_unlock_on_failed_key = true,
        .clear_unlock_on_session_change = true,
        .allow_replay_without_unlock = true,
        .quarantine_config_write_did = false,
        .quarantined_did = UDS_VALID_WRITE_DID,
        .max_failed_attempts = 2U,
        .lockout_duration_ticks = 3U,
    };

    uds_dispatcher_init_common(dispatcher, &policy);
}

void uds_dispatcher_apply_strict_patch(uds_dispatcher_t *dispatcher)
{
    if (dispatcher == NULL) {
        return;
    }

    dispatcher->policy.write_requires_unlock = true;
    dispatcher->policy.clear_unlock_on_failed_key = true;
    dispatcher->policy.clear_unlock_on_session_change = true;
    dispatcher->policy.allow_replay_without_unlock = false;
    dispatcher->policy.quarantine_config_write_did = false;
    dispatcher->policy.quarantined_did = UDS_VALID_WRITE_DID;
    uds_session_state_clear_unlock(&dispatcher->session_state);
    dispatcher->session_state.pending_seed_valid = false;
    uds_replay_guard_reset(&dispatcher->replay_guard);
}

void uds_dispatcher_activate_quarantine_policy(uds_dispatcher_t *dispatcher)
{
    if (dispatcher == NULL) {
        return;
    }

    dispatcher->policy.quarantined_did = UDS_VALID_WRITE_DID;
    dispatcher->policy.quarantine_config_write_did = true;
}

bool uds_dispatcher_quarantine_policy_active(const uds_dispatcher_t *dispatcher)
{
    return dispatcher != NULL &&
        dispatcher->policy.quarantine_config_write_did &&
        dispatcher->policy.quarantined_did == UDS_VALID_WRITE_DID;
}

void uds_dispatcher_tick(uds_dispatcher_t *dispatcher)
{
    if (dispatcher == NULL) {
        return;
    }

    dispatcher->session_state.periodic_task_tick += 1U;
    if (dispatcher->session_state.lockout_ticks_remaining > 0U) {
        dispatcher->session_state.lockout_ticks_remaining -= 1U;
    }
}

uds_security_phase_t uds_dispatcher_security_phase(
    const uds_dispatcher_t *dispatcher
)
{
    if (dispatcher == NULL) {
        return UDS_SECURITY_PHASE_DEFAULT_SESSION;
    }
    if (dispatcher->session_state.lockout_ticks_remaining > 0U) {
        return UDS_SECURITY_PHASE_LOCKED_OUT;
    }
    if (dispatcher->session_state.security_unlocked) {
        return UDS_SECURITY_PHASE_UNLOCKED;
    }
    if (dispatcher->session_state.pending_seed_valid) {
        return UDS_SECURITY_PHASE_SEED_ISSUED;
    }
    if (dispatcher->session_state.session == SESSION_EXTENDED) {
        return UDS_SECURITY_PHASE_EXTENDED_SESSION;
    }
    return UDS_SECURITY_PHASE_DEFAULT_SESSION;
}

static void uds_handle_session_control(
    uds_dispatcher_t *dispatcher,
    const uds_request_t *request,
    uds_response_t *response
)
{
    uint8_t requested_session;
    uint16_t p2_ms = UDS_SESSION_P2_SERVER_MAX_MS;
    uint16_t p2_star_ms = UDS_SESSION_P2_STAR_SERVER_MAX_MS;
    uint8_t data[5];

    if (!request->has_subfunction) {
        uds_response_make_negative(response, request->sid, NRC_INCORRECT_MESSAGE_LENGTH);
        return;
    }

    requested_session = (uint8_t)(request->subfunction & 0x7FU);
    if (requested_session != SESSION_DEFAULT && requested_session != SESSION_EXTENDED) {
        uds_response_make_negative(response, request->sid, NRC_SUBFUNCTION_NOT_SUPPORTED);
        return;
    }

    if (dispatcher->session_state.session != requested_session) {
        dispatcher->session_state.session_generation += 1U;
    }
    dispatcher->session_state.session = requested_session;
    if (dispatcher->policy.clear_unlock_on_session_change) {
        uds_session_state_clear_unlock(&dispatcher->session_state);
    }
    dispatcher->session_state.pending_seed_valid = false;
    data[0] = requested_session;
    data[1] = (uint8_t)(p2_ms >> 8);
    data[2] = (uint8_t)(p2_ms & 0xFFU);
    data[3] = (uint8_t)(p2_star_ms >> 8);
    data[4] = (uint8_t)(p2_star_ms & 0xFFU);
    uds_response_make_positive(response, request->sid, data, 5U);
}

static void uds_handle_security_access(
    uds_dispatcher_t *dispatcher,
    const uds_request_t *request,
    uds_response_t *response
)
{
    uint16_t expected_key;
    uint16_t supplied_key;
    uint16_t seed_value;
    uint8_t requested_subfunction;
    uint8_t security_level;
    uint8_t data[3];

    if (!request->has_subfunction) {
        uds_response_make_negative(response, request->sid, NRC_INCORRECT_MESSAGE_LENGTH);
        return;
    }

    requested_subfunction = (uint8_t)(request->subfunction & 0x7FU);
    security_level = uds_security_access_level_from_subfunction(requested_subfunction);
    if (!uds_security_access_level_supported(security_level)) {
        uds_response_make_negative(response, request->sid, NRC_SUBFUNCTION_NOT_SUPPORTED);
        return;
    }

    if (dispatcher->session_state.lockout_ticks_remaining > 0U) {
        uds_response_make_negative(response, request->sid, NRC_REQUIRED_TIME_DELAY_NOT_EXPIRED);
        return;
    }

    if (uds_security_access_seed_subfunction(requested_subfunction)) {
        if (dispatcher->session_state.session != SESSION_EXTENDED) {
            uds_response_make_negative(response, request->sid, NRC_CONDITIONS_NOT_CORRECT);
            return;
        }

        dispatcher->session_state.seed_counter += 1U;
        seed_value = (uint16_t)(0x1200U + dispatcher->session_state.seed_counter);
        dispatcher->session_state.pending_seed = seed_value;
        dispatcher->session_state.pending_seed_level = security_level;
        dispatcher->session_state.pending_seed_valid = true;
        data[0] = requested_subfunction;
        data[1] = (uint8_t)(seed_value >> 8);
        data[2] = (uint8_t)(seed_value & 0xFFU);
        uds_response_make_positive(response, request->sid, data, 3U);
        return;
    }

    if (!uds_security_access_seed_subfunction(requested_subfunction)) {
        if (dispatcher->session_state.session != SESSION_EXTENDED) {
            uds_response_make_negative(response, request->sid, NRC_CONDITIONS_NOT_CORRECT);
            return;
        }
        if (!dispatcher->session_state.pending_seed_valid) {
            uds_response_make_negative(response, request->sid, NRC_REQUEST_SEQUENCE_ERROR);
            return;
        }
        if (dispatcher->session_state.pending_seed_level != security_level) {
            dispatcher->session_state.pending_seed_valid = false;
            uds_response_make_negative(response, request->sid, NRC_REQUEST_SEQUENCE_ERROR);
            return;
        }
        if (request->data_length != 2U) {
            uds_response_make_negative(response, request->sid, NRC_INCORRECT_MESSAGE_LENGTH);
            return;
        }

        expected_key = uds_expected_key_from_seed(
            dispatcher->session_state.pending_seed,
            security_level
        );
        supplied_key = (uint16_t)(((uint16_t)request->data[0] << 8) | request->data[1]);

        if (supplied_key != expected_key) {
            if (dispatcher->policy.clear_unlock_on_failed_key) {
                uds_session_state_clear_unlock(&dispatcher->session_state);
            }
            dispatcher->session_state.failed_attempts += 1U;
            dispatcher->session_state.pending_seed_valid = false;
            if (dispatcher->session_state.failed_attempts >= dispatcher->policy.max_failed_attempts) {
                dispatcher->session_state.lockout_ticks_remaining =
                    dispatcher->policy.lockout_duration_ticks;
                uds_response_make_negative(response, request->sid, NRC_EXCEED_NUMBER_OF_ATTEMPTS);
                return;
            }
            uds_response_make_negative(response, request->sid, NRC_INVALID_KEY);
            return;
        }

        dispatcher->session_state.security_unlocked = true;
        dispatcher->session_state.security_level = security_level;
        dispatcher->session_state.failed_attempts = 0U;
        dispatcher->session_state.pending_seed_valid = false;
        dispatcher->session_state.unlock_generation += 1U;
        data[0] = requested_subfunction;
        uds_response_make_positive(response, request->sid, data, 1U);
        return;
    }
}

static void uds_handle_write_data_by_identifier(
    uds_dispatcher_t *dispatcher,
    const uds_request_t *request,
    uds_response_t *response
)
{
    uds_config_entry_t *entry;
    uint8_t response_data[2];
    bool replay_allowed = false;

    if (!request->has_did) {
        uds_response_make_negative(response, request->sid, NRC_INCORRECT_MESSAGE_LENGTH);
        return;
    }

    entry = uds_config_table_find_mutable(&dispatcher->config_table, request->did);
    if (entry == NULL || !entry->writable) {
        uds_response_make_negative(response, request->sid, NRC_REQUEST_OUT_OF_RANGE);
        return;
    }
    if (entry->requires_extended_session &&
        dispatcher->session_state.session != SESSION_EXTENDED) {
        uds_response_make_negative(response, request->sid, NRC_CONDITIONS_NOT_CORRECT);
        return;
    }

    if (entry->requires_security_unlock &&
        dispatcher->policy.write_requires_unlock &&
        (!dispatcher->session_state.security_unlocked ||
         dispatcher->session_state.security_level < entry->required_security_level)) {
        if (dispatcher->policy.allow_replay_without_unlock) {
            replay_allowed = uds_replay_guard_matches_locked_write(
                &dispatcher->replay_guard,
                &dispatcher->session_state,
                request->did,
                request->data,
                request->data_length
            );
        }

        if (!replay_allowed) {
            uds_response_make_negative(response, request->sid, NRC_SECURITY_ACCESS_DENIED);
            return;
        }
    }

    if (dispatcher->policy.quarantine_config_write_did &&
        request->did == dispatcher->policy.quarantined_did) {
        uds_response_make_negative(response, request->sid, NRC_REQUEST_OUT_OF_RANGE);
        return;
    }

    if (request->data_length < entry->min_write_length ||
        request->data_length > entry->max_write_length) {
        uds_response_make_negative(response, request->sid, NRC_INCORRECT_MESSAGE_LENGTH);
        return;
    }

    if (!uds_config_entry_write(entry, request->data, request->data_length)) {
        uds_response_make_negative(response, request->sid, NRC_REQUEST_OUT_OF_RANGE);
        return;
    }

    if (dispatcher->session_state.security_unlocked) {
        uds_replay_guard_capture_authorized_write(
            &dispatcher->replay_guard,
            &dispatcher->session_state,
            request->did,
            request->data,
            request->data_length
        );
    }

    response_data[0] = (uint8_t)(request->did >> 8);
    response_data[1] = (uint8_t)(request->did & 0xFFU);
    uds_response_make_positive(response, request->sid, response_data, 2U);
}

static void uds_handle_read_data_by_identifier(
    uds_dispatcher_t *dispatcher,
    const uds_request_t *request,
    uds_response_t *response
)
{
    const uds_config_entry_t *entry;
    uint8_t response_data[2U + UDS_CONFIG_VALUE_MAX_LENGTH];

    if (!request->has_did) {
        uds_response_make_negative(response, request->sid, NRC_INCORRECT_MESSAGE_LENGTH);
        return;
    }

    entry = uds_dispatcher_find_config_entry(dispatcher, request->did);
    if (entry == NULL || !entry->readable) {
        uds_response_make_negative(response, request->sid, NRC_REQUEST_OUT_OF_RANGE);
        return;
    }
    if (entry->value_length > UDS_CONFIG_VALUE_MAX_LENGTH) {
        uds_response_make_negative(response, request->sid, NRC_REQUEST_OUT_OF_RANGE);
        return;
    }

    response_data[0] = (uint8_t)(request->did >> 8);
    response_data[1] = (uint8_t)(request->did & 0xFFU);
    if (entry->value_length > 0U) {
        memcpy(&response_data[2], entry->value, entry->value_length);
    }
    uds_response_make_positive(
        response,
        request->sid,
        response_data,
        (uint8_t)(2U + entry->value_length)
    );
}

static void uds_handle_tester_present(
    const uds_request_t *request,
    uds_response_t *response
)
{
    uint8_t response_data[1];
    uint8_t subfunction;

    if (!request->has_subfunction || request->data_length != 0U) {
        uds_response_make_negative(response, request->sid, NRC_INCORRECT_MESSAGE_LENGTH);
        return;
    }

    subfunction = (uint8_t)(request->subfunction & 0x7FU);
    if (subfunction != 0x00U) {
        uds_response_make_negative(response, request->sid, NRC_SUBFUNCTION_NOT_SUPPORTED);
        return;
    }

    response_data[0] = subfunction;
    uds_response_make_positive(response, request->sid, response_data, 1U);
}

void uds_dispatcher_handle_request(
    uds_dispatcher_t *dispatcher,
    const uds_request_t *request,
    uds_response_t *response
)
{
    if (dispatcher == NULL || request == NULL || response == NULL) {
        return;
    }

    uds_dispatcher_tick(dispatcher);

    switch (request->sid) {
    case SID_DIAGNOSTIC_SESSION_CONTROL:
        uds_handle_session_control(dispatcher, request, response);
        return;

    case SID_SECURITY_ACCESS:
        uds_handle_security_access(dispatcher, request, response);
        return;

    case SID_READ_DATA_BY_IDENTIFIER:
        uds_handle_read_data_by_identifier(dispatcher, request, response);
        return;

    case SID_WRITE_DATA_BY_IDENTIFIER:
        uds_handle_write_data_by_identifier(dispatcher, request, response);
        return;

    case SID_TESTER_PRESENT:
        uds_handle_tester_present(request, response);
        return;

    default:
        uds_response_make_negative(response, request->sid, NRC_REQUEST_OUT_OF_RANGE);
        return;
    }
}

void uds_dispatcher_handle_payload(
    uds_dispatcher_t *dispatcher,
    const uint8_t *request_payload,
    uint8_t request_length,
    uint8_t *response_payload_out,
    uint8_t *response_length_out
)
{
    uds_request_t request;
    uds_response_t response;
    uint8_t original_sid = 0U;

    if (dispatcher == NULL || response_payload_out == NULL || response_length_out == NULL) {
        return;
    }

    if (request_payload != NULL && request_length > 0U) {
        original_sid = request_payload[0];
    }

    if (!uds_request_from_payload(&request, request_payload, request_length)) {
        uds_response_make_negative(&response, original_sid, NRC_INCORRECT_MESSAGE_LENGTH);
        (void)uds_response_to_payload(&response, response_payload_out, response_length_out);
        return;
    }

    uds_dispatcher_handle_request(dispatcher, &request, &response);
    (void)uds_response_to_payload(&response, response_payload_out, response_length_out);
}
