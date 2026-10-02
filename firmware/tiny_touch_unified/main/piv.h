#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

void piv_init(void);
void piv_reload_keys(void);
void piv_reset_transport_state(void);
void piv_note_user_presence(void);
void piv_note_configuration_presence(void);
bool piv_set_fallback_pin(const uint8_t *pin, size_t pin_len);
bool piv_clear_fallback_pin(void);
const char *piv_fallback_pin_state_name(void);
bool piv_uses_provisioned_keys(void);
bool piv_create_identity(void);
bool piv_handle_apdu(const uint8_t *apdu, size_t apdu_len,
                     uint8_t *response, size_t *response_len,
                     size_t response_cap);
