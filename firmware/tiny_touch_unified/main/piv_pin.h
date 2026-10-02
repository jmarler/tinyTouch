#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// Optional PIV PIN that authorizes one login without a fingerprint, for
// remote sessions where nobody can touch the sensor. These functions are not
// thread-safe; piv.c serializes them with its own mutex.

#define PIV_PIN_MIN_LENGTH 6
#define PIV_PIN_MAX_LENGTH 8
#define PIV_PIN_MAX_TRIES 5

typedef enum {
  PIV_PIN_UNSET = 0,
  PIV_PIN_SET = 1,
  PIV_PIN_BLOCKED = 2,
} piv_pin_state_t;

typedef enum {
  PIV_PIN_NOT_SET = 0,
  PIV_PIN_MATCH,
  PIV_PIN_NO_MATCH,
  PIV_PIN_LOCKED,
  PIV_PIN_STORAGE_ERROR,
} piv_pin_result_t;

void piv_pin_load(void);
piv_pin_state_t piv_pin_state(void);
const char *piv_pin_state_name(void);
uint8_t piv_pin_tries_left(void);
bool piv_pin_acceptable(const uint8_t *pin, size_t pin_len);
bool piv_pin_set(const uint8_t *pin, size_t pin_len);
bool piv_pin_clear(void);
// Takes the 8-byte, 0xff-padded PIN field from a PIV VERIFY command.
piv_pin_result_t piv_pin_verify(const uint8_t padded[PIV_PIN_MAX_LENGTH]);
void piv_pin_reset_tries(void);
