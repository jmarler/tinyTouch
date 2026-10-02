#include "piv_pin.h"

#include <string.h>

#include "esp_random.h"
#include "mbedtls/sha256.h"
#include "nvs.h"

#define PIN_NAMESPACE "piv_pin"
#define PIN_KEY "state"
#define PIN_VERSION 1

// The private keys share this flash without encryption, so the digest only
// keeps the PIN out of plain sight. The retry counter is the real limit.
typedef struct {
  uint8_t version;
  uint8_t tries_left;
  uint8_t salt[16];
  uint8_t digest[32];
} stored_pin_t;

static stored_pin_t pin;
static bool pin_present;

static const uint8_t FINGERPRINT_PIN[] = {'1', '1', '1', '1', '1', '1'};

static void wipe(void *data, size_t length) {
  volatile uint8_t *cursor = data;
  while (length--) *cursor++ = 0;
}

static bool constant_time_equal(const uint8_t *left, const uint8_t *right, size_t length) {
  uint8_t difference = 0;
  for (size_t i = 0; i < length; i++) difference |= left[i] ^ right[i];
  return difference == 0;
}

static void digest_padded(const uint8_t salt[16], const uint8_t padded[PIV_PIN_MAX_LENGTH],
                          uint8_t digest[32]) {
  uint8_t material[16 + PIV_PIN_MAX_LENGTH];
  memcpy(material, salt, 16);
  memcpy(material + 16, padded, PIV_PIN_MAX_LENGTH);
  mbedtls_sha256(material, sizeof(material), digest, 0);
  wipe(material, sizeof(material));
}

static bool valid(const stored_pin_t *value) {
  return value->version == PIN_VERSION && value->tries_left <= PIV_PIN_MAX_TRIES;
}

static bool save(const stored_pin_t *value) {
  nvs_handle_t handle;
  if (nvs_open(PIN_NAMESPACE, NVS_READWRITE, &handle) != ESP_OK) return false;
  esp_err_t result = nvs_set_blob(handle, PIN_KEY, value, sizeof(*value));
  if (result == ESP_OK) result = nvs_commit(handle);
  nvs_close(handle);
  return result == ESP_OK;
}

void piv_pin_load(void) {
  wipe(&pin, sizeof(pin));
  pin_present = false;
  nvs_handle_t handle;
  if (nvs_open(PIN_NAMESPACE, NVS_READONLY, &handle) != ESP_OK) return;
  stored_pin_t stored;
  size_t length = sizeof(stored);
  esp_err_t result = nvs_get_blob(handle, PIN_KEY, &stored, &length);
  nvs_close(handle);
  // A missing or unreadable record leaves the fallback disabled, so only a
  // fingerprint can authorize PIV operations.
  if (result == ESP_OK && length == sizeof(stored) && valid(&stored)) {
    pin = stored;
    pin_present = true;
  }
  wipe(&stored, sizeof(stored));
}

piv_pin_state_t piv_pin_state(void) {
  if (!pin_present) return PIV_PIN_UNSET;
  return pin.tries_left == 0 ? PIV_PIN_BLOCKED : PIV_PIN_SET;
}

const char *piv_pin_state_name(void) {
  switch (piv_pin_state()) {
    case PIV_PIN_SET: return "set";
    case PIV_PIN_BLOCKED: return "blocked";
    default: return "unset";
  }
}

uint8_t piv_pin_tries_left(void) { return pin_present ? pin.tries_left : 0; }

bool piv_pin_acceptable(const uint8_t *candidate, size_t candidate_len) {
  if (!candidate || candidate_len < PIV_PIN_MIN_LENGTH || candidate_len > PIV_PIN_MAX_LENGTH) {
    return false;
  }
  for (size_t i = 0; i < candidate_len; i++) {
    if (candidate[i] < 0x21 || candidate[i] > 0x7e) return false;
  }
  // The device types this PIN after every fingerprint match, so it is public
  // and must never also work as the fingerprint-free fallback.
  return !(candidate_len == sizeof(FINGERPRINT_PIN) &&
           memcmp(candidate, FINGERPRINT_PIN, sizeof(FINGERPRINT_PIN)) == 0);
}

bool piv_pin_set(const uint8_t *candidate, size_t candidate_len) {
  if (!piv_pin_acceptable(candidate, candidate_len)) return false;
  uint8_t padded[PIV_PIN_MAX_LENGTH];
  memset(padded, 0xff, sizeof(padded));
  memcpy(padded, candidate, candidate_len);
  stored_pin_t next = {.version = PIN_VERSION, .tries_left = PIV_PIN_MAX_TRIES};
  esp_fill_random(next.salt, sizeof(next.salt));
  digest_padded(next.salt, padded, next.digest);
  wipe(padded, sizeof(padded));
  bool ok = save(&next);
  if (ok) {
    pin = next;
    pin_present = true;
  }
  wipe(&next, sizeof(next));
  return ok;
}

bool piv_pin_clear(void) {
  nvs_handle_t handle;
  if (nvs_open(PIN_NAMESPACE, NVS_READWRITE, &handle) != ESP_OK) return false;
  esp_err_t result = nvs_erase_key(handle, PIN_KEY);
  if (result == ESP_ERR_NVS_NOT_FOUND) result = ESP_OK;
  if (result == ESP_OK) result = nvs_commit(handle);
  nvs_close(handle);
  if (result != ESP_OK) return false;
  wipe(&pin, sizeof(pin));
  pin_present = false;
  return true;
}

piv_pin_result_t piv_pin_verify(const uint8_t padded[PIV_PIN_MAX_LENGTH]) {
  if (!pin_present) return PIV_PIN_NOT_SET;
  if (pin.tries_left == 0) return PIV_PIN_LOCKED;
  // Spend the attempt before comparing. Cutting power after a wrong guess
  // must not leave the counter where it was.
  stored_pin_t attempt = pin;
  attempt.tries_left--;
  if (!save(&attempt)) {
    wipe(&attempt, sizeof(attempt));
    return PIV_PIN_STORAGE_ERROR;
  }
  pin.tries_left = attempt.tries_left;
  uint8_t digest[32];
  digest_padded(pin.salt, padded, digest);
  bool match = constant_time_equal(digest, pin.digest, sizeof(digest));
  wipe(digest, sizeof(digest));
  if (match) {
    attempt.tries_left = PIV_PIN_MAX_TRIES;
    if (save(&attempt)) pin.tries_left = PIV_PIN_MAX_TRIES;
  }
  wipe(&attempt, sizeof(attempt));
  return match ? PIV_PIN_MATCH : PIV_PIN_NO_MATCH;
}

void piv_pin_reset_tries(void) {
  if (!pin_present || pin.tries_left == PIV_PIN_MAX_TRIES) return;
  stored_pin_t next = pin;
  next.tries_left = PIV_PIN_MAX_TRIES;
  if (save(&next)) pin.tries_left = PIV_PIN_MAX_TRIES;
  wipe(&next, sizeof(next));
}
