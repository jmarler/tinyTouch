#include "led_stubs.h"
#include "../../firmware/tiny_touch_unified/main/piv_pin.c"

static uint8_t disk[64], staged[64];
static size_t disk_len, staged_len;
static bool have_disk, stage, stage_erase, fail_save;
static int saves, fail_on_save = -1;
static uint8_t random_byte;

int nvs_open(const char *name, int mode, nvs_handle_t *handle) {
  assert(strcmp(name, "piv_pin") == 0); (void)mode; *handle = 1; return ESP_OK;
}
int nvs_get_blob(nvs_handle_t handle, const char *key, void *data, size_t *length) {
  (void)handle; assert(strcmp(key, "state") == 0);
  if (!have_disk) return ESP_ERR_NVS_NOT_FOUND;
  if (*length < disk_len) return -3;
  memcpy(data, disk, disk_len); *length = disk_len; return ESP_OK;
}
int nvs_set_blob(nvs_handle_t handle, const char *key, const void *data, size_t length) {
  (void)handle; assert(strcmp(key, "state") == 0); assert(length <= sizeof(staged));
  if (fail_save || saves == fail_on_save) return -1;
  memcpy(staged, data, length); staged_len = length; stage = true; return ESP_OK;
}
int nvs_erase_key(nvs_handle_t handle, const char *key) {
  (void)handle; assert(strcmp(key, "state") == 0);
  if (!have_disk) return ESP_ERR_NVS_NOT_FOUND;
  stage_erase = true; return ESP_OK;
}
int nvs_commit(nvs_handle_t handle) {
  (void)handle; if (fail_save) return -1;
  if (stage) { memcpy(disk, staged, staged_len); disk_len = staged_len; have_disk = true; saves++; }
  if (stage_erase) have_disk = false;
  stage = stage_erase = false; return ESP_OK;
}
// Writes that were never committed are lost, as they are after a power cut.
void nvs_close(nvs_handle_t handle) { (void)handle; stage = stage_erase = false; }
void esp_fill_random(void *buffer, size_t length) {
  uint8_t *bytes = buffer;
  for (size_t i = 0; i < length; i++) bytes[i] = random_byte++;
}
// Not SHA-256, but any change to the salt or PIN changes every output byte.
int mbedtls_sha256(const unsigned char *data, size_t length, unsigned char output[32], int is224) {
  (void)is224;
  for (unsigned i = 0; i < 32; i++) {
    uint32_t hash = 2166136261u ^ i;
    for (size_t j = 0; j < length; j++) hash = (hash ^ data[j]) * 16777619u;
    output[i] = (uint8_t)(hash >> 24);
  }
  return ESP_OK;
}

static piv_pin_result_t verify(const char *text) {
  uint8_t padded[PIV_PIN_MAX_LENGTH];
  memset(padded, 0xff, sizeof(padded));
  memcpy(padded, text, strlen(text));
  return piv_pin_verify(padded);
}
static bool set(const char *text) { return piv_pin_set((const uint8_t *)text, strlen(text)); }
static uint8_t disk_tries(void) { assert(have_disk); return ((stored_pin_t *)disk)->tries_left; }

int main(void) {
  // A device that never set a fallback PIN only accepts fingerprints.
  piv_pin_load();
  assert(piv_pin_state() == PIV_PIN_UNSET && strcmp(piv_pin_state_name(), "unset") == 0);
  assert(verify("246810") == PIV_PIN_NOT_SET);
  piv_pin_reset_tries();
  assert(saves == 0 && !have_disk);

  // Reject PIV-incompatible lengths, spaces and controls, and the PIN the
  // device types after a fingerprint match.
  const char *rejected[] = {"", "12345", "123456789", "12 456", "111111"};
  for (unsigned i = 0; i < sizeof(rejected) / sizeof(rejected[0]); i++) {
    assert(!piv_pin_acceptable((const uint8_t *)rejected[i], strlen(rejected[i])));
    assert(!set(rejected[i]));
  }
  assert(!piv_pin_acceptable((const uint8_t *)"abc\x7f" "ef", 6));
  assert(!piv_pin_acceptable(NULL, 6));
  assert(piv_pin_acceptable((const uint8_t *)"1111111", 7));
  assert(piv_pin_acceptable((const uint8_t *)"pin-test", 8));
  assert(piv_pin_state() == PIV_PIN_UNSET && !have_disk);

  assert(set("246810"));
  assert(piv_pin_state() == PIV_PIN_SET && piv_pin_tries_left() == PIV_PIN_MAX_TRIES);
  assert(disk_len == sizeof(stored_pin_t) && disk_tries() == PIV_PIN_MAX_TRIES);
  for (size_t i = 0; i + 6 <= disk_len; i++) assert(memcmp(disk + i, "246810", 6) != 0);

  // A wrong guess is spent on disk, so a reload or power cut cannot undo it.
  assert(verify("000000") == PIV_PIN_NO_MATCH);
  assert(piv_pin_tries_left() == 4 && disk_tries() == 4);
  piv_pin_load();
  assert(piv_pin_tries_left() == 4);
  // Padding is part of the PIN, so a longer PIN with the same prefix differs.
  assert(verify("2468100") == PIV_PIN_NO_MATCH && piv_pin_tries_left() == 3);
  assert(verify("246810") == PIV_PIN_MATCH);
  assert(piv_pin_tries_left() == PIV_PIN_MAX_TRIES && disk_tries() == PIV_PIN_MAX_TRIES);

  // The attempt is committed before the comparison. If restoring the counter
  // after a match fails, the match still counts but the attempt stays spent.
  fail_on_save = saves + 1;
  assert(verify("246810") == PIV_PIN_MATCH);
  fail_on_save = -1;
  assert(disk_tries() == PIV_PIN_MAX_TRIES - 1 && piv_pin_tries_left() == PIV_PIN_MAX_TRIES - 1);
  piv_pin_reset_tries();
  assert(disk_tries() == PIV_PIN_MAX_TRIES);

  // When the attempt cannot be recorded, the PIN is not checked at all.
  int before = saves;
  fail_save = true;
  assert(verify("246810") == PIV_PIN_STORAGE_ERROR);
  fail_save = false;
  assert(saves == before && piv_pin_tries_left() == PIV_PIN_MAX_TRIES);

  for (unsigned i = 0; i < PIV_PIN_MAX_TRIES; i++) assert(verify("999999") == PIV_PIN_NO_MATCH);
  assert(piv_pin_state() == PIV_PIN_BLOCKED && strcmp(piv_pin_state_name(), "blocked") == 0);
  before = saves;
  assert(verify("246810") == PIV_PIN_LOCKED && saves == before);
  piv_pin_load();
  assert(piv_pin_state() == PIV_PIN_BLOCKED);

  // A fingerprint restores the attempts.
  piv_pin_reset_tries();
  assert(piv_pin_state() == PIV_PIN_SET && disk_tries() == PIV_PIN_MAX_TRIES);
  before = saves;
  piv_pin_reset_tries();
  assert(saves == before);
  assert(verify("246810") == PIV_PIN_MATCH);

  // Replacing the PIN draws a new salt and retires the old PIN.
  uint8_t old_salt[16];
  memcpy(old_salt, pin.salt, sizeof(old_salt));
  assert(set("13579bdf"));
  assert(memcmp(old_salt, pin.salt, sizeof(old_salt)) != 0);
  assert(verify("246810") == PIV_PIN_NO_MATCH);
  assert(verify("13579bdf") == PIV_PIN_MATCH);
  fail_save = true;
  assert(!set("864200"));
  fail_save = false;
  assert(verify("13579bdf") == PIV_PIN_MATCH);

  // A damaged record disables the fallback instead of trusting it.
  uint8_t saved[64];
  size_t saved_len = disk_len;
  memcpy(saved, disk, disk_len);
  ((stored_pin_t *)disk)->tries_left = PIV_PIN_MAX_TRIES + 1;
  piv_pin_load();
  assert(piv_pin_state() == PIV_PIN_UNSET && verify("13579bdf") == PIV_PIN_NOT_SET);
  memcpy(disk, saved, saved_len);
  ((stored_pin_t *)disk)->version = 0;
  piv_pin_load();
  assert(piv_pin_state() == PIV_PIN_UNSET);
  memcpy(disk, saved, saved_len);
  disk_len = saved_len - 1;
  piv_pin_load();
  assert(piv_pin_state() == PIV_PIN_UNSET);
  disk_len = saved_len;
  piv_pin_load();
  assert(piv_pin_state() == PIV_PIN_SET);

  assert(piv_pin_clear());
  assert(piv_pin_state() == PIV_PIN_UNSET && !have_disk);
  assert(verify("13579bdf") == PIV_PIN_NOT_SET);
  piv_pin_load();
  assert(piv_pin_state() == PIV_PIN_UNSET);
  assert(piv_pin_clear());
  return 0;
}
