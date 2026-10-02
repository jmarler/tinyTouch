import unittest
from pathlib import Path


MAIN = Path(__file__).parents[1] / "firmware" / "tiny_touch_unified" / "main"


class ProtocolSixFirmwareTests(unittest.TestCase):
    def source(self, name: str) -> str:
        return (MAIN / name).read_text()

    def test_no_firmware_software_restart_path(self) -> None:
        source = "\n".join(path.read_text() for path in MAIN.glob("*.c"))
        self.assertNotIn("esp_restart", source)
        self.assertNotIn("RTC_CNTL_FORCE_DOWNLOAD_BOOT", source)

    def test_protocol_six_has_one_stable_usb_descriptor(self) -> None:
        cmake = self.source("CMakeLists.txt")
        usb = self.source("usb_ccid.c")
        descriptors = self.source("usb_descriptors.c")
        self.assertIn("TINYTOUCH_PROTOCOL_VERSION=6", cmake)
        self.assertIn("tiny_touch_configuration_descriptor", usb)
        self.assertNotIn("tiny_touch_hid_configuration_descriptor", descriptors)
        self.assertNotIn("tiny_touch_piv_configuration_descriptor", descriptors)

    def test_usb_resume_reenumerates_without_restarting_firmware(self) -> None:
        defaults = (MAIN.parent / "sdkconfig.defaults").read_text()
        usb = self.source("usb_ccid.c")
        self.assertIn("CONFIG_TINYUSB_RESUME_CALLBACK=y", defaults)
        self.assertIn("TINYUSB_EVENT_RESUMED", usb)
        self.assertIn("resume_reconnect_task", usb)
        self.assertIn("tud_disconnect();", usb)
        self.assertIn("tud_connect();", usb)

    def test_persistence_swaps_one_live_config_blob(self) -> None:
        source = self.source("device_config.c")
        self.assertIn('CONFIG_NAMESPACE "tt6"', source)
        self.assertIn("replace_locked", source)
        self.assertIn("device_config_factory_reset", source)
        self.assertNotIn('"hid_key"', source)
        self.assertNotIn('"hid_hosts"', source)
        self.assertNotIn("mode == DEVICE_MODE_HID && value->hid_host_count == 0", source)

    def test_host_listing_is_read_only_and_uses_lowercase_ids(self) -> None:
        console = self.source("config_console.c")
        self.assertIn('strcmp(command, "HOST LIST")', console)
        self.assertIn('"0123456789abcdef"', console)
        self.assertIn('"OK HOST LIST ids=%s capacity=%u"', console)

    def test_ota_stages_without_changing_the_current_runtime(self) -> None:
        console = self.source("config_console.c")
        update = self.source("firmware_update.c")
        self.assertIn("OK OTA STAGED power_cycle=required", console)
        self.assertIn("esp_ota_set_boot_partition", update)
        self.assertIn("firmware_update_staged", update)
        self.assertIn('strcmp(command, "OTA ABORT") == 0', console)
        self.assertNotIn("fingerprint_prepare_for_restart", console)

    def test_piv_create_is_live_and_status_reports_readiness(self) -> None:
        console = self.source("config_console.c")
        piv = self.source("piv.c")
        self.assertIn('strcmp(command, "PIV CREATE")', console)
        self.assertIn('piv_uses_provisioned_keys() ? "ready" : "unconfigured"', console)
        self.assertIn("piv_create_identity", piv)
        self.assertIn("piv_reload_keys()", piv)

    def test_piv_certificates_separate_login_and_keychain_usage(self) -> None:
        piv = self.source("piv.c")
        self.assertIn("#define PIV_IDENTITY_SCHEMA 3", piv)
        self.assertIn("MBEDTLS_X509_KU_KEY_ENCIPHERMENT", piv)
        self.assertIn("MBEDTLS_X509_KU_DIGITAL_SIGNATURE", piv)
        self.assertIn("if (result == 0 && !key_management)", piv)
        self.assertNotIn(
            "MBEDTLS_X509_KU_DIGITAL_SIGNATURE | "
            "MBEDTLS_X509_KU_KEY_ENCIPHERMENT",
            piv,
        )

    def test_piv_token_identifier_changes_with_the_identity(self) -> None:
        piv = self.source("piv.c")
        console = self.source("config_console.c")
        self.assertIn("set_chuid_guid(cert_9a_der, cert_9a_der_len)", piv)
        self.assertIn("set_chuid_guid(mac, sizeof(mac))", piv)
        self.assertIn("usb_ccid_rescan();", console)

    def test_piv_configuration_allows_bounded_keychain_wrapping(self) -> None:
        piv = self.source("piv.c")
        console = self.source("config_console.c")
        self.assertIn("CONFIGURATION_PRESENCE_WINDOW_TICKS", piv)
        self.assertIn("CONFIGURATION_PIV_OPERATION_LIMIT", piv)
        self.assertIn("user_presence_operations_left", piv)
        self.assertIn("user_presence_allows_repeated_slots", piv)
        self.assertIn("piv_note_configuration_presence", console)
        self.assertIn('"piv_crypto_ok"', piv)
        self.assertIn('"piv_crypto_rejected"', piv)

    def test_fallback_pin_grants_one_login_and_never_replaces_fingerprint_pin(self) -> None:
        piv = self.source("piv.c")
        console = self.source("config_console.c")
        cmake = self.source("CMakeLists.txt")
        self.assertIn('"piv_pin.c"', cmake)
        verify = piv[piv.index("static bool handle_verify("):piv.index("static bool handle_general_authenticate(")]
        # The typed fingerprint PIN is handled first and never reaches the
        # fallback check or spends one of its attempts.
        self.assertLess(
            verify.index("memcmp(data, expected_pin, sizeof(expected_pin)) == 0"),
            verify.index("piv_pin_verify(data)"),
        )
        match = verify[verify.index("case PIV_PIN_MATCH:"):verify.index("case PIV_PIN_NO_MATCH:")]
        self.assertIn("grant_user_presence_locked(USER_PRESENCE_WINDOW_TICKS, 2, false)", match)
        self.assertEqual(verify.count("grant_user_presence_locked"), 1)
        self.assertIn("0x63c0 | piv_pin_tries_left()", verify)
        self.assertIn("0x6983", verify)
        for name in ("piv_note_user_presence", "piv_note_configuration_presence"):
            body = piv[piv.index(f"void {name}(void) {{"):]
            body = body[:body.index("\n}\n")]
            self.assertIn("piv_pin_reset_tries();", body)
        self.assertIn("piv_pin_load();", piv[piv.index("void piv_init(void) {"):])
        command = console[console.index("static void piv_pin_command("):console.index("static void usb_reconnect_task(")]
        self.assertTrue(command.split("{", 1)[1].lstrip().startswith("if (!require_authorized()) return;"))
        self.assertIn("wipe(pin, sizeof(pin));", command)
        self.assertIn("wipe(hex, hex_length);", command)
        self.assertIn('strncmp(command, "PIV PIN ", 8) == 0', console)
        self.assertIn("piv_pin=%s", console)

    def test_fingerprint_auth_requires_presence(self) -> None:
        source = self.source("touch_pin_hid.c")
        self.assertIn("if (!present || !runtime.presence_armed)", source)
        auth_pause = source.index("if (fingerprint_prompted_authorization_active())")
        auth_resume = source.index("TickType_t now", auth_pause)
        paused_source = source[auth_pause:auth_resume]
        self.assertIn("runtime.presence_armed = false", paused_source)
        self.assertIn("auth_wait_for_lift", paused_source)
        self.assertIn("if (!fingerprint_is_ready())", source)
        self.assertIn("wait_hid_ready()", source)
        self.assertNotIn("fingerprint_service_health", source)
        self.assertNotIn("usb_runtime", source)

    def test_fingerprint_operations_report_each_required_touch(self) -> None:
        console = self.source("config_console.c")
        self.assertIn('"EVENT %s"', console)
        self.assertIn("fingerprint_enroll_finger(finger, replace, enroll_prompt, enrollment_connected)", console)
        self.assertIn('"ERR AUTH no_match"', console)

    def test_development_auth_bypass_is_explicitly_opt_in(self) -> None:
        project = (MAIN.parent / "CMakeLists.txt").read_text()
        component = self.source("CMakeLists.txt")
        console = self.source("config_console.c")
        self.assertIn("option(TINYTOUCH_DEVELOPMENT_SKIP_FINGERPRINT_AUTH", project)
        self.assertIn("OFF)", project)
        self.assertIn("if(TINYTOUCH_DEVELOPMENT_SKIP_FINGERPRINT_AUTH)", component)
        self.assertIn("#ifdef TINYTOUCH_DEVELOPMENT_SKIP_FINGERPRINT_AUTH", console)


if __name__ == "__main__":
    unittest.main()
