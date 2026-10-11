rule USBGuardian_Harmless_Test
{
    meta:
        description = "Harmless test rule for USB Guardian"
        author = "USB Guardian"

    strings:
        $test_string = "USB_GUARDIAN_YARA_TEST_2026"

    condition:
        $test_string
}