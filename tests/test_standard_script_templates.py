import pytest

from src.script import (
    P2TR_Key,
    ScriptType,
    StandardScriptTemplate,
    build_standard_script,
    get_scriptpubkey_type,
)


@pytest.mark.parametrize(
    ("template", "program", "expected_hex", "script_type", "address_prefix"),
    [
        ("P2SH", b"\x11" * 20, "a914" + "11" * 20 + "87", ScriptType.P2SH, "3"),
        ("P2WPKH", b"\x22" * 20, "0014" + "22" * 20, ScriptType.P2WPKH, "bc1q"),
        ("P2WSH", b"\x33" * 32, "0020" + "33" * 32, ScriptType.P2WSH, "bc1q"),
    ],
)
def test_builds_standard_hash_and_witness_templates(
    template, program, expected_hex, script_type, address_prefix
):
    result = build_standard_script(template, program)

    assert result.template.value == template
    assert result.script_type is script_type
    assert result.script_pubkey.hex() == expected_hex
    assert result.address.startswith(address_prefix)
    assert get_scriptpubkey_type(result.script_pubkey) is script_type
    assert result.to_dict()["script_pubkey_hex"] == expected_hex


@pytest.mark.parametrize(
    "template", [StandardScriptTemplate.P2TR_KEY_PATH, StandardScriptTemplate.P2TR_SCRIPT_PATH]
)
def test_builds_taproot_templates_from_the_same_committed_output_key(template):
    internal_key = bytes.fromhex(
        "924c163b385af7093440184af6fd6244936d1288cbb41cc3812286d3f83a3329"
    )
    output_key = P2TR_Key(internal_key).script[2:]

    result = build_standard_script(template, output_key)

    assert result.template is template
    assert result.script_type is ScriptType.P2TR
    assert result.script_pubkey == b"\x51\x20" + output_key
    assert result.address.startswith("bc1p")


@pytest.mark.parametrize(
    ("template", "program", "message"),
    [
        ("P2SH", b"\x11" * 19, "20-byte"),
        ("P2WPKH", b"\x11" * 21, "20-byte"),
        ("P2WSH", b"\x11" * 31, "32-byte"),
        ("P2TR-KEY-PATH", b"\x11" * 31, "32-byte"),
    ],
)
def test_rejects_programs_with_the_wrong_length(template, program, message):
    with pytest.raises(ValueError, match=message):
        build_standard_script(template, program)


def test_rejects_unknown_templates_and_non_bytes_programs():
    with pytest.raises(ValueError, match="Unsupported"):
        build_standard_script("P2PKH", b"\x11" * 20)
    with pytest.raises(TypeError, match="must be bytes"):
        build_standard_script("P2SH", "11" * 20)


def test_rejects_an_invalid_taproot_output_key_with_a_stable_error():
    with pytest.raises(ValueError, match="valid x-only output key"):
        build_standard_script("P2TR-SCRIPT-PATH", b"\xff" * 32)
