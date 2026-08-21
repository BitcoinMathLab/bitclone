import pytest

from src.script import ScriptType, SpendType, classify_spend


@pytest.mark.parametrize(
    ("script_pubkey", "expected"),
    [
        (b"\x21" + b"\x02" + b"\x11" * 32 + b"\xac", SpendType.P2PK),
        (b"\x76\xa9\x14" + b"\x11" * 20 + b"\x88\xac", SpendType.P2PKH),
        (b"\xa9\x14" + b"\x11" * 20 + b"\x87", SpendType.P2SH),
        (b"\x00\x14" + b"\x11" * 20, SpendType.P2WPKH),
        (b"\x00\x20" + b"\x11" * 32, SpendType.P2WSH),
    ],
)
def test_classifies_standard_output_spends(script_pubkey, expected):
    classification = classify_spend(script_pubkey)

    assert classification.spend_type is expected
    assert classification.output_type is ScriptType[expected.name]
    assert classification.to_dict()["spend_type"] == expected.value


@pytest.mark.parametrize(
    ("witness_program", "expected"),
    [
        (b"\x00\x14" + b"\x22" * 20, SpendType.P2SH_P2WPKH),
        (b"\x00\x20" + b"\x22" * 32, SpendType.P2SH_P2WSH),
    ],
)
def test_classifies_nested_segwit_from_the_single_redeem_script_push(witness_program, expected):
    script_pubkey = b"\xa9\x14" + b"\x11" * 20 + b"\x87"

    classification = classify_spend(
        script_pubkey,
        script_sig=bytes([len(witness_program)]) + witness_program,
        witness=[b"signature", b"script"],
    )

    assert classification.output_type is ScriptType.P2SH
    assert classification.spend_type is expected
    assert classification.is_nested
    assert classification.redeem_script == witness_program


def test_does_not_misclassify_a_p2sh_scriptsig_with_extra_stack_items():
    script_pubkey = b"\xa9\x14" + b"\x11" * 20 + b"\x87"
    witness_program = b"\x00\x14" + b"\x22" * 20

    classification = classify_spend(
        script_pubkey,
        script_sig=b"\x51" + bytes([len(witness_program)]) + witness_program,
    )

    assert classification.spend_type is SpendType.P2SH
    assert not classification.is_nested


@pytest.mark.parametrize(
    ("witness", "expected"),
    [
        ([b"\x11" * 64], SpendType.P2TR_KEY_PATH),
        ([b"\x11" * 64, b"\x50annex"], SpendType.P2TR_KEY_PATH),
        ([b"argument", b"\x51", b"\xc0" + b"\x22" * 32], SpendType.P2TR_SCRIPT_PATH),
        (
            [b"argument", b"\x51", b"\xc0" + b"\x22" * 32, b"\x50annex"],
            SpendType.P2TR_SCRIPT_PATH,
        ),
        ([], SpendType.UNKNOWN),
        ([b"argument", b"script", b"short control"], SpendType.UNKNOWN),
    ],
)
def test_distinguishes_taproot_spend_paths_and_optional_annex(witness, expected):
    script_pubkey = b"\x51\x20" + b"\x11" * 32

    classification = classify_spend(script_pubkey, witness=witness)

    assert classification.output_type is ScriptType.P2TR
    assert classification.spend_type is expected


@pytest.mark.parametrize("script", [b"", b"\x76", b"\xa9", b"\x51\x20", b"\x6a\x01\x01"])
def test_unknown_or_truncated_scripts_are_safe(script):
    classification = classify_spend(script)

    assert classification.output_type is None
    assert classification.spend_type is SpendType.UNKNOWN
