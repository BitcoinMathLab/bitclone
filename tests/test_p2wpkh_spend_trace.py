from dataclasses import FrozenInstanceError

import pytest

from src.core import serialize_data
from src.script import (
    P2WPKHTraceResult,
    get_segwit_sighash,
    get_segwit_sighash_preimage,
    trace_p2wpkh_spend,
)
from src.tx import Tx, UTXO
from tests.script_vectors import build_p2wpkh_case


def test_trace_known_valid_native_p2wpkh_spend():
    case = build_p2wpkh_case()

    result = trace_p2wpkh_spend(case.tx, 0, case.utxos)

    assert isinstance(result, P2WPKHTraceResult)
    assert result.witness == tuple(case.tx.witness[0].items)
    assert result.locking_script == case.scriptpubkey.script
    assert result.script_code.hex() == "76a914841b80d2cc75f5345c482af96294d04fdd66b2b788ac"
    assert result.trace.success is True
    assert result.trace.steps[0].main_stack_before.items == tuple(reversed(result.witness))
    assert [step.opcode.name for step in result.trace.steps] == [
        "OP_DUP", "OP_HASH160", "OP_PUSHBYTES_20", "OP_EQUALVERIFY", "OP_CHECKSIG"
    ]


def test_bip143_preimage_and_digest_match_known_valid_signature():
    case = build_p2wpkh_case()
    result = trace_p2wpkh_spend(case.tx, 0, case.utxos)
    preimage = get_segwit_sighash_preimage(
        case.tx, 0, case.utxos[0].amount, serialize_data(result.script_code), 1
    )

    assert preimage.hex() == (
        "02000000d409ff70f88bfdf4f82f201b99df100cc56466165688acf203d4fd6a7173e8bc"
        "3bb13029ce7b1f559ef5e747fcac439f1455a2ec7c5f09b72290795e70665044"
        "3aa815ace3c5751ee6c325d614044ad58c18ed2858a44f9d9f98fbcddad878c100000000"
        "1976a914841b80d2cc75f5345c482af96294d04fdd66b2b788ac4087100000000000"
        "ffffffff59d2c073a8f9790f052fe8da122d2de40b1d5646e32f5512e3fb2c46023dd9f4"
        "0000000001000000"
    )
    assert get_segwit_sighash(
        case.tx, 0, case.utxos[0].amount, serialize_data(result.script_code), 1
    ).hex() == "e4ce544b38c694f09ca943f9a53a9051c981a81177fc0f9d689e2873c5e95270"


def test_trace_invalid_witness_signature_returns_failure_trace():
    case = build_p2wpkh_case()
    tx = Tx.from_bytes(case.tx.to_bytes())
    signature = bytearray(tx.witness[0].items[0])
    signature[10] ^= 1
    tx.witness[0].items[0] = bytes(signature)

    result = trace_p2wpkh_spend(tx, 0, case.utxos)

    assert result.trace.success is False
    assert result.trace.diagnostic.code == "false-final-value"


def test_trace_rejects_wrong_native_witness_context():
    case = build_p2wpkh_case()
    tx = Tx.from_bytes(case.tx.to_bytes())
    tx.inputs[0].scriptsig = b"\x00"
    with pytest.raises(ValueError, match="empty scriptSig"):
        trace_p2wpkh_spend(tx, 0, case.utxos)

    output = UTXO(case.utxos[0].outpoint, case.utxos[0].amount, b"\x51", 0)
    with pytest.raises(ValueError, match="native P2WPKH"):
        trace_p2wpkh_spend(case.tx, 0, [output])


def test_trace_result_is_immutable():
    case = build_p2wpkh_case()
    result = trace_p2wpkh_spend(case.tx, 0, case.utxos)
    with pytest.raises(FrozenInstanceError):
        result.input_index = 1
