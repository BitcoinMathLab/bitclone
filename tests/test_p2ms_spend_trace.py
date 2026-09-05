from dataclasses import FrozenInstanceError

import pytest

from src.script import P2MSTraceResult, trace_p2ms_spend
from src.tx import Tx, UTXO
from tests.script_vectors import build_p2ms_case


def test_trace_known_valid_bare_p2ms_spend():
    case = build_p2ms_case()

    result = trace_p2ms_spend(case.tx, 0, case.utxos)

    assert isinstance(result, P2MSTraceResult)
    assert case.tx.txid[::-1].hex() == "949591ad468cef5c41656c0a502d9500671ee421fadb590fbc6373000039b693"
    assert result.input_index == 0
    assert result.unlocking_script == case.scriptsig.script
    assert result.locking_script == case.scriptpubkey.script
    assert result.required_signatures == 2
    assert len(result.public_keys) == 3
    assert len(result.signatures) == 2
    assert result.null_dummy == b""
    assert result.trace.success is True
    assert result.trace.diagnostic is None
    assert [step.opcode.name for step in result.trace.steps] == [
        "OP_0",
        "OP_PUSHBYTES_72",
        "OP_PUSHBYTES_72",
        "OP_2",
        "OP_PUSHBYTES_65",
        "OP_PUSHBYTES_65",
        "OP_PUSHBYTES_65",
        "OP_3",
        "OP_CHECKMULTISIG",
    ]


def test_trace_invalid_multisig_signature_returns_failure_trace():
    case = build_p2ms_case()
    tx = Tx.from_bytes(case.tx.to_bytes())
    scriptsig = bytearray(tx.inputs[0].scriptsig)
    scriptsig[12] ^= 1
    tx.inputs[0].scriptsig = bytes(scriptsig)

    result = trace_p2ms_spend(tx, 0, case.utxos)

    assert result.trace.success is False
    assert result.trace.diagnostic.code == "false-final-value"
    assert result.trace.steps[-1].opcode.name == "OP_CHECKMULTISIG"


def test_trace_rejects_non_bare_multisig_spent_output():
    case = build_p2ms_case()
    output = UTXO(case.tx.inputs[0].outpoint, case.utxos[0].amount, b"\xa9\x14" + b"\x11" * 20 + b"\x87", 0)

    with pytest.raises(ValueError, match="not a legacy bare P2MS"):
        trace_p2ms_spend(case.tx, 0, [output])


def test_trace_rejects_missing_nulldummy():
    case = build_p2ms_case()
    tx = Tx.from_bytes(case.tx.to_bytes())
    tx.inputs[0].scriptsig = tx.inputs[0].scriptsig[1:]

    with pytest.raises(ValueError, match="P2MS scriptSig"):
        trace_p2ms_spend(tx, 0, case.utxos)


def test_trace_result_is_immutable():
    case = build_p2ms_case()
    result = trace_p2ms_spend(case.tx, 0, case.utxos)

    with pytest.raises(FrozenInstanceError):
        result.input_index = 1
