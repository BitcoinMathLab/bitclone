from dataclasses import FrozenInstanceError

import pytest

from src.script import P2PKHTraceResult, trace_p2pkh_spend
from src.tx import Tx, UTXO
from tests.script_vectors import build_p2pkh_case


def test_trace_known_valid_p2pkh_spend():
    case = build_p2pkh_case()

    result = trace_p2pkh_spend(case.tx, 0, case.utxos)

    assert isinstance(result, P2PKHTraceResult)
    assert result.input_index == 0
    assert result.unlocking_script == case.scriptsig.script
    assert result.locking_script == case.scriptpubkey.script
    assert result.combined_script == case.scriptsig.script + case.scriptpubkey.script
    assert result.trace.success is True
    assert result.trace.diagnostic is None
    assert [step.opcode.name for step in result.trace.steps] == [
        "OP_PUSHBYTES_72",
        "OP_PUSHBYTES_33",
        "OP_DUP",
        "OP_HASH160",
        "OP_PUSHBYTES_20",
        "OP_EQUALVERIFY",
        "OP_CHECKSIG",
    ]


def test_trace_invalid_p2pkh_signature_returns_failure_trace():
    case = build_p2pkh_case()
    tx = Tx.from_bytes(case.tx.to_bytes())
    scriptsig = bytearray(tx.inputs[0].scriptsig)
    scriptsig[10] ^= 0x01
    tx.inputs[0].scriptsig = bytes(scriptsig)

    result = trace_p2pkh_spend(tx, 0, case.utxos)

    assert result.trace.success is False
    assert result.trace.diagnostic is not None
    assert result.trace.diagnostic.code == "false-final-value"
    assert result.trace.steps[-1].opcode.name == "OP_CHECKSIG"


def test_trace_requires_every_spent_output_in_input_order():
    case = build_p2pkh_case()

    with pytest.raises(ValueError, match="one UTXO per input"):
        trace_p2pkh_spend(case.tx, 0, [])

    wrong_output = UTXO(
        outpoint=b"\x00" * 36,
        amount=case.utxos[0].amount,
        scriptpubkey=case.utxos[0].scriptpubkey,
        block_height=case.utxos[0].block_height,
    )
    with pytest.raises(ValueError, match="expected"):
        trace_p2pkh_spend(case.tx, 0, [wrong_output])


def test_trace_rejects_non_p2pkh_spent_output():
    case = build_p2pkh_case()
    output = UTXO(
        outpoint=case.tx.inputs[0].outpoint,
        amount=case.utxos[0].amount,
        scriptpubkey=b"\x51",
        block_height=case.utxos[0].block_height,
    )

    with pytest.raises(ValueError, match="not a legacy P2PKH"):
        trace_p2pkh_spend(case.tx, 0, [output])


def test_trace_rejects_p2pkh_scriptsig_with_trailing_instruction():
    case = build_p2pkh_case()
    tx = Tx.from_bytes(case.tx.to_bytes())
    tx.inputs[0].scriptsig += b"\x51"

    with pytest.raises(ValueError, match="P2PKH scriptSig"):
        trace_p2pkh_spend(tx, 0, case.utxos)


def test_trace_result_is_immutable():
    case = build_p2pkh_case()
    result = trace_p2pkh_spend(case.tx, 0, case.utxos)

    with pytest.raises(FrozenInstanceError):
        result.input_index = 1
