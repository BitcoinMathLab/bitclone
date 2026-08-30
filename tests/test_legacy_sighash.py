import pytest

from src.core import SignatureError
from src.cryptography import hash256
from src.script import get_legacy_sighash, get_legacy_sighash_preimage
from src.tx import Tx, TxIn, TxOut


def _transaction() -> Tx:
    return Tx(
        inputs=[
            TxIn(b"\x11" * 32, 0, b"original-one", 0xFFFFFFFE),
            TxIn(b"\x22" * 32, 1, b"original-two", 0xFFFFFFFD),
        ],
        outputs=[TxOut(5_000, b"\x51"), TxOut(7_000, b"\x52")],
        version=1,
        locktime=9,
    )


def test_legacy_preimage_replaces_only_the_selected_input_script_and_appends_hash_type():
    tx = _transaction()
    script_code = bytes.fromhex("76a914" + "33" * 20 + "88ac")

    preimage = get_legacy_sighash_preimage(tx, 1, script_code, 1)
    signing_tx = Tx.from_bytes(preimage[:-4])

    assert signing_tx.inputs[0].scriptsig == b""
    assert signing_tx.inputs[1].scriptsig == script_code
    assert preimage[-4:] == bytes.fromhex("01000000")
    assert hash256(preimage) == get_legacy_sighash(tx, 1, script_code, 1)
    assert tx.inputs[0].scriptsig == b"original-one"
    assert tx.inputs[1].scriptsig == b"original-two"


def test_legacy_sighash_none_commits_to_no_outputs_or_other_input_sequences():
    tx = _transaction()

    preimage = get_legacy_sighash_preimage(tx, 1, b"\x51", 0x02)
    signing_tx = Tx.from_bytes(preimage[:-4])

    assert signing_tx.outputs == []
    assert [tx_input.sequence for tx_input in signing_tx.inputs] == [0, 0xFFFFFFFD]
    assert preimage[-4:] == bytes.fromhex("02000000")


def test_legacy_sighash_single_commits_only_to_the_matching_output():
    tx = _transaction()

    preimage = get_legacy_sighash_preimage(tx, 1, b"\x51", 0x03)
    signing_tx = Tx.from_bytes(preimage[:-4])

    assert signing_tx.outputs[0] == TxOut(0xFFFFFFFFFFFFFFFF, b"")
    assert signing_tx.outputs[1] == tx.outputs[1]
    assert [tx_input.sequence for tx_input in signing_tx.inputs] == [0, 0xFFFFFFFD]


@pytest.mark.parametrize("sighash_type", [0x81, 0x82, 0x83])
def test_legacy_anyonecanpay_commits_only_to_the_selected_input(sighash_type):
    tx = _transaction()

    preimage = get_legacy_sighash_preimage(tx, 1, b"\x51", sighash_type)
    signing_tx = Tx.from_bytes(preimage[:-4])

    assert len(signing_tx.inputs) == 1
    assert signing_tx.inputs[0].txid == b"\x22" * 32
    assert signing_tx.inputs[0].scriptsig == b"\x51"
    assert preimage[-4:] == sighash_type.to_bytes(4, "little")


def test_unknown_legacy_base_type_uses_sighash_all_transformation():
    tx = _transaction()

    preimage = get_legacy_sighash_preimage(tx, 1, b"\x51", 0x04)
    signing_tx = Tx.from_bytes(preimage[:-4])

    assert signing_tx.outputs == tx.outputs
    assert [tx_input.sequence for tx_input in signing_tx.inputs] == [0xFFFFFFFE, 0xFFFFFFFD]


def test_legacy_sighash_single_bug_returns_uint256_one_without_a_preimage():
    tx = Tx(inputs=_transaction().inputs, outputs=[TxOut(5_000, b"\x51")])

    assert get_legacy_sighash(tx, 1, b"\x51", 0x03) == b"\x01" + b"\x00" * 31
    with pytest.raises(SignatureError, match="no corresponding output preimage"):
        get_legacy_sighash_preimage(tx, 1, b"\x51", 0x03)
