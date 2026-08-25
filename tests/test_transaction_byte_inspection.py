import pytest

from src.tx import Tx, TxIn, TxOut, Witness, inspect_transaction_bytes


def transaction(*, segwit: bool) -> Tx:
    return Tx(
        version=2,
        inputs=[TxIn(b"\x11" * 32, 3, b"\x51", 0xFFFFFFFE)],
        outputs=[
            TxOut(1_000, bytes.fromhex("76a914" + "22" * 20 + "88ac")),
            TxOut(2_000, b"\x51"),
        ],
        witness=[Witness([b"signature", b"public keys"])] if segwit else None,
        locktime=840_000,
    )


def test_inspects_every_legacy_transaction_byte_in_serialization_order():
    tx = transaction(segwit=False)

    fields = inspect_transaction_bytes(tx)

    assert b"".join(bytes.fromhex(field.hex) for field in fields) == tx.to_bytes()
    assert [(field.id, field.offset) for field in fields[:3]] == [
        ("version", 0),
        ("input-count", 4),
        ("input-0-previous-txid", 5),
    ]
    assert next(field for field in fields if field.id == "output-count").decoded == (
        "2 (1 byte CompactSize)"
    )
    assert next(field for field in fields if field.id == "output-1-amount").decoded == "2000 sats"
    assert next(field for field in fields if field.id == "output-0-script-pubkey").decoded == (
        "25 bytes P2PKH locking script"
    )
    assert next(field for field in fields if field.id == "output-1-script-pubkey").decoded == (
        "1 byte nonstandard or unrecognized locking script"
    )
    assert next(field for field in fields if field.id == "input-0-script-sig").decoded == (
        "1 byte unlocking script"
    )
    assert fields[-1].decoded == "840000 (block height)"


def test_inspects_marker_flag_and_each_segwit_stack_item():
    tx = transaction(segwit=True)

    fields = inspect_transaction_bytes(tx)

    assert b"".join(bytes.fromhex(field.hex) for field in fields) == tx.to_bytes()
    assert fields[1].id == "marker-flag"
    assert fields[1].hex == "0001"
    assert next(field for field in fields if field.id == "input-0-witness-count").decoded == (
        "2 (1 byte CompactSize)"
    )
    assert next(field for field in fields if field.id == "input-0-witness-1").hex == b"public keys".hex()
    assert next(field for field in fields if field.id == "input-0-witness-1").decoded == (
        "11 bytes witness stack item"
    )
    assert tx.wu % 4 != 0
    assert tx.vbytes == (tx.wu + 3) // 4
    assert isinstance(tx.vbytes, int)


def test_marks_coinbase_outpoint_and_final_sequence():
    tx = Tx(
        inputs=[TxIn(bytes(32), 0xFFFFFFFF, b"coinbase", 0xFFFFFFFF)],
        outputs=[TxOut(5_000_000_000, b"\x51")],
    )

    fields = inspect_transaction_bytes(tx)

    assert next(field for field in fields if field.id == "input-0-vout").decoded.endswith(
        "(coinbase marker)"
    )
    assert next(field for field in fields if field.id == "input-0-sequence").decoded.endswith("(final)")


@pytest.mark.parametrize(
    ("scriptpubkey", "expected_type"),
    [
        (bytes.fromhex("76a914" + "11" * 20 + "88ac"), "P2PKH"),
        (bytes.fromhex("a914" + "11" * 20 + "87"), "P2SH"),
        (bytes.fromhex("0014" + "11" * 20), "P2WPKH"),
        (bytes.fromhex("0020" + "11" * 32), "P2WSH"),
        (bytes.fromhex("5120" + "11" * 32), "P2TR"),
    ],
)
def test_decodes_standard_locking_script_types(scriptpubkey: bytes, expected_type: str):
    tx = Tx(
        inputs=[TxIn(bytes(32), 0xFFFFFFFF, b"coinbase", 0xFFFFFFFF)],
        outputs=[TxOut(1_000, scriptpubkey)],
    )

    field = next(
        field for field in inspect_transaction_bytes(tx) if field.id == "output-0-script-pubkey"
    )

    assert field.decoded == f"{len(scriptpubkey)} bytes {expected_type} locking script"
