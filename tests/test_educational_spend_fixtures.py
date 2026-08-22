"""Regression coverage for the real spend used by Bitcoin Math Lab lessons."""

from src.script import SpendType, classify_spend, trace_p2pkh_spend
from src.tx import Tx, UTXO


HISTORICAL_P2PKH_TXID = "40e331b67c0fe7750bb3b1943b378bf702dce86124dc12fa5980f975db7ec930"
HISTORICAL_P2PKH_TRANSACTION_HEX = (
    "0100000001a4e61ed60e66af9f7ca4f2eb25234f6e32e0cb8f6099db21a2462c42de61640b010000006b"
    "483045022100c233c3a8a510e03ad18b0a24694ef00c78101bfd5ac075b8c1037952ce26e91e02205aa5f8f88f29bb"
    "4ad5808ebc12abfd26bd791256f367b04c6d955f01f28a7724012103f0609c81a45f8cab67fc2d050c21b1acd3d37c"
    "7acfd54041be6601ab4cef4f31feffffff02f9243751130000001976a9140c443537e6e31f06e6edb2d4bb80f8481e"
    "2831ac88ac14206c00000000001976a914d807ded709af8893f02cdc30a37994429fa248ca88ac751a0600"
)
HISTORICAL_P2PKH_AMOUNT_SATS = 82_974_043_165
HISTORICAL_P2PKH_SCRIPT_PUBKEY_HEX = "76a91455ae51684c43435da751ac8d2173b2652eb6410588ac"


def historical_spend(transaction_hex=HISTORICAL_P2PKH_TRANSACTION_HEX):
    transaction = Tx.from_bytes(bytes.fromhex(transaction_hex))
    spent_output = UTXO(
        outpoint=transaction.inputs[0].outpoint,
        amount=HISTORICAL_P2PKH_AMOUNT_SATS,
        scriptpubkey=bytes.fromhex(HISTORICAL_P2PKH_SCRIPT_PUBKEY_HEX),
        block_height=0,
    )
    return transaction, spent_output


def test_historical_fixture_is_canonical_and_has_expected_shape():
    transaction, spent_output = historical_spend()

    assert transaction.to_bytes().hex() == HISTORICAL_P2PKH_TRANSACTION_HEX
    assert transaction.txid[::-1].hex() == HISTORICAL_P2PKH_TXID
    assert len(transaction.inputs) == 1
    assert len(transaction.outputs) == 2
    assert classify_spend(
        spent_output.scriptpubkey,
        script_sig=transaction.inputs[0].scriptsig,
    ).spend_type is SpendType.P2PKH


def test_historical_fixture_produces_a_successful_p2pkh_trace():
    transaction, spent_output = historical_spend()

    result = trace_p2pkh_spend(transaction, 0, [spent_output])

    assert result.trace.success is True
    assert result.trace.diagnostic is None
    assert result.trace.steps[-1].opcode.name == "OP_CHECKSIG"


def test_one_changed_historical_signature_byte_produces_the_teaching_failure():
    invalid_hex = HISTORICAL_P2PKH_TRANSACTION_HEX.replace("c233", "c333", 1)
    transaction, spent_output = historical_spend(invalid_hex)

    changed_bytes = sum(
        left != right
        for left, right in zip(
            bytes.fromhex(HISTORICAL_P2PKH_TRANSACTION_HEX), bytes.fromhex(invalid_hex), strict=True
        )
    )
    result = trace_p2pkh_spend(transaction, 0, [spent_output])

    assert changed_bytes == 1
    assert result.trace.success is False
    assert result.trace.diagnostic is not None
    assert result.trace.diagnostic.code == "false-final-value"
    assert result.trace.steps[-1].opcode.name == "OP_CHECKSIG"
