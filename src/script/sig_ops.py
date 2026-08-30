"""
The SignatureEngine class, used to create signatures for transactions
#TODO: Add docstrings to each function stating the algorithm and references
"""

from __future__ import annotations

from enum import IntEnum

from src.core import SignatureError, TX, TAPROOT, write_compact_size
from src.cryptography import ecdsa, verify_ecdsa, schnorr_verify, schnorr_sig, hash256, sha256, tapsighash_hash
from src.data import encode_der_signature, decode_der_signature, PubKey
from src.tx import Tx, TxOut, UTXO

__all__ = ["SigHash", "get_legacy_sighash_preimage", "get_legacy_sighash", "get_segwit_sighash", "get_taproot_sighash", "get_schnorr_sig",
           "verify_schnorr_sig", "get_ecdsa_sig", "verify_ecdsa_sig"]


class SigHash(IntEnum):
    DEFAULT = 0x00
    ALL = 0x01
    NONE = 0x02
    SINGLE = 0x03
    ALL_ANYONECANPAY = 0x81  # (0x81 interpreted as signed int)
    NONE_ANYONECANPAY = 0x82  # (0x82 interpreted as signed int)
    SINGLE_ANYONECANPAY = 0x83  # (0x83 interpreted as signed int)

    def to_byte(self) -> bytes:
        """
        Encodes the sighash integer using Bitcoin numeric encoding
        """
        return self.value.to_bytes(1, "little")

    def for_hashing(self):
        """
        Encodes the sighash integer using BTCNum encoding and padded to 4 bytes
        """
        return self.value.to_bytes(4, "little")


def get_legacy_sighash_preimage(tx: Tx, input_index: int, scriptpubkey: bytes, sighash_num: int = 1) -> bytes:
    """Return the exact legacy transaction bytes committed to by a signature.

    This implements the transaction transformations used by Bitcoin's original
    signature-hash algorithm, including ``NONE``, ``SINGLE``, and
    ``ANYONECANPAY``.  ``SIGHASH_SINGLE`` without a corresponding output has no
    preimage because consensus returns the historical ``uint256::ONE`` value
    directly; callers should use :func:`get_legacy_sighash` for that case.
    """
    if any(t is None for t in [tx, input_index, sighash_num, scriptpubkey]):
        raise SignatureError("Insufficient context items for legacy signature hash")
    if not isinstance(input_index, int) or not 0 <= input_index < len(tx.inputs):
        raise SignatureError("Legacy signature hash input index is out of range")
    if not isinstance(sighash_num, int) or not 0 <= sighash_num <= 0xFF:
        raise SignatureError("Legacy signature hash type must fit in one byte")

    base_type = sighash_num & 0x1F
    if base_type == SigHash.SINGLE and input_index >= len(tx.outputs):
        raise SignatureError("SIGHASH_SINGLE has no corresponding output preimage")

    tx_copy = tx.clone()
    for tx_input in tx_copy.inputs:
        tx_input.scriptsig = bytes()
    tx_copy.inputs[input_index].scriptsig = scriptpubkey

    if base_type == SigHash.NONE:
        tx_copy.outputs = []
        for index, tx_input in enumerate(tx_copy.inputs):
            if index != input_index:
                tx_input.sequence = 0
    elif base_type == SigHash.SINGLE:
        tx_copy.outputs = [TxOut(0xFFFFFFFFFFFFFFFF, b"") for _ in range(input_index)] + [
            tx_copy.outputs[input_index]
        ]
        for index, tx_input in enumerate(tx_copy.inputs):
            if index != input_index:
                tx_input.sequence = 0

    if sighash_num & 0x80:
        tx_copy.inputs = [tx_copy.inputs[input_index]]

    return tx_copy._get_txid_preimage() + sighash_num.to_bytes(4, "little")


def get_legacy_sighash(tx: Tx, input_index: int, scriptpubkey: bytes, sighash_num: int = 1):
    """
    Computes legacy message_hash for signing:
        1. Remove all existing script_sigs
        2. Put the script_pubkey from referenced output in the script_sig for the input.
        3. Append the sighash byte(s) at the end of the serialized tx data
        4. Hash the serialized tx data
    We require the following from the SignatureContext:
        script_code == scriptpubkey

    """
    if (
        isinstance(input_index, int)
        and isinstance(sighash_num, int)
        and (sighash_num & 0x1F) == SigHash.SINGLE
        and 0 <= input_index < len(tx.inputs)
        and input_index >= len(tx.outputs)
    ):
        return b"\x01" + b"\x00" * 31
    return hash256(get_legacy_sighash_preimage(tx, input_index, scriptpubkey, sighash_num))


def get_segwit_sighash(tx: Tx, input_index: int, amount: int, scriptpubkey: bytes, sighash_num:
int = 1):
    """
    We return the sighash for a segwit Transaction
    """
    # 1. Get copy of tx
    tx_copy = Tx.from_bytes(tx.to_bytes())

    # 2. Construct the preimage and preimage hash
    # 2-1. version
    serialized_version = tx_copy.version.to_bytes(TX.VERSION, "little")

    # 2-2. hash256(serialized txid+vout for all the inputs in the tx)
    serialized_inputs = b''.join([txin.outpoint for txin in tx_copy.inputs])
    hashed_inputs = hash256(serialized_inputs)

    # 2-3. Serialize and hash the sequence of each input
    serialized_sequences = b''.join([txin.sequence.to_bytes(TX.SEQUENCE, "little") for txin in tx_copy.inputs])
    hashed_sequences = hash256(serialized_sequences)

    # 2-4. Serialize the outpoint for the input we're signing
    my_input = tx_copy.inputs[input_index]
    my_input_outpoint = my_input.outpoint

    # 2-5. Create script for the input we're signing
    scriptcode = scriptpubkey  # Either P2WPKH or P2WSH. The latter is a witness script, the former is P2PKH

    # 2-6. Amount
    serialized_amount = amount.to_bytes(TX.AMOUNT, "little")

    # 2-7. My Sequence
    my_sequence = my_input.sequence.to_bytes(TX.SEQUENCE, "little")

    # 2-8. Serialized and hash all outputs
    serialized_outputs = b''.join([txout.to_bytes() for txout in tx_copy.outputs])
    hashed_outputs = hash256(serialized_outputs)

    # 2-9. Locktime
    serialized_locktime = tx_copy.locktime.to_bytes(TX.LOCKTIME, "little")

    # 2.10 Construct pre-image
    preimage = (
            serialized_version + hashed_inputs + hashed_sequences + my_input_outpoint + scriptcode +
            serialized_amount + my_sequence + hashed_outputs + serialized_locktime
    )

    # 2-11. Add signature hash type
    preimage_sighash = preimage + SigHash(sighash_num).for_hashing()

    return hash256(preimage_sighash)


def get_taproot_sighash(tx: Tx,
                        input_index: int,
                        utxos: list[UTXO],  # List of UTXOs for ALL inputs in order
                        ext_flag: int = 0,
                        sighash_num: int = 1,
                        annex: bytes = None,
                        leaf_hash: bytes = None,  # Necesary for script-path spend
                        codesep_pos: bytes = bytes.fromhex("ffffffff")):
    """
    We return the taproot sighash for any type of taproot spend

    NOTE: We expect the list of utxos to correspond to the list of inputs in the tx
    """
    # Copy tx
    tx_copy = Tx.from_bytes(tx.to_bytes())

    #  Get elements for pre-image
    hash_type = SigHash(sighash_num)
    hash_byte = hash_type.to_byte()
    version = tx_copy.version.to_bytes(TX.VERSION, "little")
    locktime = tx_copy.locktime.to_bytes(TX.LOCKTIME, "little")

    # --- TX ELEMENTS --- #
    _prevouts = b''.join([txin.outpoint for txin in tx_copy.inputs])
    _sequences = b''.join([txin.sequence.to_bytes(TX.SEQUENCE, "little") for txin in tx_copy.inputs])
    _outputs = b''.join([txout.to_bytes() for txout in tx_copy.outputs])

    # 1. Get context elements
    if ext_flag == 1:
        # Script-path spend
        amounts = [u.amount for u in utxos]
        scriptpubkeys = [u.scriptpubkey for u in utxos]
        _amounts = b''.join([a.to_bytes(TX.AMOUNT, "little") for a in amounts])
        _pubkeys = b''.join([write_compact_size(len(pubkey)) + pubkey for pubkey in scriptpubkeys])

    else:
        # Key-path spend
        utxo = utxos[0]
        amount = utxo.amount
        scriptpubkey = utxo.scriptpubkey
        _amounts = amount.to_bytes(TX.AMOUNT, "little")
        _pubkeys = write_compact_size(len(scriptpubkey)) + scriptpubkey

    # --- HASHING --- #
    hash_prevouts = sha256(_prevouts)
    hash_amounts = sha256(_amounts)
    hash_pubkeys = sha256(_pubkeys)
    hash_outputs = sha256(_outputs)
    hash_sequences = sha256(_sequences)

    spend_type_int = (2 * ext_flag) + (1 if annex else 0)
    spend_type = spend_type_int.to_bytes(1, "little")

    # Input specific
    temp_input = tx_copy.inputs[input_index]
    temp_utxo = utxos[input_index]
    input_outpoint = temp_input.outpoint
    input_amount = temp_utxo.amount.to_bytes(TX.AMOUNT, "little")  # From signature Context
    input_scriptpubkey = temp_utxo.scriptpubkey
    input_sequence = temp_input.sequence.to_bytes(TX.SEQUENCE, "little")
    input_index_bytes = input_index.to_bytes(TX.INDEX, "little")

    hash_annex = b''
    if annex:
        hash_annex = sha256(
            write_compact_size(len(annex)) + annex
        )

    hash_single_output = sha256(tx_copy.outputs[input_index].to_bytes())

    # 3. Assemble message for TapSighash hash function
    message = hash_byte + version + locktime

    if hash_type not in [SigHash.ALL_ANYONECANPAY, SigHash.NONE_ANYONECANPAY, SigHash.SINGLE_ANYONECANPAY]:
        # Not an ANYONECANPAY Sighash
        message += hash_prevouts + hash_amounts + hash_pubkeys + hash_sequences

        # Sighash.ALL
        if hash_type == SigHash.ALL:
            message += hash_outputs

        # Spend type and annex
        message += spend_type + input_index_bytes + hash_annex

        # Sighash.SINGLE
        if hash_type == SigHash.SINGLE:
            message += hash_single_output
    else:
        # ANYONECANPAY
        message += spend_type + input_outpoint + input_amount + input_scriptpubkey + input_sequence + hash_annex

    # Get sighash_epoch and create extension if necessary
    extension = b''
    if ext_flag:
        # leaf_hash = ctx.merkle_root if ctx.leaf_hash is None else ctx.leaf_hash
        extension = leaf_hash + TAPROOT.PUBKEY_VERSION + codesep_pos

    sighash_epoch = TAPROOT.SIGHASH_EPOCH
    return tapsighash_hash(sighash_epoch + message + extension)


# --- Schnorr --- #
def get_schnorr_sig(priv_key: int, msg: bytes, aux_bytes: bytes = None) -> bytes:
    # Validation here
    return schnorr_sig(priv_key, msg, aux_bytes)


def verify_schnorr_sig(xonly_pubkey: int | bytes, msg: bytes, sig: bytes) -> bool:
    # Validation here
    return schnorr_verify(xonly_pubkey, msg, sig)


# --- ECDSA --- #
def get_ecdsa_sig(private_key: int, message: bytes):
    """
    Returns DER-encoded ECDSA signature
    """
    # Validation here
    r, s = ecdsa(private_key, message)
    return encode_der_signature(r, s)


def _decode_lax_der_signature(signature: bytes) -> tuple[int, int]:
    """
    Parse the historical non-strict DER forms accepted before BIP66.

    This follows Bitcoin Core's bounded lax parser: sequence lengths are
    ignored, long-form integer lengths are accepted, redundant zero padding
    and trailing garbage are tolerated, and values larger than 32 bytes are
    converted to an invalid zero signature.
    """
    position = 0

    def read_byte() -> int:
        nonlocal position
        if position >= len(signature):
            raise ValueError("Truncated DER signature")
        value = signature[position]
        position += 1
        return value

    def read_length() -> int:
        nonlocal position
        length = read_byte()
        if not length & 0x80:
            return length

        length_bytes = length & 0x7f
        if length_bytes > len(signature) - position:
            raise ValueError("Truncated DER length")
        while length_bytes > 0 and signature[position] == 0:
            position += 1
            length_bytes -= 1
        if length_bytes >= 4:
            raise ValueError("DER length is too large")

        value = 0
        for _ in range(length_bytes):
            value = (value << 8) | read_byte()
        return value

    if read_byte() != 0x30:
        raise ValueError("DER signature is not a sequence")
    sequence_length = read_byte()
    if sequence_length & 0x80:
        descriptor_bytes = sequence_length & 0x7f
        if descriptor_bytes > len(signature) - position:
            raise ValueError("Truncated DER sequence length")
        position += descriptor_bytes

    values: list[int] = []
    for _ in range(2):
        if read_byte() != 0x02:
            raise ValueError("DER signature value is not an integer")
        value_length = read_length()
        if value_length > len(signature) - position:
            raise ValueError("Truncated DER integer")
        raw_value = signature[position:position + value_length]
        position += value_length
        raw_value = raw_value.lstrip(b"\x00")
        if len(raw_value) > 32:
            return 0, 0
        values.append(int.from_bytes(raw_value, "big"))

    return values[0], values[1]


def verify_ecdsa_sig(
        signature: bytes,
        message: bytes,
        public_key: bytes,
        *,
        strict_der: bool = True,
) -> bool:
    try:
        signature_tuple = (
            decode_der_signature(signature)
            if strict_der
            else _decode_lax_der_signature(signature)
        )
        pubkey = PubKey.from_bytes(public_key)
        return verify_ecdsa(signature_tuple, message, pubkey.to_point())
    except (TypeError, ValueError):
        return False
