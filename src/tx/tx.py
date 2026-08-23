"""
The classes for BitClone transactions
"""
import re
from io import SEEK_CUR

from src.core import (Serializable, SERIALIZED, TransactionError, get_stream, read_little_int, read_stream, TX,
                      deserialize_data, serialize_data, read_compact_size, write_compact_size, UTXO_SERIAL)
from src.core.logging import get_logger
from src.cryptography import hash256

logger = get_logger(__name__)
__all__ = ["TxIn", "TxOut", "Witness", "Tx", "UTXO", "LoadedTx"]

# --- CACHE KEYS --- #
SEGWIT_KEY = "is_segwit"
TXID_KEY = "txid"
WTXID_KEY = "wtxid"
WU_KEY = "weight_units"
VB_KEY = "virtual_bytes"
COINBASE_KEY = "is_coinbase"


class TxIn(Serializable):
    """
    =============================================================================
    |   name            |   datatype    |   serialzed format    |   byte size   |
    =============================================================================
    |   txid            |   bytes       |   natural byte order  |   32          |
    |   vout            |   int         |   little-endian       |   4           |
    |   scriptsig_size  |   int         |   compactSize         |   var         |
    |   scriptsig       |   bytes       |   script bytes        |   var         |
    |   sequence        |   int         |   little-endian       |   4           |
    =============================================================================
    """
    __slots__ = ("txid", "vout", "scriptsig", "sequence")

    def __init__(self, txid: bytes, vout: int | bytes, scriptsig: bytes, sequence: int | bytes):
        self.txid = txid
        self.vout = vout if isinstance(vout, int) else int.from_bytes(vout, "little")
        self.scriptsig = scriptsig
        self.sequence = sequence if isinstance(sequence, int) else int.from_bytes(sequence, "little")

    @property
    def outpoint(self):
        return self.txid + self.vout.to_bytes(TX.VOUT, "little")

    @classmethod
    def from_bytes(cls, byte_stream: SERIALIZED):
        stream = get_stream(byte_stream)

        txid = read_stream(stream, TX.TXID, "txid")
        vout = read_little_int(stream, TX.VOUT, "vout")
        scriptsig_size = read_compact_size(stream)
        scriptsig = read_stream(stream, scriptsig_size, "scriptsig")
        sequence = read_little_int(stream, TX.SEQUENCE, "sequence")

        return cls(txid, vout, scriptsig, sequence)

    def to_bytes(self) -> bytes:
        """
        Serialize input
        txid || vout || scriptsig_size || scriptsig || sequence
        """
        parts = [
            self.txid,
            self.vout.to_bytes(TX.VOUT, "little"),
            write_compact_size(len(self.scriptsig)),
            self.scriptsig,
            self.sequence.to_bytes(TX.SEQUENCE, "little")
        ]
        return b''.join(parts)

    def to_dict(self) -> dict:
        ss_len = len(self.scriptsig)
        return {
            "txid": self.txid.hex(),  # little-endian (natural byte order)
            "vout": self.vout.to_bytes(TX.VOUT, "little").hex(),
            "scriptsig_size": write_compact_size(ss_len).hex(),
            "scriptsig": self.scriptsig.hex(),
            "sequence": self.sequence.to_bytes(TX.SEQUENCE, "little").hex()
        }

    def to_data(self, is_coinbase: bool = False) -> dict:
        ss_len = len(self.scriptsig)
        decoded_scriptsig = self._decode_scriptsig()
        return {
            "txid": self.txid[::-1].hex(),  # big-endian for display
            "vout": self.vout,
            "scriptsig_size": ss_len,
            "scriptsig": self.scriptsig.hex() if not is_coinbase or decoded_scriptsig is None else decoded_scriptsig,
            "sequence": self.sequence
        }

    def _decode_scriptsig(self) -> str | None:
        """
        To be called whenever the is_coinbase var is true in the to_dict method
        """
        try:
            decoded = self.scriptsig.decode("latin-1")  # latin-1 so it doesn't throw on arbitrary bytes
        except Exception as e:
            logger.error(f"Decode scriptsig fails: {e}")
            return None
        printable = ''.join(c for c in decoded if 32 <= ord(c) <= 126)
        match = re.search(r'[A-Za-z].{20,}', printable)
        return match.group(0).strip() if match else None


class TxOut(Serializable):
    """
    =============================================================================
    |   name            |   datatype    |   serialzed format    |   byte size   |
    =============================================================================
    |   amount          |   int         |   little-endian       |   8           |
    |   scriptlen       |   int         |   compactSize         |   vatInt      |
    |   scriptpubkey    |   bytes       |   bytes               |   var         |
    =============================================================================
    """
    __slots__ = ("amount", "scriptpubkey")

    def __init__(self, amount: int | bytes, scriptpubkey: bytes):
        self.amount: int = amount if isinstance(amount, int) else int.from_bytes(amount, "little")
        self.scriptpubkey = scriptpubkey

    @classmethod
    def from_bytes(cls, byte_stream: SERIALIZED):
        stream = get_stream(byte_stream)

        amount = read_little_int(stream, TX.AMOUNT)
        scriptpubkey = deserialize_data(stream)

        return cls(amount, scriptpubkey)

    def to_bytes(self) -> bytes:
        """
        Serializt the TxOutput
        amount || scriptpubkey_size || scriptpubkey
        """
        return self.amount.to_bytes(TX.AMOUNT, "little") + serialize_data(self.scriptpubkey)

    def to_dict(self) -> dict:
        scriptpubkey_len = len(self.scriptpubkey)
        return {
            "amount": self.amount.to_bytes(TX.AMOUNT, "little").hex(),
            "scriptpubkey_size": write_compact_size(scriptpubkey_len).hex(),
            "scriptpubkey": self.scriptpubkey.hex()
        }

    def to_data(self) -> dict:
        scriptpubkey_len = len(self.scriptpubkey)
        return {
            "amount": self.amount,
            "scriptpubkey_size": scriptpubkey_len,
            "scriptpubkey": self.scriptpubkey.hex()
        }


class Witness(Serializable):
    """
    WitnessField
    =================================================================================
    |   name            |   datatype    |   serialzed format        |   byte size   |
    =================================================================================
    |   stack_items     |   int         |   compactSize             |   varInt      |
    |   item*           |   bytes       |   serialized_data(item)   |   varInt      |
    =================================================================================
    *Each item in the Witness is serialized with a leading compactSize value indicating the item size
    """
    __slots__ = ("items",)

    def __init__(self, items: list | bytes):
        self.items = items if isinstance(items, list) else [items]

    @classmethod
    def from_bytes(cls, byte_stream: SERIALIZED):
        stream = get_stream(byte_stream)

        # Number of stack items
        stack_items = read_compact_size(stream)

        # Get items
        witness_items = [deserialize_data(stream) for _ in range(stack_items)]
        return cls(witness_items)

    def to_bytes(self) -> bytes:
        """
        Serialize the stack items
        """
        stack_items = len(self.items)
        item_bytes = b''.join([serialize_data(item) for item in self.items])
        return write_compact_size(stack_items) + item_bytes

    def to_dict(self) -> dict:
        stack_items = len(self.items)
        items_dict = {}

        for x, item in enumerate(self.items):
            size = len(item)
            items_dict[str(x)] = {
                "size": write_compact_size(size).hex(),
                "item": item.hex(),
            }

        return {
            "stack_items": write_compact_size(stack_items).hex(),
            "items": items_dict,
        }

    def to_data(self) -> dict:
        stack_items = len(self.items)
        items_dict = {}

        for x, item in enumerate(self.items):
            items_dict[str(x)] = {
                "size": len(item),
                "item": item.hex(),
            }

        return {
            "stack_items": stack_items,
            "items": items_dict,
        }


class UTXO(Serializable):
    """
    Unspent Transaction Output - represents a spendable output
    =============================================================================
    |   name            |   datatype    |   serialzed format    |   byte size   |
    =============================================================================
    |   outpoint        |   bytes       |   natural byte order  |   36          |
    |   amount          |   int         |   little-endian       |   8           |
    |   script_len      |   int         |   compactSize         |   varInt      |
    |   scriptpubkey    |   bytes       |   natural byte order  |   varInt      |
    |   block_height    |   int         |   little-endian       |   4           |
    |   is_coinbase     |   bool        |   little-endian       |   1           |
    =============================================================================
    # is_coinbase uses 0 = False, 1 = True for single byte int values
    """
    __slots__ = ("outpoint", "amount", "scriptpubkey", "block_height", "is_coinbase")

    def __init__(self, outpoint: bytes, amount: int, scriptpubkey: bytes,
                 block_height: int, is_coinbase: bool = False):
        self.outpoint = outpoint
        self.amount = amount
        self.scriptpubkey = scriptpubkey
        self.block_height = block_height
        self.is_coinbase = is_coinbase

    @classmethod
    def from_txoutput(cls, outpoint: bytes, txoutput: TxOut,
                      block_height: int, is_coinbase: bool = False):
        """Create UTXO from a TxOutput"""
        return cls(outpoint, txoutput.amount, txoutput.scriptpubkey,
                   block_height, is_coinbase)

    @classmethod
    def from_bytes(cls, byte_stream: SERIALIZED):
        stream = get_stream(byte_stream)

        outpoint = read_stream(stream, UTXO_SERIAL.OUTPOINT)
        amount = read_little_int(stream, UTXO_SERIAL.AMOUNT)
        script_len = read_compact_size(stream)
        scriptpubkey = read_stream(stream, script_len)
        block_height = read_little_int(stream, UTXO_SERIAL.HEIGHT)
        is_coinbase = bool(read_little_int(stream, UTXO_SERIAL.IS_COINBASE))

        return cls(outpoint, amount, scriptpubkey, block_height, is_coinbase)

    def to_bytes(self) -> bytes:
        script_len = len(self.scriptpubkey)
        parts = [
            self.outpoint, self.amount.to_bytes(UTXO_SERIAL.AMOUNT, "little"), write_compact_size(script_len),
            self.scriptpubkey, self.block_height.to_bytes(UTXO_SERIAL.HEIGHT, "little"),
            int(self.is_coinbase).to_bytes(UTXO_SERIAL.IS_COINBASE, "little")
        ]
        return b''.join(parts)

    def to_dict(self) -> dict:
        txid = self.outpoint[:TX.TXID]
        vout = self.outpoint[TX.TXID:]
        return {
            "outpoint": self.outpoint.hex(),
            "txid": txid.hex(),  # little-endian (natural byte order)
            "vout": vout.hex(),
            "amount": self.amount.to_bytes(UTXO_SERIAL.AMOUNT, "little").hex(),
            "scriptpubkey": self.scriptpubkey.hex(),
            "block_height": self.block_height.to_bytes(UTXO_SERIAL.HEIGHT, "little").hex(),
            "is_coinbase": int(self.is_coinbase).to_bytes(UTXO_SERIAL.IS_COINBASE, "little").hex()
        }

    def to_data(self) -> dict:
        txid = self.outpoint[:TX.TXID]
        vout = self.outpoint[TX.TXID:]
        return {
            "outpoint": self.outpoint.hex(),
            "txid": txid[::-1].hex(),  # big-endian for display
            "vout": int.from_bytes(vout, "little"),
            "amount": self.amount,
            "scriptpubkey": self.scriptpubkey.hex(),
            "block_height": self.block_height,
            "is_coinbase": self.is_coinbase
        }


class Tx(Serializable):
    """
    Transaction
    =============================================================================
    |   name            |   datatype    |   serialzed format    |   byte size   |
    =============================================================================
    |   version         |   int         |   little-endian       |   4           |
    |   marker*         |   bytes       |   little-endian       |   1           |
    |   flag*           |   bytes       |   little-endian       |   1           |
    |   input_count     |   int         |   compactSize         |   var         |
    |   inputs          |   list        |   TxIn.to_bytes()     |   var         |
    |   output_count    |   int         |   compactSize         |   var         |
    |   outputs         |   list        |   TxOut.to_bytes()    |   var         |
    |   witness         |   Witness     |   Witness.to_bytes()  |   var         |
    =============================================================================
    * indicates optional segwit specific fields
    """
    __slots__ = ("version", "inputs", "outputs", "locktime", "witness", "_cache")

    def __init__(self, inputs: list[TxIn] = None, outputs: list[TxOut] = None, witness: list[Witness] = None,
                 locktime: int = 0, version: int = TX.BIP68_VERSION):
        self.inputs = inputs or []
        self.outputs = outputs or []
        self.witness = witness or []
        self.version = version
        self.locktime = locktime
        self._cache = {}  # Internal dict for future values

    def _update_cache(self):
        """
        Run those functions which contribute to the _cache dict
        """
        _ = self.is_segwit
        _ = self.txid

    def _invalidate_cache(self):
        """
        Remove all cache values
        """
        self._cache = {}

    def _get_txid_preimage(self) -> bytes:
        """
        For a given transaction, return what will need to be hashed to yield the tx id
        For segwit, this is the formatted version, inputs, outpus and locktiem
        For non-segwit this is the serialized tx itself
        """
        if self.is_segwit:
            parts = [
                self.version.to_bytes(TX.VERSION, "little"),
                self._get_input_bytes(),
                self._get_output_bytes(),
                self.locktime.to_bytes(TX.LOCKTIME, "little")
            ]
            return b''.join(parts)

        # Legacy TX
        return self.to_bytes()

    def _get_wtxid_preimage(self) -> bytes:
        if self.is_segwit:
            parts = [
                self.version.to_bytes(TX.VERSION, "little"),
                b'\x00\x01',  # Marker\Flag
                self._get_input_bytes(),
                self._get_output_bytes(),
                self.locktime.to_bytes(TX.LOCKTIME, "little"),
                self._get_witness_bytes()
            ]
            return b''.join(parts)
        # Legacy TX
        return self.to_bytes()

    def _get_input_bytes(self) -> bytes:
        """
        Returns the serialized inputs, including input_num
        """
        input_num = len(self.inputs)
        return write_compact_size(input_num) + b''.join([i.to_bytes() for i in self.inputs])

    def _get_output_bytes(self) -> bytes:
        """
        Returns the serialized inputs, including input_num
        """
        output_num = len(self.outputs)
        return write_compact_size(output_num) + b''.join([t.to_bytes() for t in self.outputs])

    def _get_witness_bytes(self) -> bytes:
        """
        Returns the serialized witness
        """
        return b''.join([w.to_bytes() for w in self.witness])

    def get_utxo_list(self, block_height: int) -> list[UTXO]:
        """
        We generate UTXOs for the current tx and all its inputs
        """
        utxo_list = []
        for vout in range(0, len(self.outputs)):
            temp_output = self.outputs[vout]
            utxo_list.append(UTXO(
                outpoint=self.txid + vout.to_bytes(TX.VOUT, "little"),
                amount=temp_output.amount,
                scriptpubkey=temp_output.scriptpubkey,
                block_height=block_height,
                is_coinbase=False  # Coinbase will have their own Tx type
            ))
        return utxo_list

    @property
    def is_coinbase(self):
        if COINBASE_KEY not in self._cache:
            truth_list = [
                len(self.inputs) == 1,
                self.inputs[0].txid == b'\x00' * TX.TXID,
                self.inputs[0].vout == 0xffffffff
            ]
            self._cache[COINBASE_KEY] = all(truth_list)
        return self._cache[COINBASE_KEY]

    @property
    def is_segwit(self):
        """
        True if the witness_list is populated or if any of the inputs don't have a scriptsig (tx to be signed)
        """
        if SEGWIT_KEY not in self._cache:
            self._cache[SEGWIT_KEY] = len(self.witness) > 0
        return self._cache[SEGWIT_KEY]

    @property
    def txid(self):
        """
        Return cached txid if it exists. Otherwise, return new txid
        """
        if TXID_KEY not in self._cache:
            txid_preimage = self._get_txid_preimage()
            self._cache[TXID_KEY] = hash256(txid_preimage)
        return self._cache[TXID_KEY]

    @property
    def wtxid(self):
        """
        Return cached wtxid if it exists. Otherwise, return new txid
        """
        if WTXID_KEY not in self._cache:
            wtxid_preimage = self._get_wtxid_preimage()
            self._cache[WTXID_KEY] = hash256(wtxid_preimage)
        return self._cache[WTXID_KEY]

    @property
    def wu(self):
        """
        Returns size of tx in terms of weight units
        """
        if WU_KEY not in self._cache:
            if self.is_segwit:
                input_length = 0
                output_length = 0
                witness_length = 0
                for i in self.inputs:
                    input_length += i.length
                for o in self.outputs:
                    output_length += o.length
                for w in self.witness:
                    witness_length += w.length

                input_num = len(write_compact_size(len(self.inputs)))
                output_num = len(write_compact_size(len(self.outputs)))

                self._cache[WU_KEY] = 4 * (TX.VERSION + input_num + input_length + output_num + output_length +
                                           TX.LOCKTIME) + (witness_length + TX.MARKERFLAG)
            else:
                self._cache[WU_KEY] = self.length * 4
        return self._cache[WU_KEY]

    @property
    def vbytes(self):
        """Return BIP 141 virtual transaction size, rounded up to a whole vbyte."""
        return (self.wu + 3) // 4

    @classmethod
    def from_bytes(cls, byte_stream: SERIALIZED):
        stream = get_stream(byte_stream)

        # Version
        version = read_little_int(stream, TX.VERSION, "version")

        # Marker/Flag
        marker = stream.read(1)
        if marker == b'\x00':
            flag = stream.read(1)
            if flag != b'\x01':
                raise ValueError("Invalid SegWit flag.")
            segwit = True
        else:
            segwit = False
            stream.seek(-1, SEEK_CUR)  # Rewind the marker byte

        # Read inputs
        num_inputs = read_compact_size(stream)
        inputs = []
        for _ in range(num_inputs):
            inputs.append(TxIn.from_bytes(stream))

        # Read outputs
        num_outputs = read_compact_size(stream)
        outputs = []
        for _ in range(num_outputs):
            outputs.append(TxOut.from_bytes(stream))

        # Read witness if segwit
        witness = []
        if segwit:
            for _ in range(num_inputs):
                witness.append(Witness.from_bytes(stream))

        # Locktime
        locktime = read_little_int(stream, TX.LOCKTIME, "locktime")

        return cls(inputs, outputs, witness, locktime, version, )

    def to_bytes(self) -> bytes:
        """
        Serialize the tx
        """
        # Get counts ahead of time
        input_num = len(self.inputs)
        output_num = len(self.outputs)

        # Version
        parts = [
            self.version.to_bytes(TX.VERSION, "little"),
        ]

        # Marker/Flag
        if self.is_segwit:
            parts.append(b'\x00\x01')  # Fixed MarkerFlag

        # Inputs/Outputs
        parts.append(self._get_input_bytes())
        parts.append(self._get_output_bytes())

        # Witness
        if self.is_segwit:
            parts.append(self._get_witness_bytes())

        # Locktime
        parts.append(self.locktime.to_bytes(TX.LOCKTIME, "little"))

        return b''.join(parts)

    def to_dict(self) -> dict:
        inputs = [i.to_dict() for i in self.inputs]
        outputs = [o.to_dict() for o in self.outputs]

        tx_dict = {
            "txid": self.txid.hex(),  # little-endian (natural byte order)
            "wtxid": self.wtxid.hex(),
            "wu": self.wu,
            "bytes": self.length,
            "vbytes": self.vbytes,
            "version": self.version.to_bytes(TX.VERSION, "little").hex()
        }

        if self.is_segwit:
            tx_dict.update({"marker": "00", "flag": "01"})

        tx_dict.update({
            "input_num": write_compact_size(len(self.inputs)).hex(),
            "inputs": inputs,
            "output_num": write_compact_size(len(self.outputs)).hex(),
            "outputs": outputs
        })

        if self.is_segwit:
            tx_dict.update({"witness": [w.to_dict() for w in self.witness]})

        tx_dict.update({
            "locktime": self.locktime.to_bytes(TX.LOCKTIME, "little").hex(),
            "is_segwit": self.is_segwit,
            "is_coinbase": self.is_coinbase
        })
        return tx_dict

    def to_data(self) -> dict:
        inputs = [i.to_data(self.is_coinbase) for i in self.inputs]
        outputs = [o.to_data() for o in self.outputs]

        tx_dict = {
            "txid": self.txid[::-1].hex(),  # big-endian for display
            "wtxid": self.wtxid[::-1].hex(),
            "wu": self.wu,
            "bytes": self.length,
            "vbytes": self.vbytes,
            "version": self.version
        }

        if self.is_segwit:
            tx_dict.update({"marker": 0x00, "flag": 0x01})

        tx_dict.update({
            "input_num": len(self.inputs),
            "inputs": inputs,
            "output_num": len(self.outputs),
            "outputs": outputs
        })

        if self.is_segwit:
            tx_dict.update({"witness": [w.to_data() for w in self.witness]})

        tx_dict.update({
            "locktime": self.locktime,
            "is_segwit": self.is_segwit,
            "is_coinbase": self.is_coinbase
        })
        return tx_dict


class LoadedTx:
    """
    A transaction bundled with the UTXOs spent by its inputs.

    The UTXOs must be complete and in the same order as ``tx.inputs``. Keeping
    that invariant here lets validation code pass one object around instead of
    repeatedly trusting that separate ``tx`` and ``utxos`` values stayed aligned.
    """
    __slots__ = ("tx", "utxos")

    def __init__(self, tx: Tx, utxos: list[UTXO] | UTXO):
        if utxos is None:
            raise ValueError("LoadedTx requires referenced UTXOs")

        utxos = utxos if isinstance(utxos, list) else [utxos]

        if len(utxos) != len(tx.inputs):
            raise ValueError(
                f"LoadedTx requires one UTXO per input: got {len(utxos)} UTXO(s) for {len(tx.inputs)} input(s)"
            )

        for i, (txin, utxo) in enumerate(zip(tx.inputs, utxos)):
            if utxo.outpoint != txin.outpoint:
                raise ValueError(
                    f"UTXO at index {i} has outpoint {utxo.outpoint.hex()}, "
                    f"expected {txin.outpoint.hex()}"
                )

        self.tx = tx
        self.utxos = utxos

    @property
    def input_total(self) -> int:
        return sum(utxo.amount for utxo in self.utxos)

    @property
    def output_total(self) -> int:
        return sum(txout.amount for txout in self.tx.outputs)

    @property
    def fee(self) -> int:
        fee = self.input_total - self.output_total
        if fee < 0:
            raise TransactionError(
                f"Input total {self.input_total}, output total {self.output_total}. "
                f"Negative fee value: {-fee} for tx {self.tx.txid.hex()}"
            )
        return fee

    def utxo_for_input(self, input_index: int) -> UTXO:
        return self.utxos[input_index]


# -- TESTING ---
if __name__ == "__main__":
    sep = "===" * 50
    space = "\n\n"

    print(" --- TX FORMATTING VALIDATION ---")
    print(sep)

    # # TxInput
    test_tx_bytes = bytes.fromhex("0200000000010d4e5a75b4b55367073123ac4b351875be832a387a3f1aec4b508bdb3cdf231e02000000001716001402c8147af586cace7589672191bb1c790e9e9a72fdffffff419ea287480a53e96aaeb95db362eb4a608cabccb82ba78a701ea63a0b23af14000000001716001402c8147af586cace7589672191bb1c790e9e9a72fdffffff604b150686c6459235e69be6202154634639b81088d5f7011e31665c2a5a371f010000001716001402c8147af586cace7589672191bb1c790e9e9a72fdffffffe576dfe9c5c52146c666e2f554feb2dd2ad470cd03130a4b7ddaeef5ccfcc31f010000001716001402c8147af586cace7589672191bb1c790e9e9a72fdffffff0c3e97ca785fdf883b240bc7cbc407de6c4689aaf1368480fafabf6196702639000000001716001402c8147af586cace7589672191bb1c790e9e9a72fdffffff4529bc7981a486dae2cdf12a058816fac5a73ff283c8e2d3eb057da9b927d34c010000001716001402c8147af586cace7589672191bb1c790e9e9a72fdffffffa102354da66de20c297bd16eb5d01eef1460e0dcd6ffac5d415c7fdbc1b01b78410000001716001402c8147af586cace7589672191bb1c790e9e9a72fdffffff5fe060edff8c3317f86f4c0f3924f26d3614b72f2ed28461f6194d07daa3f587000000001716001402c8147af586cace7589672191bb1c790e9e9a72fdffffffa7b5e7eed6977fced331d6584dd2268c83c03b9bcf5959a0ebdf765c50f7e18f000000001716001402c8147af586cace7589672191bb1c790e9e9a72fdfffffff23eada5b5a698ce09738bd0d50f9fa5d0dbfcbf858f6452ca798f347c889ad9010000001716001402c8147af586cace7589672191bb1c790e9e9a72fdffffff775b6257bb283ceb283d313feb86a59eb1791f6f0cd370b584e1ca45642817e3000000001716001402c8147af586cace7589672191bb1c790e9e9a72fdffffff8d206dea8e821433af2a861ec6d37afcb643b8e2cd593673214e6f68e96913ea000000001716001402c8147af586cace7589672191bb1c790e9e9a72fdfffffffdc64af7edb03bca45cdb62cd605c7fc9f7bbacf928b46a075c9fbefcf2630ed000000008a4730440220730e055cefab7ac3120dd9e7fe7e9490c6b88b1dd2184635b15512e23d618d8302206f6aa6911e2e3ec348021633334c75b75486548fea38354e5aa772272e02a6cd01410408b281209f4e42f7a85a459eb19b65154a4eb078282bf58382f30eae58d249659cb67bc5e52afb23470dca828ff1193d43b46779d330332e3e1fd32955e5379bfdffffff010715990600000000160014907189739c6255dce21f61cc906707f949322add0247304402201f85ab44217563b4ce9d11e4c7b00dc59dd102099eb250634f4b6906276ba07702206147cc98f29c5fcbad925b5e40fe154f4d429f9569f292f9298f615c494004450121022ae7dd28111380c100301f5e9797383e291234c341d7a242202a6def9069181c024730440220346d5b3ef82fcd35618cce141925474cc4a652c2bbedc54605af267f08f98dad022020b630ea92f193d30f36841bfacdaf7f21d877745a01cd70fb6f1ed8726165680121022ae7dd28111380c100301f5e9797383e291234c341d7a242202a6def9069181c02473044022008e762cf7163c6adbd56d53648849fd6a606a65a4bd4888c3d8f55168afd13d002202778e6ac8eb2e6f35facef2e6fda07d7c39e44759a2c4e4253f895d02328b9900121022ae7dd28111380c100301f5e9797383e291234c341d7a242202a6def9069181c0247304402207cf547a4f22aec344ec1b3cc7db7c2a63db1a1a9b8626aaeb32c9b2546e361f5022053fe8dcbc1bd133765b5caf95ff9db5c34a4066b25acb2df2791e193c823cc370121022ae7dd28111380c100301f5e9797383e291234c341d7a242202a6def9069181c02473044022004c3c5517599fdf88c6209237a2b113cf4a4500538dfeee21c93f68c067319e202206a44299a0e9a45896f51d37a6b64d9587b6093a527fd8ccc129715fb4e3235e80121022ae7dd28111380c100301f5e9797383e291234c341d7a242202a6def9069181c0247304402206268b59fb737258d90be572e89edca479826986a2be599b20b6000c4c131ae8c02204ca861d33240d0dadeb437c4e849a700b455847609a810e6236a71cda58a8ba90121022ae7dd28111380c100301f5e9797383e291234c341d7a242202a6def9069181c0247304402205710dbfb624e0e05fe4b9874386c93084e88b89e16eb94608d6a92e451f5f3cd0220570367db12e3d07de3f08c735f3a3e719b6f78f87a7e20baf1f3db01764451bf0121022ae7dd28111380c100301f5e9797383e291234c341d7a242202a6def9069181c0247304402206d43fe58a74044fc81df8b10854a4067af4c7fe1b61992818c2bac30eb5cb28b02204a58491439771f897a087748df55e78b6d63a7105f83491aac408e446391dac70121022ae7dd28111380c100301f5e9797383e291234c341d7a242202a6def9069181c02473044022062599a99c5e7bcbce1fe649869cd017d7107a63550fa67c1677039f1ab4b593402201a4c271c3c0792d28d78338a97c3651de329e0cde31fb610157bf026f22b68e00121022ae7dd28111380c100301f5e9797383e291234c341d7a242202a6def9069181c0247304402207b7bfd5c8abf833d2a9b10f95749e596eab49fd77ce9237fcfbb804be492d3ed02207a85b47a0ba69e483dd411e4da9c0470b6bf21664096be160067dd674701980e0121022ae7dd28111380c100301f5e9797383e291234c341d7a242202a6def9069181c0247304402206d7db777e15bf1974aec93ce65d02802ded6ee2055dd890698e573f22b02f55e02206e21249c21f72700b583365ed111d1d172452175d8bb870e7076d6a4b3e529d50121022ae7dd28111380c100301f5e9797383e291234c341d7a242202a6def9069181c0247304402202af8e3170475f06e91a26fe2c666d745406b91b9a063ec0513062f0e982a219f02200d6f865b3dc4eae5fcb2eb11fc15cefdb5d0c4868f2dd2a17f981d3065e28f280121022ae7dd28111380c100301f5e9797383e291234c341d7a242202a6def9069181c0081a80c00")
    test_tx = Tx.from_bytes(test_tx_bytes)
    # print(f"TEST TX: {test_tx.to_json()}")
    print(f"TEST TX DISPLAY: {test_tx.to_display()}")
    
