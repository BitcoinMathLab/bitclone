"""Stable byte-range inspection for canonical transaction serializations."""
from __future__ import annotations

from dataclasses import dataclass

from src.core import TX, write_compact_size
from src.tx.tx import Tx

__all__ = ["TransactionByteField", "inspect_transaction_bytes"]


@dataclass(frozen=True, slots=True)
class TransactionByteField:
    id: str
    label: str
    group: str
    offset: int
    length: int
    hex: str
    decoded: str


class _Inspector:
    def __init__(self, transaction: Tx) -> None:
        self.transaction = transaction
        self.offset = 0
        self.fields: list[TransactionByteField] = []

    def inspect(self) -> tuple[TransactionByteField, ...]:
        tx = self.transaction
        self._add("version", "Version", "header", tx.version.to_bytes(TX.VERSION, "little"), str(tx.version))
        if tx.is_segwit:
            self._add("marker-flag", "SegWit marker and flag", "header", b"\x00\x01", "Witness serialization")

        self._compact("input-count", "Input count", "header", len(tx.inputs))
        for index, tx_input in enumerate(tx.inputs):
            display = index + 1
            self._add(
                f"input-{index}-previous-txid",
                f"Input {display} previous txid",
                "input",
                tx_input.txid,
                tx_input.txid[::-1].hex(),
            )
            vout = tx_input.vout
            vout_decoded = (
                f"{vout} (coinbase marker)"
                if tx_input.txid == bytes(TX.TXID) and vout == 0xFFFFFFFF
                else str(vout)
            )
            self._add(
                f"input-{index}-vout",
                f"Input {display} previous output index",
                "input",
                vout.to_bytes(TX.VOUT, "little"),
                vout_decoded,
            )
            self._compact(
                f"input-{index}-script-length",
                f"Input {display} scriptSig length",
                "input",
                len(tx_input.scriptsig),
            )
            if tx_input.scriptsig:
                self._add(
                    f"input-{index}-script-sig",
                    f"Input {display} scriptSig",
                    "input",
                    tx_input.scriptsig,
                    f"{len(tx_input.scriptsig)} bytes",
                )
            self._add(
                f"input-{index}-sequence",
                f"Input {display} sequence",
                "input",
                tx_input.sequence.to_bytes(TX.SEQUENCE, "little"),
                _describe_sequence(tx_input.sequence),
            )

        self._compact("output-count", "Output count", "header", len(tx.outputs))
        for index, tx_output in enumerate(tx.outputs):
            display = index + 1
            self._add(
                f"output-{index}-amount",
                f"Output {display} amount",
                "output",
                tx_output.amount.to_bytes(TX.AMOUNT, "little"),
                f"{tx_output.amount} sats",
            )
            self._compact(
                f"output-{index}-script-length",
                f"Output {display} locking-script length",
                "output",
                len(tx_output.scriptpubkey),
            )
            if tx_output.scriptpubkey:
                self._add(
                    f"output-{index}-script-pubkey",
                    f"Output {display} locking script",
                    "output",
                    tx_output.scriptpubkey,
                    f"{len(tx_output.scriptpubkey)} bytes",
                )

        if tx.is_segwit:
            for input_index, witness in enumerate(tx.witness):
                display = input_index + 1
                self._compact(
                    f"input-{input_index}-witness-count",
                    f"Input {display} witness item count",
                    "witness",
                    len(witness.items),
                )
                for item_index, item in enumerate(witness.items):
                    self._compact(
                        f"input-{input_index}-witness-{item_index}-length",
                        f"Input {display} witness item {item_index + 1} length",
                        "witness",
                        len(item),
                    )
                    if item:
                        self._add(
                            f"input-{input_index}-witness-{item_index}",
                            f"Input {display} witness item {item_index + 1}",
                            "witness",
                            item,
                            f"{len(item)} bytes",
                        )

        self._add(
            "locktime",
            "Locktime",
            "footer",
            tx.locktime.to_bytes(TX.LOCKTIME, "little"),
            _describe_locktime(tx.locktime),
        )
        if self.offset != len(tx.to_bytes()):
            raise ValueError("Transaction byte inspection did not cover the canonical serialization")
        return tuple(self.fields)

    def _compact(self, field_id: str, label: str, group: str, value: int) -> None:
        self._add(field_id, label, group, write_compact_size(value), str(value))

    def _add(self, field_id: str, label: str, group: str, raw: bytes, decoded: str) -> None:
        self.fields.append(
            TransactionByteField(
                id=field_id,
                label=label,
                group=group,
                offset=self.offset,
                length=len(raw),
                hex=raw.hex(),
                decoded=decoded,
            )
        )
        self.offset += len(raw)


def inspect_transaction_bytes(transaction: Tx) -> tuple[TransactionByteField, ...]:
    """Map every byte of a canonical transaction to its serialized field."""
    return _Inspector(transaction).inspect()


def _describe_sequence(sequence: int) -> str:
    if sequence == 0xFFFFFFFF:
        return f"{sequence} (final)"
    if sequence & 0x80000000:
        return f"{sequence} (relative locktime disabled)"
    value = sequence & 0xFFFF
    if sequence & 0x00400000:
        return f"{sequence} ({value} × 512 seconds relative locktime)"
    return f"{sequence} ({value} block relative locktime)"


def _describe_locktime(locktime: int) -> str:
    if locktime == 0:
        return "0 (disabled)"
    if locktime < 500_000_000:
        return f"{locktime} (block height)"
    return f"{locktime} (Unix timestamp)"
