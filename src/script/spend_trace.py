"""Transport-neutral orchestration for tracing supported Bitcoin spends."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from src.core import ScriptSigError, ScriptVerifyFlag
from src.script.context import ScriptValidationInput
from src.script.script_engine import ScriptEngine
from src.script.scriptpubkeys import P2PKH_Key
from src.script.scriptsigs import P2PKH_Sig
from src.script.trace import ExecutionTrace
from src.tx import LoadedTx, Tx, UTXO

__all__ = ["P2PKHTraceResult", "trace_p2pkh_spend"]


DEFAULT_TRACE_FLAGS = (
    ScriptVerifyFlag.P2SH
    | ScriptVerifyFlag.DERSIG
    | ScriptVerifyFlag.CHECKLOCKTIMEVERIFY
    | ScriptVerifyFlag.WITNESS
    | ScriptVerifyFlag.TAPROOT
)


@dataclass(frozen=True, slots=True)
class P2PKHTraceResult:
    """The immutable result of tracing one legacy P2PKH transaction input."""

    input_index: int
    unlocking_script: bytes
    locking_script: bytes
    trace: ExecutionTrace

    def __post_init__(self) -> None:
        if not isinstance(self.input_index, int) or isinstance(self.input_index, bool):
            raise TypeError("P2PKH trace input index must be an integer")
        if self.input_index < 0:
            raise ValueError("P2PKH trace input index cannot be negative")
        if not isinstance(self.unlocking_script, bytes):
            raise TypeError("P2PKH unlocking script must be bytes")
        if not isinstance(self.locking_script, bytes):
            raise TypeError("P2PKH locking script must be bytes")
        if not isinstance(self.trace, ExecutionTrace):
            raise TypeError("P2PKH trace must be an ExecutionTrace")
        if self.trace.script != self.combined_script:
            raise ValueError("P2PKH trace script must combine the unlocking and locking scripts")

    @property
    def combined_script(self) -> bytes:
        return self.unlocking_script + self.locking_script


def trace_p2pkh_spend(
        tx: Tx,
        input_index: int,
        spent_outputs: Iterable[UTXO],
        *,
        flags: ScriptVerifyFlag = DEFAULT_TRACE_FLAGS,
) -> P2PKHTraceResult:
    """Validate and trace one legacy P2PKH input.

    The caller supplies every spent output in transaction-input order. This keeps
    the boundary correct for multi-input transactions and ready for later witness
    and Taproot tracing, even though this story exposes P2PKH only.
    """
    if not isinstance(tx, Tx):
        raise TypeError("P2PKH tracing requires a Tx")
    if not isinstance(input_index, int) or isinstance(input_index, bool):
        raise TypeError("P2PKH trace input index must be an integer")
    if input_index < 0 or input_index >= len(tx.inputs):
        raise ValueError("P2PKH trace input index is outside the transaction inputs")
    if not isinstance(flags, ScriptVerifyFlag):
        raise TypeError("P2PKH trace flags must be ScriptVerifyFlag")

    outputs = tuple(spent_outputs)
    loaded_tx = LoadedTx(tx, list(outputs))
    spent_output = outputs[input_index]
    unlocking_script = tx.inputs[input_index].scriptsig
    locking_script = spent_output.scriptpubkey

    if len(locking_script) != 25 or not P2PKH_Key.matches(locking_script):
        raise ValueError("Selected spent output is not a legacy P2PKH script")
    try:
        P2PKH_Sig.from_bytes(unlocking_script)
    except (IndexError, ScriptSigError, TypeError) as exc:
        raise ValueError("Selected input does not contain a P2PKH scriptSig") from exc

    validation = ScriptValidationInput(
        tx=loaded_tx.tx,
        input_index=input_index,
        spent_outputs=tuple(loaded_tx.utxos),
        flags=flags,
    )
    context = validation.execution_context()
    engine = ScriptEngine()
    engine.validate_script(unlocking_script + locking_script, context, trace=True)
    if engine.last_trace is None:  # pragma: no cover - defensive invariant
        raise RuntimeError("P2PKH tracing completed without producing an execution trace")

    return P2PKHTraceResult(
        input_index=input_index,
        unlocking_script=unlocking_script,
        locking_script=locking_script,
        trace=engine.last_trace,
    )
