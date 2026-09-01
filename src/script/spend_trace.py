"""Transport-neutral orchestration for tracing supported Bitcoin spends."""
from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Iterable

from src.core import ScriptSigError, ScriptVerifyFlag
from src.core import serialize_data
from src.cryptography import hash160
from src.data import decode_der_signature
from src.script.context import ScriptValidationInput, SignatureVersion
from src.script.script_engine import ScriptEngine
from src.script.scriptpubkeys import P2PKH_Key, P2WPKH_Key
from src.script.scriptsigs import P2PKH_Sig
from src.script.sig_ops import (
    get_legacy_sighash,
    get_legacy_sighash_preimage,
    get_segwit_sighash,
    get_segwit_sighash_preimage,
    verify_ecdsa_sig,
)
from src.script.trace import ExecutionTrace, TraceDiagnostic
from src.tx import LoadedTx, Tx, UTXO

__all__ = [
    "ECDSASignatureVerificationResult",
    "P2PKHTraceResult",
    "P2WPKHTraceResult",
    "trace_p2pkh_spend",
    "trace_p2wpkh_spend",
    "verify_input_ecdsa_signature",
]


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


@dataclass(frozen=True, slots=True)
class P2WPKHTraceResult:
    """The immutable result of tracing one native witness-v0 P2WPKH input."""

    input_index: int
    witness: tuple[bytes, bytes]
    locking_script: bytes
    script_code: bytes
    trace: ExecutionTrace

    def __post_init__(self) -> None:
        if not isinstance(self.input_index, int) or isinstance(self.input_index, bool):
            raise TypeError("P2WPKH trace input index must be an integer")
        if self.input_index < 0:
            raise ValueError("P2WPKH trace input index cannot be negative")
        if len(self.witness) != 2 or any(not isinstance(item, bytes) for item in self.witness):
            raise ValueError("P2WPKH trace witness must contain signature and public key bytes")
        if not isinstance(self.locking_script, bytes) or not isinstance(self.script_code, bytes):
            raise TypeError("P2WPKH trace scripts must be bytes")
        if not isinstance(self.trace, ExecutionTrace):
            raise TypeError("P2WPKH trace must be an ExecutionTrace")
        if self.trace.script != self.script_code:
            raise ValueError("P2WPKH trace script must be the derived scriptCode")


@dataclass(frozen=True, slots=True)
class ECDSASignatureVerificationResult:
    """Verified message context for a caller-supplied DER signature."""

    input_index: int
    script_type: str
    signature: bytes
    public_key: bytes
    sighash_type: int
    preimage: bytes
    digest: bytes
    locking_script: bytes
    unlocking_script: bytes
    witness: tuple[bytes, ...]
    script_code: bytes | None
    amount: int | None
    valid: bool

    def __post_init__(self) -> None:
        if self.script_type not in {"P2PKH", "P2WPKH"}:
            raise ValueError("ECDSA verification supports P2PKH and P2WPKH")
        if len(self.digest) != 32:
            raise ValueError("ECDSA verification digest must contain 32 bytes")
        if not 0 <= self.sighash_type <= 0xFF:
            raise ValueError("ECDSA verification hash type must fit in one byte")


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


def trace_p2wpkh_spend(
        tx: Tx,
        input_index: int,
        spent_outputs: Iterable[UTXO],
        *,
        flags: ScriptVerifyFlag = DEFAULT_TRACE_FLAGS,
) -> P2WPKHTraceResult:
    """Validate and trace one native SegWit-v0 P2WPKH input."""
    if not isinstance(tx, Tx):
        raise TypeError("P2WPKH tracing requires a Tx")
    if not isinstance(input_index, int) or isinstance(input_index, bool):
        raise TypeError("P2WPKH trace input index must be an integer")
    if input_index < 0 or input_index >= len(tx.inputs):
        raise ValueError("P2WPKH trace input index is outside the transaction inputs")
    if not isinstance(flags, ScriptVerifyFlag):
        raise TypeError("P2WPKH trace flags must be ScriptVerifyFlag")

    outputs = tuple(spent_outputs)
    loaded_tx = LoadedTx(tx, list(outputs))
    spent_output = outputs[input_index]
    locking_script = spent_output.scriptpubkey
    if not P2WPKH_Key.matches(locking_script):
        raise ValueError("Selected spent output is not a native P2WPKH script")
    if tx.inputs[input_index].scriptsig:
        raise ValueError("Native P2WPKH input must have an empty scriptSig")
    if input_index >= len(tx.witness) or len(tx.witness[input_index].items) != 2:
        raise ValueError("P2WPKH witness must contain exactly a signature and public key")

    signature, public_key = tx.witness[input_index].items
    p2pkh_script = P2PKH_Key.from_pubkeyhash(locking_script[2:]).script
    serialized_script_code = serialize_data(p2pkh_script)
    validation = ScriptValidationInput(
        tx=loaded_tx.tx,
        input_index=input_index,
        spent_outputs=tuple(loaded_tx.utxos),
        flags=flags,
    )
    context = validation.execution_context(
        script_code=serialized_script_code,
        signature_version=SignatureVersion.WITNESS_V0,
    )
    engine = ScriptEngine()
    engine.stack.push(signature)
    engine.stack.push(public_key)
    executed = engine.execute_script(p2pkh_script, context, trace=True)
    stack_height = engine.stack.height
    valid = executed and engine.validate_stack()
    if engine.last_trace is None:  # pragma: no cover - defensive invariant
        raise RuntimeError("P2WPKH tracing completed without producing an execution trace")
    if not valid:
        if stack_height == 0:
            code, message = "empty-final-stack", "The script finished with an empty main stack."
        elif stack_height != 1:
            code, message = "unclean-final-stack", f"The script finished with {stack_height} items instead of exactly one."
        else:
            code, message = "false-final-value", "The script finished with a false value on top of the main stack."
        engine.last_trace = replace(
            engine.last_trace,
            success=False,
            diagnostic=engine.last_trace.diagnostic or TraceDiagnostic(code=code, message=message),
        )

    return P2WPKHTraceResult(
        input_index=input_index,
        witness=(signature, public_key),
        locking_script=locking_script,
        script_code=p2pkh_script,
        trace=engine.last_trace,
    )


def verify_input_ecdsa_signature(
        tx: Tx,
        input_index: int,
        spent_outputs: Iterable[UTXO],
        der_signature: bytes,
) -> ECDSASignatureVerificationResult:
    """Verify a strict-DER candidate against the message committed by an input.

    The public key and hash type come from the transaction's actual scriptSig or
    witness. The previous output determines whether the legacy or BIP143 message
    algorithm is used; callers cannot supply those security-critical values.
    """
    if not isinstance(tx, Tx):
        raise TypeError("ECDSA verification requires a Tx")
    if not isinstance(input_index, int) or isinstance(input_index, bool):
        raise TypeError("ECDSA verification input index must be an integer")
    if input_index < 0 or input_index >= len(tx.inputs):
        raise ValueError("ECDSA verification input index is outside the transaction inputs")
    if not isinstance(der_signature, bytes):
        raise TypeError("ECDSA verification signature must be bytes")
    try:
        decode_der_signature(der_signature)
    except (TypeError, ValueError) as exc:
        raise ValueError("Supplied signature is not strict DER") from exc

    outputs = tuple(spent_outputs)
    loaded_tx = LoadedTx(tx, list(outputs))
    spent_output = outputs[input_index]
    locking_script = spent_output.scriptpubkey

    if P2PKH_Key.matches(locking_script):
        unlocking_script = tx.inputs[input_index].scriptsig
        try:
            P2PKH_Sig.from_bytes(unlocking_script)
        except (IndexError, ScriptSigError, TypeError) as exc:
            raise ValueError("Selected input does not contain a P2PKH scriptSig") from exc
        signature_length = unlocking_script[0]
        signature_with_type = unlocking_script[1:1 + signature_length]
        public_key_length_offset = 1 + signature_length
        public_key_length = unlocking_script[public_key_length_offset]
        public_key = unlocking_script[
            public_key_length_offset + 1:public_key_length_offset + 1 + public_key_length
        ]
        if not signature_with_type:
            raise ValueError("P2PKH signature is missing its hash type")
        if hash160(public_key) != locking_script[3:23]:
            raise ValueError("P2PKH public key does not match the selected spent output")
        sighash_type = signature_with_type[-1]
        preimage = get_legacy_sighash_preimage(
            loaded_tx.tx, input_index, locking_script, sighash_type
        )
        digest = get_legacy_sighash(loaded_tx.tx, input_index, locking_script, sighash_type)
        return ECDSASignatureVerificationResult(
            input_index=input_index,
            script_type="P2PKH",
            signature=der_signature,
            public_key=public_key,
            sighash_type=sighash_type,
            preimage=preimage,
            digest=digest,
            locking_script=locking_script,
            unlocking_script=unlocking_script,
            witness=(),
            script_code=None,
            amount=None,
            valid=verify_ecdsa_sig(der_signature, digest, public_key),
        )

    if P2WPKH_Key.matches(locking_script):
        if tx.inputs[input_index].scriptsig:
            raise ValueError("Native P2WPKH input must have an empty scriptSig")
        if input_index >= len(tx.witness) or len(tx.witness[input_index].items) != 2:
            raise ValueError("P2WPKH witness must contain exactly a signature and public key")
        signature_with_type, public_key = tx.witness[input_index].items
        if not signature_with_type:
            raise ValueError("P2WPKH signature is missing its hash type")
        if hash160(public_key) != locking_script[2:]:
            raise ValueError("P2WPKH public key does not match the selected spent output")
        sighash_type = signature_with_type[-1]
        script_code = P2PKH_Key.from_pubkeyhash(locking_script[2:]).script
        serialized_script_code = serialize_data(script_code)
        preimage = get_segwit_sighash_preimage(
            loaded_tx.tx,
            input_index,
            spent_output.amount,
            serialized_script_code,
            sighash_type,
        )
        digest = get_segwit_sighash(
            loaded_tx.tx,
            input_index,
            spent_output.amount,
            serialized_script_code,
            sighash_type,
        )
        return ECDSASignatureVerificationResult(
            input_index=input_index,
            script_type="P2WPKH",
            signature=der_signature,
            public_key=public_key,
            sighash_type=sighash_type,
            preimage=preimage,
            digest=digest,
            locking_script=locking_script,
            unlocking_script=b"",
            witness=tuple(tx.witness[input_index].items),
            script_code=script_code,
            amount=spent_output.amount,
            valid=verify_ecdsa_sig(der_signature, digest, public_key),
        )

    raise ValueError("Selected spent output is not P2PKH or native P2WPKH")
