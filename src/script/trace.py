"""Immutable data structures for Bitcoin Script execution traces.

This module defines the transport-neutral trace contract used by later tracing
and API stories. It deliberately does not execute scripts or mutate engine
state.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import ClassVar, Iterable

from src.core.opcodes import OPCODES
from src.script.stack import BitStack

__all__ = [
    "ExecutionTrace",
    "ExecutionTraceStep",
    "OpcodeMetadata",
    "StackSnapshot",
    "TraceDiagnostic",
    "explain_opcode",
]


_OPCODE_EXPLANATIONS = {
    "OP_0": "Push an empty byte string, which represents false and the number zero.",
    "OP_1NEGATE": "Push the Script number -1 onto the main stack.",
    "OP_NOP": "Do nothing and continue to the next instruction.",
    "OP_IF": "Execute the following branch when the top stack item is true.",
    "OP_NOTIF": "Execute the following branch when the top stack item is false.",
    "OP_ELSE": "Switch to the alternative branch of the current conditional.",
    "OP_ENDIF": "End the current conditional branch.",
    "OP_VERIFY": "Remove the top item and fail unless it represents true.",
    "OP_RETURN": "Stop execution and mark the script as invalid.",
    "OP_TOALTSTACK": "Move the top item from the main stack to the alternate stack.",
    "OP_FROMALTSTACK": "Move the top item from the alternate stack to the main stack.",
    "OP_2DROP": "Remove the top two items from the main stack.",
    "OP_2DUP": "Copy the top two items and place both copies on top of the main stack.",
    "OP_3DUP": "Copy the top three items and place all three copies on top of the main stack.",
    "OP_2OVER": "Copy the third and fourth items and place both copies on top.",
    "OP_2ROT": "Move the fifth and sixth items to the top of the main stack.",
    "OP_2SWAP": "Swap the top pair of stack items with the pair immediately below it.",
    "OP_IFDUP": "Copy the top item when it represents true.",
    "OP_DEPTH": "Push the current number of main-stack items as a Script number.",
    "OP_DROP": "Remove the top item from the main stack.",
    "OP_DUP": "Copy the top item and place the copy on top of the main stack.",
    "OP_NIP": "Remove the item immediately below the top item.",
    "OP_OVER": "Copy the second item and place the copy on top of the main stack.",
    "OP_PICK": "Copy the selected stack item and place the copy on top.",
    "OP_ROLL": "Move the selected stack item to the top.",
    "OP_ROT": "Rotate the top three stack items.",
    "OP_SWAP": "Swap the top two stack items.",
    "OP_TUCK": "Copy the top item beneath the second item.",
    "OP_SIZE": "Push the byte length of the top item without removing that item.",
    "OP_EQUAL": "Compare the top two items and push true when their bytes are equal.",
    "OP_EQUALVERIFY": "Compare the top two items and fail unless their bytes are equal.",
    "OP_1ADD": "Add one to the top Script number.",
    "OP_1SUB": "Subtract one from the top Script number.",
    "OP_NEGATE": "Replace the top Script number with its negation.",
    "OP_ABS": "Replace the top Script number with its absolute value.",
    "OP_NOT": "Push true when the top Script number is zero, otherwise push false.",
    "OP_0NOTEQUAL": "Push true when the top Script number is not zero.",
    "OP_ADD": "Add the top two Script numbers and push the result.",
    "OP_SUB": "Subtract the top Script number from the second number and push the result.",
    "OP_BOOLAND": "Push true when both of the top two items represent true.",
    "OP_BOOLOR": "Push true when either of the top two items represents true.",
    "OP_NUMEQUAL": "Compare the top two Script numbers and push true when they are equal.",
    "OP_NUMEQUALVERIFY": "Compare the top two Script numbers and fail unless they are equal.",
    "OP_NUMNOTEQUAL": "Compare the top two Script numbers and push true when they differ.",
    "OP_LESSTHAN": "Push true when the second Script number is less than the top number.",
    "OP_GREATERTHAN": "Push true when the second Script number is greater than the top number.",
    "OP_LESSTHANOREQUAL": "Push true when the second Script number is at most the top number.",
    "OP_GREATERTHANOREQUAL": "Push true when the second Script number is at least the top number.",
    "OP_MIN": "Push the smaller of the top two Script numbers.",
    "OP_MAX": "Push the larger of the top two Script numbers.",
    "OP_WITHIN": "Push true when a value is within the given minimum-inclusive, maximum-exclusive range.",
    "OP_RIPEMD160": "Replace the top item with its RIPEMD-160 digest.",
    "OP_SHA1": "Replace the top item with its SHA-1 digest.",
    "OP_SHA256": "Replace the top item with its SHA-256 digest.",
    "OP_HASH160": "Replace the top item with its SHA-256 then RIPEMD-160 digest.",
    "OP_HASH256": "Replace the top item with its double-SHA-256 digest.",
    "OP_CODESEPARATOR": "Mark the position used when constructing a signature hash.",
    "OP_CHECKSIG": "Check the signature against the public key and push the result.",
    "OP_CHECKSIGVERIFY": "Check the signature against the public key and fail unless it is valid.",
    "OP_CHECKMULTISIG": "Check the supplied signatures against the public keys and push the result.",
    "OP_CHECKMULTISIGVERIFY": "Check the supplied signatures and fail unless enough are valid.",
    "OP_CHECKLOCKTIMEVERIFY": "Fail when the transaction cannot yet be included at the required lock time.",
    "OP_CHECKSEQUENCEVERIFY": "Fail when the input does not satisfy the required relative lock time.",
    "OP_CHECKSIGADD": "Check a Schnorr signature and add one to the counter when it is valid.",
}


def _json_dump(value: dict) -> str:
    """Return the stable, human-readable JSON form used by trace objects."""
    return json.dumps(value, indent=2)


def explain_opcode(opcode: "OpcodeMetadata") -> str:
    """Return a deterministic, plain-English description of one instruction."""
    if not isinstance(opcode, OpcodeMetadata):
        raise TypeError("Opcode explanations require OpcodeMetadata")
    if opcode.is_push:
        byte_count = len(opcode.push_data or b"")
        noun = "byte" if byte_count == 1 else "bytes"
        return f"Push {byte_count} {noun} of data onto the main stack."
    if opcode.name.startswith("OP_UNKNOWN_"):
        return "This byte does not identify a supported Bitcoin Script opcode."
    if opcode.name.startswith("OP_") and opcode.name[3:].isdigit():
        return f"Push the Script number {opcode.name[3:]} onto the main stack."
    return _OPCODE_EXPLANATIONS.get(
        opcode.name,
        f"Execute {opcode.name.replace('_', ' ')}.",
    )


@dataclass(frozen=True, slots=True)
class TraceDiagnostic:
    """A stable, presentation-safe explanation of why traced execution failed."""

    code: str
    message: str
    step_index: int | None = None
    opcode_name: str | None = None
    exception_type: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.code, str) or not self.code:
            raise ValueError("Trace diagnostic code must be a non-empty string")
        if not isinstance(self.message, str) or not self.message:
            raise ValueError("Trace diagnostic message must be a non-empty string")
        if self.step_index is not None:
            if not isinstance(self.step_index, int) or isinstance(self.step_index, bool):
                raise TypeError("Trace diagnostic step index must be an integer or None")
            if self.step_index < 0:
                raise ValueError("Trace diagnostic step index cannot be negative")
        if self.opcode_name is not None and (
                not isinstance(self.opcode_name, str) or not self.opcode_name
        ):
            raise ValueError("Trace diagnostic opcode name must be a non-empty string or None")
        if self.exception_type is not None and (
                not isinstance(self.exception_type, str) or not self.exception_type
        ):
            raise ValueError("Trace diagnostic exception type must be a non-empty string or None")

    def to_dict(self) -> dict:
        return {
            "code": self.code,
            "message": self.message,
            "step_index": self.step_index,
            "opcode_name": self.opcode_name,
            "exception_type": self.exception_type,
        }

    def to_json(self) -> str:
        return _json_dump(self.to_dict())


@dataclass(frozen=True, slots=True)
class StackSnapshot:
    """An immutable, top-first snapshot of one Bitcoin Script stack."""

    items: tuple[bytes, ...] = ()

    def __post_init__(self) -> None:
        normalized = tuple(self.items)
        if any(not isinstance(item, bytes) for item in normalized):
            raise TypeError("Stack snapshot items must be bytes")
        object.__setattr__(self, "items", normalized)

    @classmethod
    def from_items(cls, items: Iterable[bytes]) -> "StackSnapshot":
        """Build a snapshot from items ordered from stack top to bottom."""
        return cls(tuple(items))

    @classmethod
    def capture(cls, stack: BitStack) -> "StackSnapshot":
        """Copy the current state of a ``BitStack`` without mutating it."""
        if not isinstance(stack, BitStack):
            raise TypeError("Stack snapshots can only capture a BitStack")
        return cls(tuple(stack.stack))

    @property
    def depth(self) -> int:
        return len(self.items)

    @property
    def top(self) -> bytes | None:
        return self.items[0] if self.items else None

    def to_dict(self) -> dict:
        return {
            "depth": self.depth,
            "items": [item.hex() for item in self.items],
        }

    def to_json(self) -> str:
        return _json_dump(self.to_dict())


@dataclass(frozen=True, slots=True)
class OpcodeMetadata:
    """Display and byte-location metadata for one parsed instruction."""

    value: int
    name: str
    byte_offset: int
    raw: bytes
    is_push: bool
    push_data: bytes | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.value, int) or isinstance(self.value, bool):
            raise TypeError("Opcode value must be an integer")
        if not 0 <= self.value <= 0xff:
            raise ValueError("Opcode value must fit in one byte")
        if not isinstance(self.name, str) or not self.name:
            raise ValueError("Opcode name must be a non-empty string")
        if not isinstance(self.byte_offset, int) or isinstance(self.byte_offset, bool):
            raise TypeError("Opcode byte offset must be an integer")
        if self.byte_offset < 0:
            raise ValueError("Opcode byte offset cannot be negative")
        if not isinstance(self.raw, bytes) or not self.raw:
            raise ValueError("Opcode raw bytes must be non-empty bytes")
        if self.raw[0] != self.value:
            raise ValueError("Opcode raw bytes must begin with the opcode value")
        if not isinstance(self.is_push, bool):
            raise TypeError("Opcode is_push must be a boolean")
        if self.push_data is not None and not isinstance(self.push_data, bytes):
            raise TypeError("Opcode push data must be bytes or None")
        if not self.is_push and self.push_data is not None:
            raise ValueError("Only push instructions can include push data")

    @classmethod
    def create(
            cls,
            *,
            value: int,
            byte_offset: int,
            raw: bytes,
            is_push: bool,
            push_data: bytes | None = None,
    ) -> "OpcodeMetadata":
        """Create metadata using BitClone's canonical opcode name mapping."""
        name = OPCODES.get_name(value) or f"OP_UNKNOWN_{value:02X}"
        return cls(
            value=value,
            name=name,
            byte_offset=byte_offset,
            raw=raw,
            is_push=is_push,
            push_data=push_data,
        )

    @property
    def byte_length(self) -> int:
        return len(self.raw)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "value": self.value,
            "hex": f"0x{self.value:02x}",
            "byte_offset": self.byte_offset,
            "byte_length": self.byte_length,
            "raw": self.raw.hex(),
            "is_push": self.is_push,
            "push_data": self.push_data.hex() if self.push_data is not None else None,
        }

    def to_json(self) -> str:
        return _json_dump(self.to_dict())


@dataclass(frozen=True, slots=True)
class ExecutionTraceStep:
    """The immutable before/after state transition for one instruction."""

    index: int
    opcode: OpcodeMetadata
    main_stack_before: StackSnapshot
    main_stack_after: StackSnapshot
    alt_stack_before: StackSnapshot
    alt_stack_after: StackSnapshot
    explanation: str = ""
    diagnostic: TraceDiagnostic | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.index, int) or isinstance(self.index, bool):
            raise TypeError("Trace step index must be an integer")
        if self.index < 0:
            raise ValueError("Trace step index cannot be negative")
        if not isinstance(self.opcode, OpcodeMetadata):
            raise TypeError("Trace step opcode must be OpcodeMetadata")
        snapshots = (
            self.main_stack_before,
            self.main_stack_after,
            self.alt_stack_before,
            self.alt_stack_after,
        )
        if any(not isinstance(snapshot, StackSnapshot) for snapshot in snapshots):
            raise TypeError("Trace step stacks must be StackSnapshot instances")
        if not isinstance(self.explanation, str):
            raise TypeError("Trace step explanation must be a string")
        if self.diagnostic is not None and not isinstance(self.diagnostic, TraceDiagnostic):
            raise TypeError("Trace step diagnostic must be TraceDiagnostic or None")
        if self.diagnostic is not None and self.diagnostic.step_index != self.index:
            raise ValueError("Trace step diagnostic index must match the trace step")

    def to_dict(self) -> dict:
        payload = {
            "index": self.index,
            "opcode": self.opcode.to_dict(),
            "stacks": {
                "before": {
                    "main": self.main_stack_before.to_dict(),
                    "alt": self.alt_stack_before.to_dict(),
                },
                "after": {
                    "main": self.main_stack_after.to_dict(),
                    "alt": self.alt_stack_after.to_dict(),
                },
            },
        }
        if self.explanation:
            payload["explanation"] = self.explanation
        if self.diagnostic is not None:
            payload["diagnostic"] = self.diagnostic.to_dict()
        return payload

    def to_json(self) -> str:
        return _json_dump(self.to_dict())


@dataclass(frozen=True, slots=True)
class ExecutionTrace:
    """An ordered, immutable trace for one serialized Bitcoin Script."""

    SCHEMA_VERSION: ClassVar[int] = 1

    script: bytes
    steps: tuple[ExecutionTraceStep, ...] = ()
    success: bool | None = None
    diagnostic: TraceDiagnostic | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.script, bytes):
            raise TypeError("Traced script must be bytes")

        normalized_steps = tuple(self.steps)
        if any(not isinstance(step, ExecutionTraceStep) for step in normalized_steps):
            raise TypeError("Execution trace steps must be ExecutionTraceStep instances")
        if any(step.index != index for index, step in enumerate(normalized_steps)):
            raise ValueError("Execution trace step indexes must be contiguous and zero-based")

        for previous, current in zip(normalized_steps, normalized_steps[1:]):
            if previous.main_stack_after != current.main_stack_before:
                raise ValueError("Adjacent trace steps must preserve the main stack state")
            if previous.alt_stack_after != current.alt_stack_before:
                raise ValueError("Adjacent trace steps must preserve the alt-stack state")

        if self.success is not None and not isinstance(self.success, bool):
            raise TypeError("Trace success must be a boolean or None")
        if self.diagnostic is not None and not isinstance(self.diagnostic, TraceDiagnostic):
            raise TypeError("Trace diagnostic must be TraceDiagnostic or None")
        if self.success is True and self.diagnostic is not None:
            raise ValueError("A successful trace cannot include a failure diagnostic")
        if self.diagnostic is not None and self.diagnostic.step_index is not None:
            if self.diagnostic.step_index >= len(normalized_steps):
                raise ValueError("Trace diagnostic step index must identify a trace step")
            step_diagnostic = normalized_steps[self.diagnostic.step_index].diagnostic
            if step_diagnostic != self.diagnostic:
                raise ValueError("Step-level and trace-level diagnostics must match")

        object.__setattr__(self, "steps", normalized_steps)

    @property
    def initial_main_stack(self) -> StackSnapshot:
        return self.steps[0].main_stack_before if self.steps else StackSnapshot()

    @property
    def final_main_stack(self) -> StackSnapshot:
        return self.steps[-1].main_stack_after if self.steps else StackSnapshot()

    @property
    def initial_alt_stack(self) -> StackSnapshot:
        return self.steps[0].alt_stack_before if self.steps else StackSnapshot()

    @property
    def final_alt_stack(self) -> StackSnapshot:
        return self.steps[-1].alt_stack_after if self.steps else StackSnapshot()

    def to_dict(self) -> dict:
        payload = {
            "schema_version": self.SCHEMA_VERSION,
            "script": self.script.hex(),
            "steps": [step.to_dict() for step in self.steps],
        }
        if self.success is not None:
            payload["success"] = self.success
        if self.diagnostic is not None:
            payload["diagnostic"] = self.diagnostic.to_dict()
        return payload

    def to_json(self) -> str:
        return _json_dump(self.to_dict())
