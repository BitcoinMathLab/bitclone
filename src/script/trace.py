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
]


def _json_dump(value: dict) -> str:
    """Return the stable, human-readable JSON form used by trace objects."""
    return json.dumps(value, indent=2)


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

    def to_dict(self) -> dict:
        return {
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

    def to_json(self) -> str:
        return _json_dump(self.to_dict())


@dataclass(frozen=True, slots=True)
class ExecutionTrace:
    """An ordered, immutable trace for one serialized Bitcoin Script."""

    SCHEMA_VERSION: ClassVar[int] = 1

    script: bytes
    steps: tuple[ExecutionTraceStep, ...] = ()

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
        return {
            "schema_version": self.SCHEMA_VERSION,
            "script": self.script.hex(),
            "steps": [step.to_dict() for step in self.steps],
        }

    def to_json(self) -> str:
        return _json_dump(self.to_dict())
