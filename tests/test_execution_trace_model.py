import json
from dataclasses import FrozenInstanceError, replace

import pytest

from src.script import (
    BitStack,
    ExecutionTrace,
    ExecutionTraceStep,
    OpcodeMetadata,
    StackSnapshot,
    TraceDiagnostic,
)


EMPTY_STACK = StackSnapshot()


def _opcode(
        value: int,
        *,
        offset: int = 0,
        raw: bytes | None = None,
        is_push: bool = False,
        push_data: bytes | None = None,
) -> OpcodeMetadata:
    return OpcodeMetadata.create(
        value=value,
        byte_offset=offset,
        raw=raw if raw is not None else bytes([value]),
        is_push=is_push,
        push_data=push_data,
    )


def _step(
        index: int,
        opcode: OpcodeMetadata,
        *,
        main_before: StackSnapshot = EMPTY_STACK,
        main_after: StackSnapshot = EMPTY_STACK,
        alt_before: StackSnapshot = EMPTY_STACK,
        alt_after: StackSnapshot = EMPTY_STACK,
) -> ExecutionTraceStep:
    return ExecutionTraceStep(
        index=index,
        opcode=opcode,
        main_stack_before=main_before,
        main_stack_after=main_after,
        alt_stack_before=alt_before,
        alt_stack_after=alt_after,
    )


def test_stack_snapshot_captures_top_first_without_mutating_or_aliasing_stack():
    stack = BitStack()
    stack.push(b"bottom")
    stack.push(b"top")

    snapshot = StackSnapshot.capture(stack)
    stack.push(b"later")

    assert snapshot.items == (b"top", b"bottom")
    assert snapshot.top == b"top"
    assert snapshot.depth == 2
    assert stack.height == 3


def test_stack_snapshot_normalizes_iterables_and_serializes_bytes_as_hex():
    snapshot = StackSnapshot.from_items(item for item in (b"\x02", b"", b"\xff"))

    assert snapshot.items == (b"\x02", b"", b"\xff")
    assert snapshot.to_dict() == {
        "depth": 3,
        "items": ["02", "", "ff"],
    }
    assert json.loads(snapshot.to_json()) == snapshot.to_dict()


def test_stack_snapshot_rejects_non_bytes_and_non_stack_capture_source():
    with pytest.raises(TypeError, match="items must be bytes"):
        StackSnapshot((bytearray(b"mutable"),))
    with pytest.raises(TypeError, match="only capture a BitStack"):
        StackSnapshot.capture([b"not-a-stack"])


def test_trace_model_objects_are_frozen():
    snapshot = StackSnapshot((b"\x01",))
    metadata = _opcode(0x51)
    step = _step(0, metadata, main_after=snapshot)
    trace = ExecutionTrace(b"\x51", (step,))
    diagnostic = TraceDiagnostic(code="failed", message="It failed.")

    with pytest.raises(FrozenInstanceError):
        snapshot.items = ()
    with pytest.raises(FrozenInstanceError):
        metadata.name = "OP_CHANGED"
    with pytest.raises(FrozenInstanceError):
        step.index = 1
    with pytest.raises(FrozenInstanceError):
        trace.script = b""
    with pytest.raises(FrozenInstanceError):
        diagnostic.code = "changed"


def test_opcode_metadata_uses_canonical_names_and_preserves_empty_push_data():
    metadata = _opcode(
        0x4c,
        raw=b"\x4c\x00",
        is_push=True,
        push_data=b"",
    )

    assert metadata.name == "OP_PUSHDATA1"
    assert metadata.byte_length == 2
    assert metadata.to_dict() == {
        "name": "OP_PUSHDATA1",
        "value": 76,
        "hex": "0x4c",
        "byte_offset": 0,
        "byte_length": 2,
        "raw": "4c00",
        "is_push": True,
        "push_data": "",
    }
    assert json.loads(metadata.to_json()) == metadata.to_dict()


def test_opcode_metadata_gives_unknown_values_a_stable_name():
    metadata = _opcode(0xbb, offset=4)

    assert metadata.name == "OP_UNKNOWN_BB"
    assert metadata.to_dict()["hex"] == "0xbb"


@pytest.mark.parametrize(
    ("kwargs", "exception", "message"),
    [
        ({"value": -1, "name": "OP_BAD", "byte_offset": 0, "raw": b"\xff", "is_push": False},
         ValueError, "fit in one byte"),
        ({"value": 0x51, "name": "", "byte_offset": 0, "raw": b"\x51", "is_push": False},
         ValueError, "non-empty string"),
        ({"value": 0x51, "name": "OP_1", "byte_offset": -1, "raw": b"\x51", "is_push": False},
         ValueError, "cannot be negative"),
        ({"value": 0x51, "name": "OP_1", "byte_offset": 0, "raw": b"", "is_push": False},
         ValueError, "non-empty bytes"),
        ({"value": 0x51, "name": "OP_1", "byte_offset": 0, "raw": b"\x52", "is_push": False},
         ValueError, "begin with"),
        ({"value": 0x51, "name": "OP_1", "byte_offset": 0, "raw": b"\x51", "is_push": False,
          "push_data": b"data"}, ValueError, "Only push instructions"),
    ],
)
def test_opcode_metadata_rejects_invalid_states(kwargs, exception, message):
    with pytest.raises(exception, match=message):
        OpcodeMetadata(**kwargs)


def test_execution_step_serializes_before_and_after_states_for_both_stacks():
    step = _step(
        3,
        _opcode(0x6b, offset=7),
        main_before=StackSnapshot((b"\x02", b"\x01")),
        main_after=StackSnapshot((b"\x01",)),
        alt_before=EMPTY_STACK,
        alt_after=StackSnapshot((b"\x02",)),
    )

    payload = step.to_dict()

    assert payload["index"] == 3
    assert payload["opcode"]["name"] == "OP_TOALTSTACK"
    assert payload["stacks"]["before"]["main"]["items"] == ["02", "01"]
    assert payload["stacks"]["after"]["main"]["items"] == ["01"]
    assert payload["stacks"]["after"]["alt"]["items"] == ["02"]
    assert json.loads(step.to_json()) == payload


def test_execution_trace_serializes_ordered_state_transitions():
    one = StackSnapshot((b"\x01",))
    first = _step(0, _opcode(0x51), main_after=one)
    second = _step(
        1,
        _opcode(0x6b, offset=1),
        main_before=one,
        alt_after=one,
    )
    trace = ExecutionTrace(b"\x51\x6b", [first, second])

    assert isinstance(trace.steps, tuple)
    assert trace.initial_main_stack == EMPTY_STACK
    assert trace.final_main_stack == EMPTY_STACK
    assert trace.initial_alt_stack == EMPTY_STACK
    assert trace.final_alt_stack == one
    assert trace.to_dict() == {
        "schema_version": 1,
        "script": "516b",
        "steps": [first.to_dict(), second.to_dict()],
    }
    assert json.loads(trace.to_json()) == trace.to_dict()


def test_empty_execution_trace_has_empty_boundary_snapshots():
    trace = ExecutionTrace(b"")

    assert trace.steps == ()
    assert trace.initial_main_stack == EMPTY_STACK
    assert trace.final_main_stack == EMPTY_STACK
    assert trace.initial_alt_stack == EMPTY_STACK
    assert trace.final_alt_stack == EMPTY_STACK


def test_execution_trace_requires_contiguous_indexes():
    step = _step(1, _opcode(0x51), main_after=StackSnapshot((b"\x01",)))

    with pytest.raises(ValueError, match="contiguous and zero-based"):
        ExecutionTrace(b"\x51", (step,))


@pytest.mark.parametrize("stack_name", ["main", "alt"])
def test_execution_trace_rejects_disconnected_stack_transitions(stack_name):
    one = StackSnapshot((b"\x01",))
    two = StackSnapshot((b"\x02",))
    first_kwargs = {f"{stack_name}_after": one}
    second_kwargs = {f"{stack_name}_before": two}
    first = _step(0, _opcode(0x51), **first_kwargs)
    second = _step(1, _opcode(0x61, offset=1), **second_kwargs)

    expected = "main stack state" if stack_name == "main" else "alt-stack state"
    with pytest.raises(ValueError, match=expected):
        ExecutionTrace(b"\x51\x61", (first, second))


def test_trace_step_requires_matching_diagnostic_index():
    diagnostic = TraceDiagnostic(
        code="execution-error",
        message="The instruction failed.",
        step_index=1,
        opcode_name="OP_1",
    )

    with pytest.raises(ValueError, match="index must match"):
        replace(_step(0, _opcode(0x51)), diagnostic=diagnostic)


def test_successful_trace_rejects_diagnostic():
    diagnostic = TraceDiagnostic(code="failure", message="It failed.")

    with pytest.raises(ValueError, match="successful trace"):
        ExecutionTrace(b"", success=True, diagnostic=diagnostic)


def test_trace_requires_matching_step_and_top_level_diagnostics():
    diagnostic = TraceDiagnostic(
        code="opcode-failed",
        message="OP_RETURN failed.",
        step_index=0,
        opcode_name="OP_RETURN",
    )
    step_without_diagnostic = _step(0, _opcode(0x6a))

    with pytest.raises(ValueError, match="must match"):
        ExecutionTrace(
            b"\x6a",
            (step_without_diagnostic,),
            success=False,
            diagnostic=diagnostic,
        )
