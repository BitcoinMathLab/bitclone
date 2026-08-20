from io import BytesIO

import pytest

from src.core.exceptions import BitStackError, ReadError
from src.script import OpcodeMetadata, ScriptEngine, StackSnapshot, TraceDiagnostic, explain_opcode
from src.script.opcode_map import OPCODE_MAP


def _stack_items(engine: ScriptEngine) -> tuple[bytes, ...]:
    return tuple(engine.stack.stack)


def test_tracing_is_opt_in_and_preserves_execution_behavior():
    script = bytes.fromhex("5152766b6c93")  # 1 2 DUP TOALT FROMALT ADD
    normal = ScriptEngine()
    traced = ScriptEngine()

    assert normal.execute_script(script) is True
    assert traced.execute_script(script, trace=True) is True

    assert normal.last_trace is None
    assert traced.last_trace is not None
    assert traced.last_trace.success is True
    assert _stack_items(traced) == _stack_items(normal)
    assert traced.alt_stack.height == normal.alt_stack.height
    assert traced.ops_log == normal.ops_log


def test_trace_captures_each_instruction_bytes_offsets_explanations_and_stacks():
    engine = ScriptEngine()
    trace = engine.trace_script(bytes.fromhex("02aabb766b6c"))

    assert trace.success is True
    assert [step.opcode.name for step in trace.steps] == [
        "OP_PUSHBYTES_2",
        "OP_DUP",
        "OP_TOALTSTACK",
        "OP_FROMALTSTACK",
    ]
    assert [step.opcode.byte_offset for step in trace.steps] == [0, 3, 4, 5]
    assert [step.opcode.raw.hex() for step in trace.steps] == ["02aabb", "76", "6b", "6c"]
    assert trace.steps[0].explanation == "Push 2 bytes of data onto the main stack."
    assert trace.steps[1].explanation.startswith("Copy the top item")
    assert trace.steps[2].main_stack_after.items == (b"\xaa\xbb",)
    assert trace.steps[2].alt_stack_after.items == (b"\xaa\xbb",)
    assert trace.steps[3].main_stack_after.items == (b"\xaa\xbb", b"\xaa\xbb")
    assert trace.steps[3].alt_stack_after == StackSnapshot()


def test_trace_snapshots_do_not_alias_later_engine_mutations():
    engine = ScriptEngine()
    trace = engine.trace_script(bytes.fromhex("51"))

    engine.stack.push(b"later")

    assert trace.final_main_stack.items == (b"\x01",)
    assert _stack_items(engine) == (b"later", b"\x01")


def test_false_return_records_opcode_failure_without_changing_return_value():
    engine = ScriptEngine()

    assert engine.execute_script(bytes.fromhex("516a52"), trace=True) is False

    trace = engine.last_trace
    assert trace is not None
    assert trace.success is False
    assert [step.opcode.name for step in trace.steps] == ["OP_1", "OP_RETURN"]
    assert trace.diagnostic == trace.steps[-1].diagnostic
    assert trace.diagnostic.to_dict() == {
        "code": "opcode-failed",
        "message": "OP_RETURN caused script execution to fail.",
        "step_index": 1,
        "opcode_name": "OP_RETURN",
        "exception_type": None,
    }


def test_execute_with_tracing_still_raises_after_capturing_failure():
    engine = ScriptEngine()

    with pytest.raises(BitStackError):
        engine.execute_script(bytes.fromhex("75"), trace=True)  # OP_DROP on an empty stack

    trace = engine.last_trace
    assert trace is not None
    assert trace.success is False
    assert len(trace.steps) == 1
    assert trace.diagnostic == trace.steps[0].diagnostic
    assert trace.diagnostic.code == "execution-error"
    assert trace.diagnostic.opcode_name == "OP_DROP"
    assert trace.diagnostic.exception_type == "BitStackError"


def test_trace_script_preserves_exception_behavior_and_retains_diagnostic():
    engine = ScriptEngine()

    with pytest.raises(BitStackError):
        engine.trace_script(bytes.fromhex("75"))

    trace = engine.last_trace
    assert trace is not None
    assert trace.success is False
    assert trace.diagnostic is not None
    assert "empty stack" in trace.diagnostic.message


def test_truncated_push_records_parse_diagnostic_without_inventing_a_step():
    engine = ScriptEngine()

    with pytest.raises(ReadError):
        engine.execute_script(bytes.fromhex("02aa"), trace=True)

    trace = engine.last_trace
    assert trace is not None
    assert trace.steps == ()
    assert trace.success is False
    assert trace.diagnostic is not None
    assert trace.diagnostic.code == "parse-error"
    assert trace.diagnostic.step_index is None


@pytest.mark.parametrize(
    ("script_hex", "require_clean_stack", "code"),
    [
        ("", True, "empty-final-stack"),
        ("00", True, "false-final-value"),
        ("5152", True, "unclean-final-stack"),
    ],
)
def test_validation_adds_final_stack_failure_diagnostics(script_hex, require_clean_stack, code):
    engine = ScriptEngine()

    assert engine.validate_script(
        bytes.fromhex(script_hex),
        require_clean_stack=require_clean_stack,
        trace=True,
    ) is False

    assert engine.last_trace is not None
    assert engine.last_trace.success is False
    assert engine.last_trace.diagnostic is not None
    assert engine.last_trace.diagnostic.code == code
    assert engine.last_trace.diagnostic.step_index is None


def test_successful_validation_retains_successful_trace():
    engine = ScriptEngine()

    assert engine.validate_script(bytes.fromhex("51"), trace=True) is True

    assert engine.last_trace is not None
    assert engine.last_trace.success is True
    assert engine.last_trace.diagnostic is None


@pytest.mark.parametrize(
    ("script_hex", "expected_names", "expected_offsets"),
    [
        ("51635267536854", ["OP_1", "OP_IF", "OP_2", "OP_4"], [0, 1, 2, 6]),
        ("00635267536854", ["OP_0", "OP_IF", "OP_3", "OP_4"], [0, 1, 4, 6]),
    ],
)
def test_conditional_trace_captures_only_executed_branch_with_root_offsets(
        script_hex,
        expected_names,
        expected_offsets,
):
    trace = ScriptEngine().trace_script(bytes.fromhex(script_hex))

    assert trace.success is True
    assert [step.opcode.name for step in trace.steps] == expected_names
    assert [step.opcode.byte_offset for step in trace.steps] == expected_offsets
    assert all(
        previous.main_stack_after == current.main_stack_before
        for previous, current in zip(trace.steps, trace.steps[1:])
    )


def test_bytesio_trace_offsets_are_relative_to_the_executed_slice():
    stream = BytesIO(bytes.fromhex("ff5152"))
    stream.seek(1)

    trace = ScriptEngine().trace_script(stream)

    assert trace.script == bytes.fromhex("5152")
    assert [step.opcode.byte_offset for step in trace.steps] == [0, 1]


def test_trace_serialization_adds_explanations_outcome_and_diagnostic():
    trace = ScriptEngine().trace_script(bytes.fromhex("6a"))
    payload = trace.to_dict()

    assert payload["schema_version"] == 1
    assert payload["success"] is False
    assert payload["steps"][0]["explanation"] == "Stop execution and mark the script as invalid."
    assert payload["steps"][0]["diagnostic"] == payload["diagnostic"]


def test_diagnostic_validation_and_opcode_explanation_guards():
    with pytest.raises(ValueError, match="code"):
        TraceDiagnostic(code="", message="failure")
    with pytest.raises(ValueError, match="message"):
        TraceDiagnostic(code="failure", message="")
    with pytest.raises(TypeError, match="OpcodeMetadata"):
        explain_opcode("OP_DUP")


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (0x76, "Copy the top item and place the copy on top of the main stack."),
        (0xa9, "Replace the top item with its SHA-256 then RIPEMD-160 digest."),
        (0x88, "Compare the top two items and fail unless their bytes are equal."),
        (0xac, "Check the signature against the public key and push the result."),
    ],
)
def test_p2pkh_opcodes_have_purpose_written_explanations(value, expected):
    opcode = OpcodeMetadata.create(
        value=value,
        byte_offset=0,
        raw=bytes([value]),
        is_push=False,
    )

    assert explain_opcode(opcode) == expected


@pytest.mark.parametrize(
    "value",
    sorted(set(OPCODE_MAP) | {0x61, 0x63, 0x64, 0x6a, 0xac, 0xad, 0xae, 0xaf, 0xb1, 0xba}),
)
def test_every_supported_non_push_opcode_has_a_purpose_written_explanation(value):
    opcode = OpcodeMetadata.create(
        value=value,
        byte_offset=0,
        raw=bytes([value]),
        is_push=False,
    )

    assert not explain_opcode(opcode).startswith("Execute OP ")


def test_trace_flag_requires_a_boolean():
    with pytest.raises(TypeError, match="trace must be a boolean"):
        ScriptEngine().execute_script(b"\x51", trace=1)
