# Execution Trace Model

Story 9.1 defines the immutable data contract that later tracing, API, and visualizer work will use. The model lives in
`src/script/trace.py` and does not change or instrument `ScriptEngine` execution.

## Scope

The model provides four frozen, slotted data classes:

- `StackSnapshot` captures one main or alternate stack without retaining mutable engine state.
- `OpcodeMetadata` identifies an instruction and its exact location and bytes in the script.
- `ExecutionTraceStep` records the main-stack and alt-stack state before and after one instruction.
- `ExecutionTrace` contains the ordered steps for one serialized script.

Optional engine tracing, plain-language explanations, and failure diagnostics remain Story 9.2 work. P2PKH orchestration
and the HTTP response contract remain Story 9.3 work.

## Stack ordering and byte encoding

`StackSnapshot.items` is always ordered **top first**. This matches `BitStack`, whose first deque item is the next item
that will be popped. Capturing a stack copies its current items into a tuple, so later engine mutations cannot change a
recorded step.

All byte strings are encoded as lowercase hexadecimal in dictionaries and JSON:

- `b"\x01"` becomes `"01"`;
- `b""` becomes `""`; and
- an empty stack becomes `{ "depth": 0, "items": [] }`.

The representation does not guess whether bytes are a number, signature, public key, or hash. That interpretation is
presentation metadata to be added by the lesson and explanation layers.

## Opcode metadata

Each instruction records:

| Field | Meaning |
|---|---|
| `name` | Canonical name from `OPCODES`, such as `OP_DUP` |
| `value` | Unsigned numeric opcode value |
| `hex` | Two-digit, `0x`-prefixed opcode value |
| `byte_offset` | Zero-based offset of the opcode in the traced script |
| `byte_length` | Total instruction length, including push length and data bytes |
| `raw` | Exact serialized instruction bytes as lowercase hex |
| `is_push` | Whether the parser classified the instruction as a data push |
| `push_data` | Pushed bytes as hex, or `null` for non-push instructions |

Unknown byte values receive a stable `OP_UNKNOWN_XX` label. This lets Story 9.2 describe an invalid instruction without
discarding its location or bytes.

## Trace invariants

Constructors reject states that would make a trace ambiguous or mutable:

- opcode values must fit in one byte and raw instruction bytes must begin with that value;
- step indexes must be contiguous and zero-based;
- the after-state of each step must equal the before-state of the next step for both stacks;
- stack items, scripts, instruction bytes, and push data must be immutable `bytes`; and
- nested model objects must have their expected trace-model types.

These checks keep malformed traces from crossing the future API boundary.

## Example

The script `OP_1 OP_TOALTSTACK` (`516b`) can be represented as:

```python
from src.script import (
    ExecutionTrace,
    ExecutionTraceStep,
    OpcodeMetadata,
    StackSnapshot,
)

empty = StackSnapshot()
one = StackSnapshot((b"\x01",))

trace = ExecutionTrace(
    script=b"\x51\x6b",
    steps=(
        ExecutionTraceStep(
            index=0,
            opcode=OpcodeMetadata.create(
                value=0x51,
                byte_offset=0,
                raw=b"\x51",
                is_push=False,
            ),
            main_stack_before=empty,
            main_stack_after=one,
            alt_stack_before=empty,
            alt_stack_after=empty,
        ),
        ExecutionTraceStep(
            index=1,
            opcode=OpcodeMetadata.create(
                value=0x6b,
                byte_offset=1,
                raw=b"\x6b",
                is_push=False,
            ),
            main_stack_before=one,
            main_stack_after=empty,
            alt_stack_before=empty,
            alt_stack_after=one,
        ),
    ),
)

payload = trace.to_dict()
json_payload = trace.to_json()
```

The serialized top-level shape is versioned from its first release:

```json
{
  "schema_version": 1,
  "script": "516b",
  "steps": []
}
```

Each actual step supplies its opcode metadata and `before`/`after` snapshots for both `main` and `alt` stacks. Additive
fields may be introduced without changing `schema_version`; incompatible field or semantic changes require a new
version.
