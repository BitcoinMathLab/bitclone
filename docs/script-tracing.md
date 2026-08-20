# Script Tracing

Story 9.2 instruments `ScriptEngine` with an opt-in execution trace for the Bitcoin Math Lab visualizer. Tracing uses
the immutable model in `src/script/trace.py`; it does not add API or P2PKH fixture orchestration, which remain Story
9.3 work.

## Using the tracer

Normal execution remains unchanged and does not allocate stack snapshots:

```python
from src.script import ScriptEngine

engine = ScriptEngine()
valid = engine.execute_script(bytes.fromhex("515293"))
assert valid is True
assert engine.last_trace is None
```

Pass `trace=True` to retain a trace while preserving the usual boolean result and exception behavior:

```python
valid = engine.execute_script(bytes.fromhex("515293"), trace=True)
trace = engine.last_trace
```

`trace_script()` is the convenience entry point for educational callers that expect execution to produce a normal
true or false result:

```python
trace = ScriptEngine().trace_script(bytes.fromhex("6a"))  # OP_RETURN
assert trace.success is False
assert trace.diagnostic.code == "opcode-failed"
```

Execution exceptions are never suppressed. When one occurs, catch it as usual and inspect `engine.last_trace` for the
partial trace and diagnostic.

`validate_script(..., trace=True)` also traces execution. If all opcodes execute but final stack validation fails, its
trace explains whether the final stack was empty, unclean, or false.

## What each step records

Every executed instruction records:

- its canonical name, numeric value, exact serialized bytes, and byte offset in the traced script;
- immutable, top-first main-stack and alternate-stack snapshots before and after execution;
- a deterministic plain-English explanation; and
- a diagnostic when that instruction causes execution to fail.

Push explanations include the exact byte count without trying to interpret the data as a key, signature, hash, or
number. Common Bitcoin Script operations have purpose-written explanations. Other supported operations receive a
stable fallback based on their canonical opcode name.

Conditional markers are execution control rather than ordinary stack operations. A trace includes `OP_IF` or
`OP_NOTIF` and every instruction in the selected branch. It omits the unselected branch and its structural
`OP_ELSE`/`OP_ENDIF` markers. Offsets always refer to the original root script, including nested conditionals.

## Outcomes and diagnostics

Generated traces set `success` to `true` or `false`. A failed trace includes one top-level diagnostic; when an opcode
was responsible, the same diagnostic is attached to that step.

| Code | Meaning |
|---|---|
| `opcode-failed` | An opcode returned a normal script-failure result, such as `OP_RETURN` or failed verification |
| `execution-error` | An opcode raised an exception, such as a stack underflow |
| `parse-error` | The serialized script ended before an instruction could be read completely |
| `empty-final-stack` | Execution completed but final validation found no main-stack item |
| `unclean-final-stack` | Clean-stack validation required exactly one item but found another count |
| `false-final-value` | The final main-stack item represented false |

Diagnostics use stable codes for consumers and readable messages for learners. They contain exception class names but
not Python tracebacks. Story 9.3 remains responsible for choosing which diagnostic fields cross the public HTTP
boundary.

## Compatibility guarantees

- Tracing defaults to disabled.
- Untraced return values, exceptions, stack mutations, and `ops_log` entries are unchanged.
- `execute_script(..., trace=True)` still raises execution and parsing exceptions after retaining the partial trace.
- Trace snapshots own immutable copies and do not change when the engine continues to mutate.
- Existing manually constructed Story 9.1 objects serialize exactly as before when the new optional fields are absent.
- Generated traces add `success`, explanations, and diagnostics within schema version 1, as permitted by the additive
  field policy.
