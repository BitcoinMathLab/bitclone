# P2PKH Spend Tracing

Story 9.3 adds the transport-neutral boundary between Bitclone's script engine and the Bitcoin Math Lab product
backend. `trace_p2pkh_spend()` validates and traces one legacy P2PKH transaction input without importing FastAPI or
any HTTP model into Bitclone.

## Inputs

The caller provides:

- a parsed `Tx`;
- the zero-based input index to trace;
- every spent `UTXO`, in the same order as the transaction inputs; and
- optional script-verification flags.

Requiring the complete spent-output set preserves Bitcoin's execution context for multi-input transactions and gives
later SegWit and Taproot stories the amounts and scripts they require. `LoadedTx` verifies that every supplied UTXO
matches its transaction input's outpoint before execution starts.

The selected input must have a structurally valid P2PKH scriptSig and its spent output must use the exact 25-byte
legacy P2PKH locking template.

```python
from src.script import trace_p2pkh_spend

result = trace_p2pkh_spend(tx, input_index=0, spent_outputs=utxos)
assert result.trace.success is True
```

## Result

`P2PKHTraceResult` is frozen and contains the selected input index, unlocking script, locking script, combined script,
and immutable `ExecutionTrace`. Normal Bitcoin Script failures produce `success=False` plus the Story 9.2 diagnostic;
they are not Python exceptions.

Input decoding, request limits, HTTP status selection, exception sanitization, and public response models belong to
the product backend. This keeps Bitclone reusable by command-line tools, tests, and future non-HTTP consumers.
