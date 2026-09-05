# P2MS Spend Tracing

`trace_p2ms_spend()` is Bitclone's transport-neutral boundary for validating and tracing one legacy bare multisig
transaction input. It uses the same transaction context and script engine as normal validation; it does not synthesize
steps or substitute P2PKH signature data.

## Inputs and validation

The caller provides a parsed `Tx`, the zero-based input index, every spent `UTXO` in transaction-input order, and
optional verification flags. The selected spent output must be a direct m-of-n P2MS locking script. P2SH-wrapped
multisig is intentionally outside this boundary.

The selected scriptSig must contain the historical empty CHECKMULTISIG dummy followed by one or more serialized
signatures. The locking script supplies the threshold and ordered SEC public keys.

```python
from src.script import trace_p2ms_spend

result = trace_p2ms_spend(tx, input_index=0, spent_outputs=utxos)
assert result.required_signatures == 2
assert len(result.public_keys) == 3
assert result.null_dummy == b""
assert result.trace.success is True
```

## Result

`P2MSTraceResult` is frozen and contains the input index, unlocking and locking scripts, m-of-n threshold, ordered
public keys, serialized signatures, empty dummy, combined script, and immutable `ExecutionTrace`. The trace preserves
the real opcode order and stack snapshots through `OP_CHECKMULTISIG`. Normal Bitcoin Script failure returns
`trace.success=False` with a safe diagnostic; malformed or non-bare spend context raises a validation error.

The known mainnet fixture
`949591ad468cef5c41656c0a502d9500671ee421fadb590fbc6373000039b693:0` exercises a valid 2-of-3 spend from previous
outpoint `581d30e2a73a2db683ac2f15d53590bd0cd72de52555c2722d9d6a78e9fea510:0`.

Run:

    .venv/bin/python -m pytest tests/test_p2ms_spend_trace.py tests/test_known_script_pairs.py
