# Spend Classification

`src.script.classify_spend` provides a transport-neutral description of a spent output. Product code supplies the
previous output's locking script and, when available, the spending input's scriptSig and witness.

The result separates the output family from the observed spend path:

- P2PK, P2PKH, P2SH, P2WPKH, and P2WSH outputs;
- native and P2SH-nested version-zero witness programs;
- Taproot key-path and script-path witnesses, including the optional annex; and
- `UNKNOWN` for unsupported, truncated, or structurally ambiguous data.

Classification recognizes structure; it does not prove that a signature, hash preimage, control block, or complete
transaction is valid. Script execution and transaction validation remain separate operations.

## Example

```python
from src.script import classify_spend

classification = classify_spend(
    bytes.fromhex("0014" + "11" * 20),
    witness=[b"signature", b"compressed public key"],
)

assert classification.spend_type.value == "P2WPKH"
assert classification.to_dict() == {
    "output_type": "P2WPKH",
    "spend_type": "P2WPKH",
    "is_nested": False,
    "redeem_script_hex": None,
}
```

## QA validation

Run the focused and complete suites:

    .venv/bin/python -m pytest tests/test_spend_classification.py
    .venv/bin/python -m pytest

Then validate representative fixtures through a Python shell:

1. Classify standard P2PK, P2PKH, P2SH, P2WPKH, and P2WSH locking scripts. Expect the matching spend type.
2. Supply P2SH with one directly pushed v0 20-byte or 32-byte witness program. Expect `P2SH-P2WPKH` or
   `P2SH-P2WSH`, the redeem script, and `is_nested=True`.
3. Add another scriptSig stack item before the witness-program push. Expect plain `P2SH`; malformed scriptSigs must
   not be presented as nested SegWit.
4. Supply a P2TR output with one witness element, then a valid script/control-block pair. Expect key path and script
   path respectively. Repeat both with a final `0x50` annex.
5. Supply empty and truncated scripts and a malformed Taproot control block. Expect `UNKNOWN`, without an exception.
6. Run existing script, transaction, and mempool tests to confirm the hardened short-script matching changed no valid
   classification or validation behavior.

This boundary processes public transaction data only. It must never receive or log private keys, RPC credentials, or
wallet secrets.
