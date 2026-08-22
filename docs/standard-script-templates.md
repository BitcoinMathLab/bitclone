# Standard script templates

`build_standard_script` constructs deterministic mainnet P2SH, P2WPKH, P2WSH, and Taproot locking scripts from the
hash or output-key program committed by the scriptPubKey.

- P2SH and P2WPKH require 20-byte programs.
- P2WSH requires a 32-byte program.
- Taproot requires a valid, already-tweaked 32-byte x-only output key.
- Taproot key-path and script-path templates produce the same locking bytes; the distinction is retained as educational
  metadata because the spend reveals the path.

The result includes the template, underlying script family, serialized scriptPubKey, and mainnet address. Invalid
template names, program types, lengths, and Taproot output keys fail before a script is returned.
