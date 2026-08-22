"""Construct standard locking-script templates from committed programs."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from src.core import PubKeyError, ScriptPubKeyError
from src.script.script_types import ScriptType
from src.script.scriptpubkeys import P2SH_Key, P2TR_Key, P2WPKH_Key, P2WSH_Key, ScriptPubKey

__all__ = ["StandardScript", "StandardScriptTemplate", "build_standard_script"]


class StandardScriptTemplate(str, Enum):
    P2SH = "P2SH"
    P2WPKH = "P2WPKH"
    P2WSH = "P2WSH"
    P2TR_KEY_PATH = "P2TR-KEY-PATH"
    P2TR_SCRIPT_PATH = "P2TR-SCRIPT-PATH"


_PROGRAM_LENGTHS = {
    StandardScriptTemplate.P2SH: 20,
    StandardScriptTemplate.P2WPKH: 20,
    StandardScriptTemplate.P2WSH: 32,
    StandardScriptTemplate.P2TR_KEY_PATH: 32,
    StandardScriptTemplate.P2TR_SCRIPT_PATH: 32,
}


@dataclass(frozen=True, slots=True)
class StandardScript:
    template: StandardScriptTemplate
    script_type: ScriptType
    script_pubkey: bytes
    address: str

    def to_dict(self) -> dict[str, str]:
        return {
            "template": self.template.value,
            "script_type": self.script_type.value,
            "script_pubkey_hex": self.script_pubkey.hex(),
            "address": self.address,
        }


def build_standard_script(
    template: StandardScriptTemplate | str,
    program: bytes,
) -> StandardScript:
    """Build a standard mainnet scriptPubKey from its committed hash or output key.

    P2SH and P2WPKH accept a 20-byte hash. P2WSH accepts a 32-byte hash.
    Taproot templates accept the already-tweaked 32-byte output key. Key-path
    and script-path intent serialize identically and remain distinct metadata.
    """
    try:
        normalized_template = StandardScriptTemplate(template)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Unsupported standard script template: {template!r}") from exc
    if not isinstance(program, bytes):
        raise TypeError("Standard script program must be bytes")

    expected_length = _PROGRAM_LENGTHS[normalized_template]
    if len(program) != expected_length:
        raise ValueError(
            f"{normalized_template.value} requires a {expected_length}-byte program"
        )

    script = _build_script(normalized_template, program)
    return StandardScript(
        template=normalized_template,
        script_type=script.script_type,
        script_pubkey=script.script,
        address=script.address,
    )


def _build_script(template: StandardScriptTemplate, program: bytes) -> ScriptPubKey:
    if template is StandardScriptTemplate.P2SH:
        return P2SH_Key(program)
    if template is StandardScriptTemplate.P2WPKH:
        return P2WPKH_Key(program)
    if template is StandardScriptTemplate.P2WSH:
        return P2WSH_Key(program)
    try:
        return P2TR_Key.from_bytes(b"\x51\x20" + program)
    except (PubKeyError, ScriptPubKeyError, TypeError, ValueError) as exc:
        raise ValueError("P2TR requires a valid x-only output key") from exc
