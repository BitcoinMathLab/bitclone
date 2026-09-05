"""Stable classification of standard Bitcoin output and spend forms."""

from dataclasses import dataclass
from enum import Enum
from typing import Sequence

from src.core import ScriptPubKeyError
from src.script.script_types import ScriptType
from src.script.scriptpubkeys import get_scriptpubkey_type

__all__ = ["SpendClassification", "SpendType", "classify_spend"]


class SpendType(str, Enum):
    """User-facing standard spend forms supported by Bitcoin Math Lab."""

    P2PK = "P2PK"
    P2PKH = "P2PKH"
    P2MS = "P2MS"
    P2SH = "P2SH"
    P2SH_P2WPKH = "P2SH-P2WPKH"
    P2SH_P2WSH = "P2SH-P2WSH"
    P2WPKH = "P2WPKH"
    P2WSH = "P2WSH"
    P2TR_KEY_PATH = "P2TR-KEY-PATH"
    P2TR_SCRIPT_PATH = "P2TR-SCRIPT-PATH"
    UNKNOWN = "UNKNOWN"


_DIRECT_TYPES: dict[ScriptType, SpendType] = {
    ScriptType.P2PK: SpendType.P2PK,
    ScriptType.P2PKH: SpendType.P2PKH,
    ScriptType.P2MS: SpendType.P2MS,
    ScriptType.P2SH: SpendType.P2SH,
    ScriptType.P2WPKH: SpendType.P2WPKH,
    ScriptType.P2WSH: SpendType.P2WSH,
}


@dataclass(frozen=True, slots=True)
class SpendClassification:
    """The locking-script family and, where observable, exact spend path."""

    output_type: ScriptType | None
    spend_type: SpendType
    redeem_script: bytes | None = None

    @property
    def is_nested(self) -> bool:
        return self.spend_type in {SpendType.P2SH_P2WPKH, SpendType.P2SH_P2WSH}

    def to_dict(self) -> dict[str, str | bool | None]:
        return {
            "output_type": self.output_type.value if self.output_type is not None else None,
            "spend_type": self.spend_type.value,
            "is_nested": self.is_nested,
            "redeem_script_hex": self.redeem_script.hex() if self.redeem_script is not None else None,
        }


def classify_spend(
    script_pubkey: bytes,
    *,
    script_sig: bytes = b"",
    witness: Sequence[bytes] = (),
) -> SpendClassification:
    """Classify a standard spend without executing or assuming its validity.

    Taproot key and script paths are distinguished after removing an optional
    annex. A malformed or unsupported script is returned as ``UNKNOWN`` rather
    than leaking a parser exception into product code.
    """
    try:
        output_type = get_scriptpubkey_type(script_pubkey)
    except (IndexError, ScriptPubKeyError, TypeError, ValueError):
        return SpendClassification(None, SpendType.UNKNOWN)

    if output_type is ScriptType.P2SH:
        redeem_script = _single_direct_push(script_sig)
        if redeem_script is not None:
            if _is_v0_witness_program(redeem_script, 20):
                return SpendClassification(output_type, SpendType.P2SH_P2WPKH, redeem_script)
            if _is_v0_witness_program(redeem_script, 32):
                return SpendClassification(output_type, SpendType.P2SH_P2WSH, redeem_script)
        return SpendClassification(output_type, SpendType.P2SH, redeem_script)

    if output_type is ScriptType.P2TR:
        path = _classify_taproot_path(witness)
        return SpendClassification(output_type, path)

    spend_type = _DIRECT_TYPES.get(output_type, SpendType.UNKNOWN)
    return SpendClassification(output_type, spend_type)


def _single_direct_push(script_sig: bytes) -> bytes | None:
    if not script_sig:
        return None
    pushed_length = script_sig[0]
    if not 1 <= pushed_length <= 75 or len(script_sig) != pushed_length + 1:
        return None
    return script_sig[1:]


def _is_v0_witness_program(script: bytes, program_length: int) -> bool:
    return len(script) == program_length + 2 and script[0] == 0 and script[1] == program_length


def _classify_taproot_path(witness: Sequence[bytes]) -> SpendType:
    stack = tuple(witness)
    if len(stack) >= 2 and stack[-1].startswith(b"\x50"):
        stack = stack[:-1]
    if len(stack) == 1:
        return SpendType.P2TR_KEY_PATH
    if len(stack) >= 2:
        control_block = stack[-1]
        if len(control_block) >= 33 and (len(control_block) - 33) % 32 == 0:
            return SpendType.P2TR_SCRIPT_PATH
    return SpendType.UNKNOWN
