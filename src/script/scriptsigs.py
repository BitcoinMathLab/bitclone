"""
Classes for all possible ScriptSig types
"""
from abc import ABC, abstractmethod

from src.core import ScriptSigError
from src.script.script_types import BaseScript, ScriptType
from src.script.scriptpubkeys import P2WPKH_Key
from src.script.stack_ops import encode_pushdata

# --- OP_CODES --- #
OP_0 = b'\x00'
OP_PUSHBYTES_22 = b'\x16'

# --- CONSTANTS --- #
PUBKEY_LENGTHS = [33, 65]

__all__ = ["P2PK_Sig", "P2PKH_Sig", "P2MS_Sig", "P2SH_Sig", "P2SH_P2WPKH_Sig", "ScriptSig", "get_scriptsig_class",
           "get_scriptsig_type", "classify_scriptsig"]


class ScriptSig(BaseScript, ABC):
    """
    The parent class for all ScriptSigs
    """

    @classmethod
    @abstractmethod
    def from_bytes(cls, scriptsig: bytes):
        """All subclasses must implement this"""
        raise NotImplementedError("Missing from_bytes construction")

    @classmethod
    @abstractmethod
    def matches(cls, b: bytes) -> bool:
        """Return True if the given script matches this type"""
        raise NotImplementedError


class P2PK_Sig(ScriptSig):
    """
    Script = OP_PUSHBYTES + signature

    ECDSA signatures are always ≤74 bytes (71-73 bytes DER + 1 byte sighash),
    so we never need OP_PUSHDATA opcodes.
    """
    script_type = ScriptType.P2PK

    def __init__(self, sig: bytes):
        self.script = encode_pushdata(sig)

    @classmethod
    def matches(cls, b: bytes) -> bool:
        script_len = b[0]
        return script_len == len(b[1:])

    @classmethod
    def from_bytes(cls, scriptsig: bytes):
        if cls.matches(scriptsig):
            obj = object.__new__(cls)
            obj.script = scriptsig
            return obj
        raise ScriptSigError("Incorrect format for P2PK ScriptSig")


class P2PKH_Sig(ScriptSig):
    """
    Script = OP_PUSHBYTES + signature + OP_PUSHBYTES + public_key

    NOTES
        -pubkey can be either compressed or uncompressed (33 bytes or 65 bytes, resp)
        -Whatever form the pubkey uses in the ScriptSig needs to be the same one which generates the pubkeyhash in
        the ScriptPubKey
    """
    script_type = ScriptType.P2PKH

    def __init__(self, sig: bytes, pubkey: bytes):
        # Verify pubkey length
        if len(pubkey) not in PUBKEY_LENGTHS:
            raise ScriptSigError("Given public key not of allowable length")

        # Construct: <sig_len> <sig> <pubkey_len> <pubkey>
        self.script = encode_pushdata(sig) + encode_pushdata(pubkey)  # Will raise errors if lengths incorrect

    @classmethod
    def matches(cls, b: bytes) -> bool:
        if not isinstance(b, bytes) or len(b) < 2:
            return False
        sig_len = b[0]
        offset = 1 + sig_len

        if offset >= len(b):  # no room for a pubkey — not P2PKH
            return False

        sig = b[1:offset]
        pubkey_len = b[offset]
        pubkey_end = offset + 1 + pubkey_len
        pubkey = b[offset + 1:pubkey_end]

        truth_list = [
            0x01 <= sig_len <= 0x4b,
            len(sig) == sig_len,
            pubkey_len in PUBKEY_LENGTHS,  # tighter: must be 33 or 65
            len(pubkey) == pubkey_len,
            pubkey_end == len(b),
        ]
        return all(truth_list)

    @classmethod
    def from_bytes(cls, scriptsig: bytes):
        if cls.matches(scriptsig):
            obj = object.__new__(cls)
            obj.script = scriptsig
            return obj
        raise ScriptSigError("Given ScriptSig doesn't match P2PKH structure")


class P2MS_Sig(ScriptSig):
    """
    Pay 2 multisig, takes in list of signatures and returns OP_PUSHBYTES ahead of each signature.
    We include an additional OP_0 due to OP_CHECKMULTISIG bug. (BIP-147)
    P2MS | OP_0 + #signatures * (OP_PUSHBYTES + SIGNATURE)
    """
    script_type = ScriptType.P2MS

    def __init__(self, signatures: list):
        self.script = OP_0  # BIP-147
        for sig in signatures:
            self.script += encode_pushdata(sig)

    @classmethod
    def matches(cls, b: bytes) -> bool:
        # Check NULLDUMMY
        if b[0] != 0:
            return False

        # Walk each pushed item; every item must be a DER-encoded signature (starts
        # with 0x30).  This rejects P2SH scriptsigs whose final pushed item is a
        # redeem script (begins with an OP_n byte such as 0x51), even though its
        # push-length byte also falls in the valid 0x01–0x4b range.
        signatures = []
        scriptsig = b[1:]
        while True:
            opcode = scriptsig[0]
            if not (0x01 <= opcode <= 0x4b):
                return False
            item = scriptsig[1:1 + opcode]
            if not item or item[0] != 0x30:  # DER compound type tag
                return False
            signatures.append(item)
            scriptsig = scriptsig[1 + opcode:]
            if scriptsig == b'':
                break
        return len(signatures) >= 1

    @classmethod
    def from_bytes(cls, scriptsig: bytes):
        if cls.matches(scriptsig):
            obj = object.__new__(cls)
            obj.script = scriptsig
            return obj
        raise ScriptSigError("Given ScriptSig doesn't match P2MS structure.")


class P2SH_Sig(ScriptSig):
    """
    The P2SH consists of two parts:
        -The signature(s) necessary to unlock the redeem script (which gets hash160'ed in the scriptpubkey)
        -A data push of the redeem script
    """
    script_type = ScriptType.P2SH

    def __init__(self, signatures: bytes | list[bytes], redeem_script: bytes):
        sig_bytes = b''.join([encode_pushdata(sig) for sig in signatures]) if isinstance(signatures,
                                                                                         list) else signatures
        self.script = sig_bytes + encode_pushdata(redeem_script)

    @classmethod
    def matches(cls, b: bytes) -> bool:
        if not b:
            return False

        length = len(b)

        # Walk backwards to find the last small push
        for i in range(length - 1, -1, -1):
            push_len = b[i]

            # Small push only (what encode_pushdata uses for short scripts)
            if 1 <= push_len <= 0x4b:
                remaining_bytes = length - (i + 1)
                if remaining_bytes == push_len:
                    # This means b[i] is OP_PUSHBYTES for the redeem_script,
                    # and the tail is exactly that many bytes.
                    return True

        return False

    @classmethod
    def from_bytes(cls, scriptsig: bytes):
        if not cls.matches(scriptsig):
            raise ScriptSigError("Given ScriptSig doesn't match P2SH structure.")

        obj = object.__new__(cls)
        obj.script = scriptsig
        return obj


class P2SH_P2WPKH_Sig(ScriptSig):
    """
    ScriptPubKey = P2SH_Key
    But we unlock using both ScriptSig and WitnessField
    """
    script_type = ScriptType.P2SH_P2WPKH

    def __init__(self, p2wpkh_key: bytes | P2WPKH_Key):
        self.script = OP_PUSHBYTES_22 + (p2wpkh_key.script if isinstance(p2wpkh_key, P2WPKH_Key) else p2wpkh_key)

    @classmethod
    def matches(cls, b: bytes) -> bool:
        return OP_PUSHBYTES_22[0] == b[0]

    @classmethod
    def from_bytes(cls, scriptsig: bytes):
        if not cls.matches(scriptsig):
            raise ScriptSigError("Given data does not match P2SH-P2WPKH opcode syntax")
        obj = object.__new__(cls)
        obj.script = scriptsig
        return obj


# --- Classifier --- #
SCRIPTSIG_CLASSIFIERS: tuple[type[ScriptSig], ...] = (
    P2SH_P2WPKH_Sig,  # specific leading byte (0x16), checked first
    P2MS_Sig,  # OP_0 + signature walk
    P2SH_Sig,  # backwards redeem-script walk, fairly loose
    P2PKH_Sig,  # sig + pubkey structure
    P2PK_Sig,  # b[0] == len(b[1:]), maximally loose — must be last
)


def get_scriptsig_class(script_bytes: bytes) -> type[ScriptSig]:
    """
    Return the ScriptSig subclass matching the serialized scriptSig.
    """
    for cls in SCRIPTSIG_CLASSIFIERS:
        if cls.matches(script_bytes):
            return cls
    raise ScriptSigError("Unrecognized scriptSig type")


def get_scriptsig_type(script_bytes: bytes) -> ScriptType:
    """
    Return the ScriptType matching the serialized scriptSig.
    """
    return get_scriptsig_class(script_bytes).script_type


def classify_scriptsig(script_bytes: bytes) -> ScriptSig:
    """
    Parse the serialized scriptSig into its matching ScriptSig object.
    """
    cls = get_scriptsig_class(script_bytes)
    return cls.from_bytes(script_bytes)
