"""
Classes for all possible ScriptPubKey types
"""
from abc import ABC, abstractmethod

from src.core import SERIALIZED, ScriptPubKeyError, get_bytes, get_stream, read_little_int, read_stream, PubKeyError
from src.cryptography import hash160
from src.data import encode_base58check, encode_bech32, get_unbalanced_merkle_root, TweakPubkey, PubKey
from src.script.script_types import BaseScript, ScriptType

# --- OP_CODES --- #
OP_0 = b'\x00'
OP_PUSHBYTES_20 = b'\x14'
OP_PUSHBYTES_32 = b'\x20'
OP_PUSHBYTES_33 = b'\x21'
OP_PUSHBYTES_65 = b'\x41'
OP_1 = b'\x51'
OP_CHECKSIG = b'\xac'
OP_CHECKMULTISIG = b'\xae'
OP_DUP = b'\x76'
OP_EQUAL = b'\x87'
OP_EQUALVERIFY = b'\x88'
OP_HASH160 = b'\xa9'

# --- CONSTANTS --- #
PUBKEY_LENGTHS = [33, 65]

__all__ = ["P2PK_Key", "P2PKH_Key", "P2MS_Key", "P2SH_Key", "P2TR_Key", "P2WSH_Key", "P2WPKH_Key", "ScriptPubKey",
           "get_scriptpubkey_type", "get_scriptpubkey_class", "classify_scriptpubkey"]


class ScriptPubKey(BaseScript, ABC):
    """
    The parent class for all ScriptPubKeys
    """

    @classmethod
    @abstractmethod
    def from_bytes(cls, byte_stream: SERIALIZED):
        raise NotImplementedError

    @property
    @abstractmethod
    def address(self) -> str:
        raise NotImplementedError

    @classmethod
    @abstractmethod
    def matches(cls, b: bytes) -> bool:
        """Return True if the given script matches this type"""
        raise NotImplementedError

    def __eq__(self, other):
        if isinstance(other, ScriptPubKey):
            return self.script == other.script
        raise ScriptPubKeyError(f"Cannot equate ScriptPubKey and {type(other)}")


class P2PK_Key(ScriptPubKey):
    """
    Pay 2 Public Key | OP_PUSHBYTES || pubkey || OP_CHECKSIG
    """
    script_type = ScriptType.P2PK

    def __init__(self, pubkey: bytes):

        # --- Validation
        if len(pubkey) not in PUBKEY_LENGTHS:
            raise ScriptPubKeyError("Given Pubkey not of allowed length")

        # --- Create script
        op_code = OP_PUSHBYTES_33 if len(pubkey) == 33 else OP_PUSHBYTES_65
        self.script = op_code + pubkey + OP_CHECKSIG

    @classmethod
    def matches(cls, b: bytes) -> bool:
        return len(b) in (35, 67) and b[0] == len(b) - 2 and b[-1] == OP_CHECKSIG[0]

    @classmethod
    def from_bytes(cls, byte_stream: SERIALIZED):
        script_bytes = get_bytes(byte_stream)
        if cls.matches(script_bytes):
            obj = cls.__new__(P2PK_Key)
            obj.script = script_bytes
            return obj
        raise ScriptPubKeyError("Byte stream does not match P2PK type")

    @property
    def address(self) -> str:
        """
        We hash160 the public key in the script and convert to base58, similar to P2PKH_Sig
        """
        pubkey = self.script[1:-1]
        pubkey_hash = hash160(pubkey)
        return encode_base58check(pubkey_hash)


class P2PKH_Key(ScriptPubKey):
    """
    Pay 2 Pubkey Hash | OP_DUP || OP_HASH160 || OP_PUSHBYTES_20 || pubkeyhash || OP_EQUALVERIFY || OP_CHECKSIG
    """
    script_type = ScriptType.P2PKH

    def __init__(self, pubkey: bytes):
        pubkeyhash = hash160(pubkey)
        self.script = OP_DUP + OP_HASH160 + OP_PUSHBYTES_20 + pubkeyhash + OP_EQUALVERIFY + OP_CHECKSIG

    @classmethod
    def matches(cls, b: bytes) -> bool:
        if len(b) != 25:
            return False
        truth_list = [
            b[0] == OP_DUP[0],
            b[1] == OP_HASH160[0],
            b[2] == OP_PUSHBYTES_20[0],
            b[-2] == OP_EQUALVERIFY[0],
            b[-1] == OP_CHECKSIG[0]
        ]
        return all(truth_list)

    @classmethod
    def from_bytes(cls, script_bytes: bytes) -> "P2PKH_Key":
        if cls.matches(script_bytes):
            obj = object.__new__(cls)
            obj.script = script_bytes
            return obj
        raise ScriptPubKeyError("Given scriptpubkey doesn't match P2PKH_Sig OP_CODE structure")

    @classmethod
    def from_pubkeyhash(cls, pubkeyhash: bytes) -> "P2PKH_Key":
        obj = object.__new__(cls)
        obj.script = OP_DUP + OP_HASH160 + OP_PUSHBYTES_20 + pubkeyhash + OP_EQUALVERIFY + OP_CHECKSIG
        return obj

    @property
    def address(self, testnet: bool = False) -> str:
        prefix_byte = b'\x6f' if testnet else b'\x00'
        pubkeyhash = self.script[3:-2]
        return encode_base58check(pubkeyhash, prefix_byte)


class P2MS_Key(ScriptPubKey):
    script_type = ScriptType.P2MS

    def __init__(self, pubkeys: list, min_num: int = 0):
        pubkey_num = len(pubkeys)
        min_num = pubkey_num if min_num == 0 else min_num

        # --- Validation
        if not all([len(pubkey) in PUBKEY_LENGTHS for pubkey in pubkeys]):
            raise ScriptPubKeyError("Given pubkeys not in correct format")

        # --- Construct script
        op_min = bytes([0x50 + min_num])
        op_tot = bytes([0x50 + pubkey_num])

        script_parts = [op_min]
        for pubkey in pubkeys:
            script_parts.append(OP_PUSHBYTES_33) if len(pubkey) == 33 else script_parts.append(OP_PUSHBYTES_65)
            script_parts.append(pubkey)
        script_parts.extend([op_tot, OP_CHECKMULTISIG])

        self.script = b''.join(script_parts)

    @classmethod
    def from_bytes(cls, byte_stream: SERIALIZED):
        script_bytes = get_bytes(byte_stream)

        if not cls.matches(script_bytes):
            raise ScriptPubKeyError("Failed to match P2MS structure")

        req_num = script_bytes[0] - 0x50  # Required number of signatures
        sig_num = script_bytes[-2] - 0x50  # Total number of signatures
        pubkey_list = []
        stream = get_stream(script_bytes[1:-2])  # Stream remaining pubkeys
        for x in range(sig_num):
            pubkey_type = read_little_int(stream, 1)
            if pubkey_type not in PUBKEY_LENGTHS:
                raise ScriptPubKeyError("Pubkey in list not of correct length")
            pubkey = read_stream(stream, pubkey_type)
            pubkey_list.append(pubkey)

        return cls(pubkey_list, req_num)

    @property
    def address(self) -> str:
        return ""

    @classmethod
    def matches(cls, b: bytes) -> bool:
        if len(b) < 3:
            return False
        # Confirm leading and tail
        lead_byte = b[0]
        tail_byte = b[-1]
        tail2_byte = b[-2]

        truth_list = [
            0x51 <= lead_byte <= 0x60,  # OP_num (required)
            0x51 <= tail2_byte <= 0x60,  # OP_num (total)
            bytes([tail_byte]) == OP_CHECKMULTISIG  # OP_CHECKMULTISIG
        ]

        return all(truth_list)


class P2SH_Key(ScriptPubKey):
    script_type = ScriptType.P2SH

    def __init__(self, hash_data: bytes):
        # Validate data is 20 byte digest
        if len(hash_data) != 20:
            raise ScriptPubKeyError("Given hash data not a 20-byte digest")

        self.script = OP_HASH160 + OP_PUSHBYTES_20 + hash_data + OP_EQUAL

    @classmethod
    def from_data(cls, data: bytes):
        """
        Hashes the data
        """
        hash_data = hash160(data)
        return cls(hash_data)

    @classmethod
    def from_bytes(cls, byte_stream: SERIALIZED):
        script_bytes = get_bytes(byte_stream)

        # Verify
        lead_byte = script_bytes[0]
        second_byte = script_bytes[1]
        last_byte = script_bytes[-1]

        if not all([lead_byte == OP_HASH160[0], second_byte == OP_PUSHBYTES_20[0], last_byte == OP_EQUAL[
            0]]):
            raise ScriptPubKeyError("Failed OP_Code structure for P2SH ScriptPubKey")

        return cls(script_bytes[2:-1])

    @property
    def address(self, testnet: bool = False) -> str:
        script_hash = self.script[2:-1]
        prefix = b'\x05' if not testnet else b'\xc4'

        return encode_base58check(script_hash, prefix)

    @classmethod
    def matches(cls, b: bytes) -> bool:
        if len(b) != 23:
            return False
        truth_list = [
            b[0] == OP_HASH160[0],  # OP_HASH160
            b[1] == OP_PUSHBYTES_20[0],  # OP_PUSHBYTES_20
            b[-1] == OP_EQUAL[0],  # OP_EQUAL
        ]
        return all(truth_list)


class P2WPKH_Key(ScriptPubKey):
    """
    For use in P2SH-P2WPKH and P2WPKH itself
    """
    script_type = ScriptType.P2WPKH

    def __init__(self, pubkeyhash: bytes):
        # Validate
        if len(pubkeyhash) != 20:
            raise ScriptPubKeyError("Given pubkeyhash not 20 bytes")
        self.script = OP_0 + OP_PUSHBYTES_20 + pubkeyhash

    @classmethod
    def from_bytes(cls, byte_stream: SERIALIZED):
        script_bytes = get_bytes(byte_stream)

        if cls.matches(script_bytes):
            return cls(script_bytes[2:])
        raise ScriptPubKeyError("Given byte digest doesn't match P2WPKH opcode structure")

    @classmethod
    def matches(cls, b: bytes) -> bool:
        if len(b) != 22:
            return False
        truthlist = [
            b[0] == OP_0[0],
            b[1] == OP_PUSHBYTES_20[0],
        ]
        return all(truthlist)

    @classmethod
    def from_pubkey(cls, pubkey: bytes):
        """
        Given a Pubkey obj, we can hash the compressed pubkey and return the instance
        """
        # Pubkey must be a 33 byte compressed public key
        if len(pubkey) != 33:
            raise ScriptPubKeyError("P2WPKH only uses compressed public keys")
        pubkeyhash = hash160(pubkey)
        return cls(pubkeyhash)

    @property
    def address(self) -> str:
        # The encode_bech32 function only takes the SCRIPTPUBKEY, and the witness version is submitted separately
        scriptpubkey = self.script[2:]
        return encode_bech32(scriptpubkey, witver=0)


class P2WSH_Key(ScriptPubKey):
    """
    Pay To Witness Script Hash
    """
    script_type = ScriptType.P2WSH

    def __init__(self, script_hash: bytes):
        # Validation
        if len(script_hash) != 32:
            raise ScriptPubKeyError("P2WSH Key must be 32 bytes")

        self.script = OP_0 + OP_PUSHBYTES_32 + script_hash

    @classmethod
    def matches(cls, b: bytes) -> bool:
        if len(b) != 34:
            return False
        lead_byte = b[0]
        first_byte = b[1]
        scripthash_len = len(b[2:])
        truth_list = [
            lead_byte == OP_0[0],
            first_byte == OP_PUSHBYTES_32[0],
            scripthash_len == 32
        ]
        return all(truth_list)

    @classmethod
    def from_bytes(cls, byte_stream: SERIALIZED):
        script_bytes = get_bytes(byte_stream)

        if cls.matches(script_bytes):
            return cls(script_bytes[2:])
        raise ScriptPubKeyError("Data failed P2WSH opcode structure")

    @property
    def address(self) -> str:
        scriptpubkey = self.script[2:]
        return encode_bech32(scriptpubkey, witver=0)


class P2TR_Key(ScriptPubKey):
    """
    A ScriptPubKey for the Key Path Spend method in Taproot
    """
    script_type = ScriptType.P2TR

    def __init__(self, xonly_pubkey: bytes, scripts: list[bytes] = None):
        merkle_root = get_unbalanced_merkle_root(scripts) if scripts else b''
        tweakpubkey = TweakPubkey(xonly_pubkey, merkle_root)

        self.script = OP_1 + OP_PUSHBYTES_32 + tweakpubkey.tweaked_pubkey.x_bytes()

    @classmethod
    def matches(cls, b: bytes) -> bool:
        if len(b) != 34:
            return False
        truth_list = [
            b[0] == OP_1[0],
            b[1] == OP_PUSHBYTES_32[0],
            len(b[2:]) == 32
        ]
        return all(truth_list)

    @classmethod
    def from_bytes(cls, byte_stream: SERIALIZED):
        script_bytes = get_bytes(byte_stream)

        if cls.matches(script_bytes):
            try:
                _ = PubKey.from_xonly(script_bytes[2:])
            except PubKeyError as e:
                raise PubKeyError(f"Given script fails x-only public key validation: {e}") from e

            obj = object.__new__(cls)
            obj.script = script_bytes
            return obj
        raise PubKeyError("Script bytes do not match opcode syntax for P2TR")

    @property
    def address(self) -> str:
        return encode_bech32(self.script[2:], hrp='bc', witver=1)  # OP_1


# --- Classifier --- #
SCRIPTPUBKEY_CLASSIFIERS: tuple[type[ScriptPubKey], ...] = (
    P2PKH_Key,
    P2SH_Key,
    P2WPKH_Key,
    P2WSH_Key,
    P2TR_Key,
    P2PK_Key,
    P2MS_Key,
)


def get_scriptpubkey_class(script_bytes: bytes) -> type[ScriptPubKey]:
    """
    Return the ScriptPubKey subclass matching the serialized scriptPubKey.
    """
    for cls in SCRIPTPUBKEY_CLASSIFIERS:
        if cls.matches(script_bytes):
            return cls
    raise ScriptPubKeyError("Unrecognized scriptPubKey type")


def get_scriptpubkey_type(script_bytes: bytes) -> ScriptType:
    """
    Return the ScriptType matching the serialized scriptPubKey.
    """
    return get_scriptpubkey_class(script_bytes).script_type


def classify_scriptpubkey(script_bytes: bytes) -> ScriptPubKey:
    """
    Parse the serialized scriptPubKey into its matching ScriptPubKey object.
    """
    cls = get_scriptpubkey_class(script_bytes)
    return cls.from_bytes(script_bytes)
