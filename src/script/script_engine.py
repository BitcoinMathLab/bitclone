"""
The ScriptEngine class
"""
import json
from dataclasses import replace, dataclass, field
from io import BytesIO

from src.core import ECC, ScriptVerifyFlag, serialize_data
from src.core.byte_stream import get_stream, read_stream, read_little_int
from src.core.exceptions import ScriptEngineError
from src.core.logging import get_logger
from src.core.opcodes import OPCODES
from src.cryptography import sha256
from src.data import Leaf, validate_control_block
from src.script import sig_ops as sig_engine
from src.script.context import LegacyExecutionContext, ScriptExecutionContext
from src.script.opcode_map import OPCODE_MAP
from src.script.parser import parse_script_ops, to_asm
from src.script.script_types import ScriptType
from src.script.scriptpubkeys import ScriptPubKey, P2PKH_Key, P2SH_Key, P2WPKH_Key, P2WSH_Key, classify_scriptpubkey
from src.script.context import SignatureVersion
from src.script.stack_ops import encode_pushdata
from src.script.scriptsigs import ScriptSig
from src.script.stack import BitStack, BitNum
from src.script.trace import (
    ExecutionTrace,
    ExecutionTraceStep,
    OpcodeMetadata,
    StackSnapshot,
    TraceDiagnostic,
    explain_opcode,
)
from src.tx.tx import Witness

__all__ = ["ScriptEngine"]
logger = get_logger(__name__)
ScriptContext = ScriptExecutionContext | LegacyExecutionContext

_OP = OPCODES()
op_verify = OPCODE_MAP[0x69]
LOCKTIME_THRESHOLD = 500_000_000


@dataclass(slots=True)
class Instruction:
    opcode: int  # numeric opcode value
    raw: bytes  # exact bytes as they appear in the script
    is_push: bool  # True for OP_PUSH* opcodes
    push_data: bytes | None = None

    def to_dict(self):
        return {
            "opcode": _OP.get_name(self.opcode),
            "opcode_num": self.opcode,
            "opcode_hex": hex(self.opcode),
            "raw": self.raw.hex(),
            "is_push": self.is_push,
            "push_data": self.push_data.hex() if self.push_data else ""
        }

    def to_json(self):
        return json.dumps(self.to_dict(), indent=2)


@dataclass(slots=True)
class _TraceState:
    script: bytes
    steps: list[ExecutionTraceStep] = field(default_factory=list)
    diagnostic: TraceDiagnostic | None = None


class ScriptEngine:

    def __init__(self):
        self.stack = BitStack()
        self.alt_stack = BitStack()
        self.ops_log = []
        self.tapscript_validation_weight_left: int | None = None
        self.last_trace: ExecutionTrace | None = None
        # self.sig_engine = SignatureEngine()

    def clear_stacks(self):
        self.stack.clear()
        self.alt_stack.clear()
        self.ops_log = []
        self.tapscript_validation_weight_left = None

    @staticmethod
    def _read_instructions(stream: BytesIO) -> Instruction | None:
        """
        Read a single instruction (opcode + any pushdata) from the stream.
        Returns None at end of stream.
        """
        opcode_byte = stream.read(1)
        if not opcode_byte:
            return None

        opcode = opcode_byte[0]

        # OP_PUSHBYTES_n: 0x01..0x4b
        if 0x01 <= opcode <= 0x4b:
            data = read_stream(stream, opcode)
            raw = opcode_byte + data
            return Instruction(opcode=opcode, raw=raw, is_push=True, push_data=data)
        # OP_PUSHDATA1
        if opcode == 0x4c:
            length = read_little_int(stream, 1)
            data = read_stream(stream, length)
            raw = opcode_byte + length.to_bytes(1, "little") + data
            return Instruction(opcode=opcode, raw=raw, is_push=True, push_data=data)
        # OP_PUSHDATA2
        if opcode == 0x4d:
            length = read_little_int(stream, 2)
            data = read_stream(stream, length)
            raw = opcode_byte + length.to_bytes(2, "little") + data
            return Instruction(opcode=opcode, raw=raw, is_push=True, push_data=data)
        # OP_PUSHDATA4
        if opcode == 0x4e:
            length = read_little_int(stream, 4)
            data = read_stream(stream, length)
            raw = opcode_byte + length.to_bytes(4, "little") + data
            return Instruction(opcode=opcode, raw=raw, is_push=True, push_data=data)

        # Non-push opcodes: single byte
        return Instruction(opcode=opcode, raw=opcode_byte, is_push=False, push_data=None)

    def _select_conditional_branch(self, opcode: int, stream: BytesIO) -> tuple[bytes, int]:
        """
        Handle OP_IF (0x63) and OP_NOTIF (0x64) with proper branching logic.
        Read through OP_ENDIF, validate the structure, and return the selected branch and offset.
        """
        # Validate opcode
        if opcode not in [0x63, 0x64]:  # OP_IF, OP_NOTIF
            raise ScriptEngineError(f"Invalid opcode for conditional handling: {opcode:#x}")

        # Pop condition from stack
        condition = self.stack.pop()

        # Determine if condition is true
        # For OP_IF: execute if condition is true (non-empty, non-zero)
        # For OP_NOTIF: execute if condition is false (empty or zero)
        condition_met = self._stack_value_is_true(condition)
        if opcode == 0x64:  # OP_NOTIF
            condition_met = not condition_met

        # Read and parse the conditional block structure
        if_branch, else_branch, if_offset, else_offset = self._parse_conditional_block(stream)

        # Determine which branch to execute
        if condition_met:
            return if_branch, if_offset
        return else_branch, else_offset

    def _parse_conditional_block(self, stream: BytesIO) -> tuple[bytes, bytes, int, int]:
        """
        Parse the conditional block structure from the stream.
        Returns (if_branch, else_branch) as bytes.
        Raises ScriptEngineError if OP_ENDIF is missing.
        """
        if_branch = BytesIO()
        else_branch = BytesIO()
        current_branch = if_branch
        if_offset = stream.tell()
        else_offset = if_offset

        depth = 1  # Track nested conditionals
        found_endif = False

        while depth > 0:
            instr = self._read_instructions(stream)
            if instr is None:
                raise ScriptEngineError("Missing OP_ENDIF: reached end of script without closing conditional")

            opcode = instr.opcode

            # Handle nested conditionals
            if opcode in (0x63, 0x64):  # OP_IF, OP_NOTIF
                depth += 1
                # Nested IF/NOTIF live inside the current branch
                current_branch.write(instr.raw)

            elif opcode == 0x67:  # OP_ELSE
                if depth == 1:
                    # This ELSE belongs to the top-level IF/NOTIF:
                    # switch branches but do NOT write OP_ELSE into either branch.
                    current_branch = else_branch
                    else_offset = stream.tell()
                    continue
                else:
                    # ELSE for a nested conditional, keep it in the branch
                    current_branch.write(instr.raw)

            elif opcode == 0x68:  # OP_ENDIF
                depth -= 1
                if depth == 0:
                    # Matching ENDIF for our top-level conditional; we stop here
                    found_endif = True
                    # Do NOT write this ENDIF into any branch
                    break
                else:
                    # ENDIF for a nested conditional, keep it in the branch
                    current_branch.write(instr.raw)

            else:
                # All other instructions (including all pushdata variants)
                # are already fully encoded in instr.raw.
                current_branch.write(instr.raw)

        if not found_endif:
            raise ScriptEngineError("Missing OP_ENDIF: conditional block not properly closed")

        return if_branch.getvalue(), else_branch.getvalue(), if_offset, else_offset

    def _handle_signatures(self, opcode: int, ctx: ScriptContext):
        """
        0xab -- 0xba
        """
        # Parse signature type
        match opcode:
            # OP_CHECKSIG
            case 0xac:
                self._handle_checksig(ctx)
            # # OP_CHECKSIGVERIFY
            # case 0xad:
            #     self._handle_checksig(ctx)
            #     verified = op_verify(self.stack)
            #     if not verified:
            #         raise ScriptEngineError("Script failed OP_VERIFY call in OP_CHECKSIGVERIFY")
            # OP_CHECKMULTISIG
            case 0xae:
                self._handle_multisig(ctx)
            case 0xba:
                self._handle_checksigadd(ctx)
            case _:
                raise ScriptEngineError(f"Unhandled signature opcode: {opcode}")

    @staticmethod
    def _stack_value_is_true(v: bytes) -> bool:
        """
        Bitcoin truthiness: false iff the ScriptNum value is 0.
        """
        # Empty is false
        if v == b'':
            return False

        # Interpret as ScriptNum; zero is false, non-zero is true.
        return BitNum.from_bytes(v).value != 0

    def _compute_sighash(self, ctx: ScriptContext, script_code: bytes, sighash_num: int) -> bytes:
        """
        Compute the appropriate sighash for the current context (legacy / segwit / tapscript).
        """
        tx = ctx.tx
        utxos = ctx.utxos
        input_index = ctx.input_index

        if tx is None or utxos is None:
            raise ScriptEngineError("Missing context elements for sighash computation")

        # Tapscript (script-path Taproot)
        if getattr(ctx, "tapscript", False):
            return sig_engine.get_taproot_sighash(
                tx=tx,
                input_index=input_index,
                utxos=utxos,
                ext_flag=1,
                sighash_num=sighash_num,
                leaf_hash=ctx.merkle_root,
            )

        # Segwit v0 (P2WPKH / P2WSH)
        if getattr(ctx, "is_segwit", False):
            return sig_engine.get_segwit_sighash(
                tx=tx,
                input_index=input_index,
                amount=utxos[input_index].amount,
                scriptpubkey=script_code,
                sighash_num=sighash_num,
            )

        # Legacy
        return sig_engine.get_legacy_sighash(
            tx=tx,
            input_index=input_index,
            scriptpubkey=script_code,
            sighash_num=sighash_num,
        )

    def _verify_sig(self, ctx: ScriptContext, pubkey: bytes, der_sig: bytes, message_hash: bytes) -> bool:
        """
        Verify a single signature given the current script context.
        """
        # Tapscript uses Schnorr over x-only pubkeys.
        if getattr(ctx, "tapscript", False):
            return sig_engine.verify_schnorr_sig(
                xonly_pubkey=pubkey,
                msg=message_hash,
                sig=der_sig,
            )

        # Legacy + segwit v0 use ECDSA.
        return sig_engine.verify_ecdsa_sig(
            signature=der_sig,
            message=message_hash,
            public_key=pubkey,
            strict_der=bool(ctx.script_flags & ScriptVerifyFlag.DERSIG),
        )

    def _handle_checksig(self, ctx: ScriptContext):
        # Get context elements
        tx = ctx.tx
        utxos = ctx.utxos
        input_index = ctx.input_index

        # Validate
        if tx is None or utxos is None:
            raise ScriptEngineError("Missing context elements for OP_CHECKSIG")

        # Pop pubkey and signature
        pubkey, sig = self.stack.popitems(2)

        # Signature should be DER-encoded with sighash num
        if len(sig) < 1:
            if ctx.tapscript:
                self.stack.pushbool(False)
                return
            raise ScriptEngineError("Signature stack item too short for OP_CHECKSIG")

        if ctx.tapscript:
            if len(sig) == 64:
                der_sig = sig
                sighash_num = 0
            elif len(sig) == 65 and sig[-1] != 0:
                der_sig = sig[:-1]
                sighash_num = sig[-1]
            else:
                self.stack.pushbool(False)
                return
            if not self._consume_tapscript_sigop(sig):
                raise ScriptEngineError("Tapscript signature validation weight exceeded")
        else:
            der_sig = sig[:-1]
            sighash_num = sig[-1]

        # Use script_code from context if available (for P2SH), otherwise use scriptpubkey
        script_code = ctx.script_code if getattr(ctx, "script_code", None) else utxos[input_index].scriptpubkey

        # Compute sighash based on context (legacy/segwit/tapscript)
        message_hash = self._compute_sighash(ctx, script_code, sighash_num)

        # Verify signature (ECDSA or Schnorr)
        signature_verified = self._verify_sig(ctx, pubkey, der_sig, message_hash)

        # Push result
        self.stack.pushbool(signature_verified)

    def _handle_checksigadd(self, ctx: ScriptContext) -> None:
        """Execute BIP342 OP_CHECKSIGADD for tapscript."""
        if not ctx.tapscript:
            raise ScriptEngineError("OP_CHECKSIGADD is only valid in tapscript")

        pubkey = self.stack.pop()
        count = self.stack.popnum()
        sig = self.stack.pop()

        if not sig:
            self.stack.push(BitNum(count).to_bytes())
            return
        if len(sig) == 64:
            schnorr_sig = sig
            sighash_num = 0
        elif len(sig) == 65 and sig[-1] != 0:
            schnorr_sig = sig[:-1]
            sighash_num = sig[-1]
        else:
            raise ScriptEngineError("Invalid tapscript signature length")
        if not self._consume_tapscript_sigop(sig):
            raise ScriptEngineError("Tapscript signature validation weight exceeded")

        script_code = ctx.script_code or ctx.utxo.scriptpubkey
        message_hash = self._compute_sighash(ctx, script_code, sighash_num)
        verified = self._verify_sig(ctx, pubkey, schnorr_sig, message_hash)
        self.stack.push(BitNum(count + int(verified)).to_bytes())

    def _consume_tapscript_sigop(self, signature: bytes) -> bool:
        if not signature:
            return True
        if self.tapscript_validation_weight_left is None:
            return False
        self.tapscript_validation_weight_left -= 50
        return self.tapscript_validation_weight_left >= 0

    def _handle_multisig(self, ctx: ScriptContext):
        """
        OP_CHECKMULTISIG:
            1) pop n, then pop that number of public keys
            2) pop m, then pop that number of signatures
            3) compare each signature with the corresponding public key
        """
        # Step 1: Extract values
        pubkeynum = self.stack.popnum()
        pubkeys = [self.stack.pop() for _ in range(pubkeynum)]
        signum = self.stack.popnum()
        sigs = [self.stack.pop() for _ in range(signum)]
        empty_byte = self.stack.pop()

        # Validate
        if empty_byte != b'':
            raise ScriptEngineError("Missing NULLDUMMY at bottom of stack for OP_CHECKMULTISIG")

        # Step 2: Initialize indexes
        sig_index = 0
        key_index = 0
        matches = 0

        # Use script_code from context if available (for P2SH), otherwise use scriptpubkey
        script_code = ctx.script_code if hasattr(ctx, 'script_code') and ctx.script_code else ctx.utxo.scriptpubkey

        # Step 3: Try to match signatures to public keys
        while sig_index < len(sigs) and key_index < len(pubkeys):
            sig = sigs[sig_index]
            pub = pubkeys[key_index]

            # Signature should be DER-encoded with sighash num
            der_sig = sig[:-1]
            sighash_num = sig[-1]
            message_hash = self._compute_sighash(ctx, script_code, sighash_num)

            if sig_engine.verify_ecdsa_sig(
                    signature=der_sig,
                    message=message_hash,
                    public_key=pub,
                    strict_der=bool(ctx.script_flags & ScriptVerifyFlag.DERSIG),
            ):
                matches += 1
                sig_index += 1

            key_index += 1  # always advance key_index

        # Push bool
        self.stack.pushbool(matches == len(sigs))

    def _checklocktime(self, ctx: ScriptContext) -> bool:
        """
        OP_CHECKLOCKTIMEVERIFY: When executed, if any of the following conditions are true, the script interpreter will terminate with an error:

            -the stack is empty; or
            -the top item on the stack is less than 0; or
            -the lock-time type (height vs. timestamp) of the top stack item and the nLockTime field are not the
            same; or
            -the top stack item is greater than the transaction's nLockTime field; or
            -the nSequence field of the txin is 0xffffffff;

        Otherwise, script execution will continue as if a NOP had been executed.
        """
        # --- check stack non-empty
        if self.stack.height == 0:
            self.ops_log.append("OP_CHECKLOCKTIMEVERIFY fails: empty stack")
            return False

        # --- top item is negative
        locktime_bytes = self.stack.top
        locktime = BitNum.from_bytes(locktime_bytes)
        if locktime < 0:
            self.ops_log.append("OP_CHECKLOCKTIMEVERIFY fails: negative locktime")
            return False

        # --- get tx from ctx for nLockTime field
        tx = ctx.tx
        input_index = ctx.input_index
        if tx is None:
            self.ops_log.append("OP_CHECKLOCKTIMEVERIFY fails: tx missing from context")
            return False

        # --- check txIn sequence to make sure its not 0xffffffff
        sequence = tx.inputs[input_index].sequence
        if sequence == 0xffffffff:
            self.ops_log.append("OP_CHECKLOCKTIMEVERIFY fails: input sequence set to 0xffffffff")
            return False

        # --- locktime type must match
        tx_locktime = tx.locktime
        stack_is_timestamp = locktime >= LOCKTIME_THRESHOLD
        tx_is_timestamp = tx_locktime >= LOCKTIME_THRESHOLD
        if stack_is_timestamp != tx_is_timestamp:
            stack_type = "timestamp" if stack_is_timestamp else "block height"
            tx_type = "timestamp" if tx_is_timestamp else "block height"
            self.ops_log.append(
                f"OP_CHECKLOCKTIMEVERIFY fails: locktime type mismatch -- "
                f"stack uses {stack_type} but tx nLockTime uses {tx_type}"
            )
            return False

        # --- tx locktime must be >= stack locktime
        if tx_locktime < locktime:
            self.ops_log.append("OP_CHECKLOCKTIMEVERIFY fails: tx locktime is less than locktime")
            return False

        # --- locktime verified | functions as NOP
        return True

    def _parse_control_block(self, control_block: bytes) -> tuple:
        """
        We parse the control block and return a tuple containing the parity bit, the x-only pubkey and the merkle proof.
        """
        block_stream = get_stream(control_block)

        control_byte = read_stream(block_stream, 1)
        xonly_pubkey = read_stream(block_stream, ECC.COORD_BYTES)
        merkle_proof = read_stream(block_stream, len(control_block) - (1 + ECC.COORD_BYTES))

        # --- LOGGING
        print(f"CONTROL BYTE: {control_byte.hex()}")
        print(f"XONLY PUBKEY: {xonly_pubkey.hex()}")
        print(f"MERKLE PROOF: {merkle_proof.hex()}")

        return control_byte[-1], xonly_pubkey, merkle_proof

    def validate_segwit(self, scriptpubkey: ScriptPubKey, ctx: ScriptContext) -> bool:
        """
        For use with P2WPKH and P2WSH
        """
        # Clear stacks
        self.clear_stacks()

        # Get WitnessField from context
        tx = ctx.tx
        input_index = ctx.input_index
        witness_field: Witness = tx.witness[input_index]
        utxo = ctx.utxo

        # Find type
        is_p2wpkh = False
        is_p2wsh = False
        is_p2tr = False

        match scriptpubkey.script_type:
            case ScriptType.P2WPKH:
                is_p2wpkh = True
            case ScriptType.P2WSH:
                is_p2wsh = True
            case ScriptType.P2TR:
                is_p2tr = True

        # TODO: Add validation here for ScriptPubKey type for mandatory spend fields

        # Handle P2WPKH
        if is_p2wpkh:
            # Validation
            if len(witness_field.items) != 2:
                raise ScriptEngineError("Expected 2 stackitems for P2WPKH Witness")

            # Push Signature and public key to stack
            sig = witness_field.items[0]
            pubkey = witness_field.items[1]
            self.stack.push(sig)
            self.stack.push(pubkey)

            # Get pubkeyhash from ScriptPubKey and create P2PKH script
            pubkeyhash = scriptpubkey.script[2:]
            p2pkh_script = P2PKH_Key.from_pubkeyhash(pubkeyhash)

            # BIP143 uses the serialized P2PKH script as scriptCode for P2WPKH.
            ctx = ctx.with_script_code(serialize_data(p2pkh_script.script))

            # Execute the P2PKH script
            self.execute_script(p2pkh_script.script, ctx)

        # Handle P2WSH
        if is_p2wsh:
            stackitems = len(witness_field.items)
            # Validation
            if stackitems < 1:
                raise ScriptEngineError("P2WSH witness is missing its witness script")

            # Script
            script = witness_field.items[-1]
            # Hash script
            hashed_script = sha256(script)
            # Compare to Scriptpubkey
            pubkeyhash = scriptpubkey.script[2:]

            # Return False if hashed script != pubkeyhash
            if pubkeyhash != hashed_script:
                self.ops_log.append("P2WSH Script fails pubkeyhash validation")
                return False

            # Push items to Witness field in reverse order
            sig_list = witness_field.items[:-1][::-1]
            self.stack.pushlist(sig_list)

            # Add serialized script as script code
            ctx = ctx.with_script_code(serialize_data(script))

            # Execute the P2WSH script
            self.execute_script(script, ctx)

        # Handle P2TR
        if is_p2tr:
            # Sort into key-path or spend-path
            stackitems = len(witness_field.items)
            if stackitems == 0:
                return False
            if stackitems == 1:
                # Key-path
                sig = witness_field.items[0]
                if len(sig) == 65:
                    # Get hash_type
                    hash_type = sig[-1]
                    sig = sig[:-1]
                else:
                    hash_type = 0

                tweaked_pubkey = scriptpubkey.script[2:]
                sighash = sig_engine.get_taproot_sighash(
                    tx=tx,
                    input_index=input_index,
                    utxos=ctx.utxos,
                    sighash_num=hash_type
                )
                valid_sig = sig_engine.verify_schnorr_sig(tweaked_pubkey, msg=sighash, sig=sig)
                return valid_sig
            else:
                # Script-path | All witness elements are datapushes
                witness_items = list(witness_field.items)  # shallow copy
                control_block = witness_items.pop(-1)  # Last element of witness is control block
                leaf_script = witness_items.pop(-1)  # second last element is leaf script
                tweaked_pubkey_bytes = scriptpubkey.script[2:]  # Same as key-path

                # --- Validate control block
                if not validate_control_block(control_block, leaf_script, tweaked_pubkey_bytes):
                    logger.error(f"Control block {control_block} not valid")
                    return False

                # Push remaining witness items and execute leaf_script
                self.stack.pushlist(witness_items)
                self.tapscript_validation_weight_left = len(witness_field.to_bytes()) + 50
                leaf_version = bytes([control_block[0] & 0xfe])
                leaf_hash = Leaf(leaf_script, leaf_version=leaf_version).leaf_hash
                tapscript_ctx = replace(
                    ctx,
                    signature_version=SignatureVersion.TAPSCRIPT,
                    tapleaf_hash=leaf_hash,
                ) if hasattr(ctx, "signature_version") else replace(
                    ctx,
                    tapscript=True,
                    merkle_root=leaf_hash,
                )
                if not self.execute_script(leaf_script, tapscript_ctx):
                    return False

        # Validate the stack
        return self.validate_stack()

    def validate_script_pair(self, scriptpubkey: ScriptPubKey, scriptsig: ScriptSig, ctx: ScriptContext = None) -> \
            bool:
        """
        We validate the scriptsig + scriptpubkey against the given ExecutionContext. For use with legacy signatures
        """
        # Proceed based on P2SH
        if not P2SH_Key.matches(scriptpubkey.script):
            # Not P2SH, validate combined script pairs
            return self.validate_script(scriptsig.script + scriptpubkey.script, ctx)

        # BIP16 requires a push-only scriptSig.
        operations = parse_script_ops(scriptsig.script)
        if not operations or any(data is None and opcode > 0x60 for opcode, data in operations):
            self.ops_log.append("P2SH scriptSig is not push-only")
            return False

        self.clear_stacks()  # Clear stacks here for P2SH

        # Execute scriptSig
        if not self.execute_script(scriptsig.script, ctx) or self.stack.height == 0:
            return False

        # Before processing the scriptpubkey we copy the redeem_script
        redeem_script = self.stack.top

        # Execute scriptpubkey
        self.execute_script(scriptpubkey.script, ctx)

        # Stack should now have 1 on top of stack and signatures for redeem script
        if not op_verify(self.stack):  # op_verify
            self.ops_log.append("Script Invalid -- P2SH ScriptPubKey failed OP_EQUAL check for HASH160")
            return False

        # Nested SegWit requires scriptSig to contain exactly one canonical
        # push of the witness program, with all unlocking data in the witness.
        if P2WPKH_Key.matches(redeem_script) or P2WSH_Key.matches(redeem_script):
            if scriptsig.script != encode_pushdata(redeem_script):
                self.ops_log.append("Nested witness scriptSig contains extra or non-canonical data")
                return False
            nested_key = classify_scriptpubkey(redeem_script)
            nested_ctx = replace(
                ctx,
                signature_version=SignatureVersion.WITNESS_V0,
            ) if hasattr(ctx, "signature_version") else replace(ctx, is_segwit=True)
            return self.validate_segwit(nested_key, nested_ctx)

        # Execute the legacy redeem script with the stack left by scriptSig
        # (minus the redeem script consumed by HASH160).
        new_ctx = replace(ctx, script_code=redeem_script)
        if not self.execute_script(redeem_script, new_ctx):
            return False
        return self.validate_stack()

    @staticmethod
    def _script_bytes(script: bytes | BytesIO) -> bytes:
        if isinstance(script, bytes):
            return script
        if not isinstance(script, BytesIO):
            raise TypeError("Script execution requires bytes or BytesIO")
        position = script.tell()
        value = script.read()
        script.seek(position)
        return value

    def _append_trace_step(
            self,
            state: _TraceState,
            instruction: Instruction,
            byte_offset: int,
            main_before: StackSnapshot,
            alt_before: StackSnapshot,
            diagnostic: TraceDiagnostic | None = None,
    ) -> None:
        opcode = OpcodeMetadata.create(
            value=instruction.opcode,
            byte_offset=byte_offset,
            raw=instruction.raw,
            is_push=instruction.is_push,
            push_data=instruction.push_data,
        )
        state.steps.append(ExecutionTraceStep(
            index=len(state.steps),
            opcode=opcode,
            main_stack_before=main_before,
            main_stack_after=StackSnapshot.capture(self.stack),
            alt_stack_before=alt_before,
            alt_stack_after=StackSnapshot.capture(self.alt_stack),
            explanation=explain_opcode(opcode),
            diagnostic=diagnostic,
        ))

    @staticmethod
    def _instruction_failure(
            *,
            code: str,
            message: str,
            step_index: int,
            opcode_name: str,
            exception: Exception | None = None,
    ) -> TraceDiagnostic:
        return TraceDiagnostic(
            code=code,
            message=message,
            step_index=step_index,
            opcode_name=opcode_name,
            exception_type=type(exception).__name__ if exception is not None else None,
        )

    def _execute_script(
            self,
            script: bytes | BytesIO,
            ctx: ScriptContext,
            *,
            trace_state: _TraceState | None,
            byte_offset_base: int,
    ) -> bool:
        stream = get_stream(script) if isinstance(script, bytes) else script
        valid_script = True

        while valid_script:
            relative_offset = stream.tell()
            try:
                instruction = self._read_instructions(stream)
            except Exception as exc:
                if trace_state is not None:
                    trace_state.diagnostic = TraceDiagnostic(
                        code="parse-error",
                        message=str(exc) or f"Script parsing raised {type(exc).__name__}.",
                        exception_type=type(exc).__name__,
                    )
                raise

            if instruction is None:
                self.ops_log.append("--- END OF SCRIPT ---")
                break

            opcode = instruction.opcode
            opcode_name = _OP.get_name(opcode) or f"OP_UNKNOWN_{opcode:02X}"
            self.ops_log.append(_OP.get_name(opcode))
            main_before = StackSnapshot.capture(self.stack) if trace_state is not None else None
            alt_before = StackSnapshot.capture(self.alt_stack) if trace_state is not None else None
            selected_branch: tuple[bytes, int] | None = None
            diagnostic: TraceDiagnostic | None = None

            try:
                if instruction.is_push:
                    self.stack.push(instruction.push_data or b"")
                    self.ops_log.append((instruction.push_data or b"").hex())
                elif opcode == 0:
                    self.stack.pushbool(False)
                elif 0x51 <= opcode <= 0x60:
                    self.stack.push(BitNum(opcode - 0x50).to_bytes())
                elif opcode == 0x61:
                    pass
                elif opcode in (0x63, 0x64):
                    branch, branch_offset = self._select_conditional_branch(opcode, stream)
                    selected_branch = (branch, byte_offset_base + branch_offset)
                elif opcode == 0x6a:
                    valid_script = False
                elif opcode in (0xac, 0xae, 0xba):
                    self._handle_signatures(opcode, ctx)
                elif opcode == 0xb1:
                    if ctx is not None and ctx.script_flags & ScriptVerifyFlag.CHECKLOCKTIMEVERIFY:
                        valid_script = self._checklocktime(ctx)
                else:
                    func = OPCODE_MAP[opcode]
                    if opcode in (0x6b, 0x6c):
                        func(self.stack, self.alt_stack)
                    elif opcode in (0x69, 0x88, 0x9d):
                        valid_script = func(self.stack)
                    elif opcode in (0xad, 0xaf):
                        self._handle_checksig(ctx) if opcode == 0xad else self._handle_multisig(ctx)
                        valid_script = op_verify(self.stack)
                    else:
                        func(self.stack)
            except Exception as exc:
                if trace_state is not None:
                    diagnostic = self._instruction_failure(
                        code="execution-error",
                        message=str(exc) or f"{opcode_name} raised {type(exc).__name__}.",
                        step_index=len(trace_state.steps),
                        opcode_name=opcode_name,
                        exception=exc,
                    )
                    trace_state.diagnostic = diagnostic
                    self._append_trace_step(
                        trace_state,
                        instruction,
                        byte_offset_base + relative_offset,
                        main_before,
                        alt_before,
                        diagnostic,
                    )
                raise

            if trace_state is not None:
                if not valid_script:
                    diagnostic = self._instruction_failure(
                        code="opcode-failed",
                        message=f"{opcode_name} caused script execution to fail.",
                        step_index=len(trace_state.steps),
                        opcode_name=opcode_name,
                    )
                    trace_state.diagnostic = diagnostic
                self._append_trace_step(
                    trace_state,
                    instruction,
                    byte_offset_base + relative_offset,
                    main_before,
                    alt_before,
                    diagnostic,
                )

            if selected_branch is not None:
                branch, branch_offset = selected_branch
                valid_script = self._execute_script(
                    branch,
                    ctx,
                    trace_state=trace_state,
                    byte_offset_base=branch_offset,
                )

        if not valid_script:
            self.ops_log.append("Invalid script")
            self.ops_log.append(to_asm(script))
        return valid_script

    def execute_script(
            self,
            script: bytes | BytesIO,
            ctx: ScriptContext = None,
            *,
            trace: bool = False,
    ) -> bool:
        """Execute a script, optionally retaining an immutable trace in ``last_trace``.

        The return value, stack mutations, operation log, and raised exceptions are
        unchanged when tracing is disabled. When tracing is enabled, exceptions are
        still raised after the failing instruction and its diagnostic are captured.
        """
        if not isinstance(trace, bool):
            raise TypeError("trace must be a boolean")

        self.last_trace = None
        trace_state = _TraceState(self._script_bytes(script)) if trace else None
        root_offset = -script.tell() if isinstance(script, BytesIO) else 0
        try:
            result = self._execute_script(
                script,
                ctx,
                trace_state=trace_state,
                byte_offset_base=root_offset,
            )
        except Exception:
            if trace_state is not None:
                self.last_trace = ExecutionTrace(
                    trace_state.script,
                    tuple(trace_state.steps),
                    success=False,
                    diagnostic=trace_state.diagnostic,
                )
            raise

        if trace_state is not None:
            self.last_trace = ExecutionTrace(
                trace_state.script,
                tuple(trace_state.steps),
                success=result,
                diagnostic=trace_state.diagnostic,
            )
        return result

    def trace_script(self, script: bytes | BytesIO, ctx: ScriptContext = None) -> ExecutionTrace:
        """Execute a script and return its trace without suppressing execution exceptions."""
        self.execute_script(script, ctx, trace=True)
        if self.last_trace is None:  # pragma: no cover - defensive invariant
            raise RuntimeError("Tracing completed without producing an execution trace")
        return self.last_trace

    def validate_script(
            self,
            script: bytes,
            ctx: ScriptContext = None,
            *,
            require_clean_stack: bool = True,
            trace: bool = False,
    ) -> bool:
        # Clear stacks
        self.clear_stacks()

        # Execute script
        if not self.execute_script(script, ctx, trace=trace):
            return False  # Triggered invalid script

        # Validate stack
        stack_height = self.stack.height
        result = self.validate_stack(require_clean_stack=require_clean_stack)
        if trace and not result and self.last_trace is not None:
            if stack_height == 0:
                code = "empty-final-stack"
                message = "The script finished with an empty main stack."
            elif require_clean_stack and stack_height != 1:
                code = "unclean-final-stack"
                message = f"The script finished with {stack_height} items instead of exactly one."
            else:
                code = "false-final-value"
                message = "The script finished with a false value on top of the main stack."
            diagnostic = TraceDiagnostic(code=code, message=message)
            self.last_trace = replace(
                self.last_trace,
                success=False,
                diagnostic=diagnostic,
            )
        return result

    def validate_stack(self, *, require_clean_stack: bool = True) -> bool:
        """
        Called at the end of the script engine. Return False if any of the following are True:
            - Stack is empty
            - Only element left on the stack is OP_0 (aka b'')
            - More than one element is left when clean-stack semantics apply
            - Script exits prematurely (e.g. OP_RETURN)
        """
        if self.stack.height == 0:
            return False
        if require_clean_stack and self.stack.height != 1:
            return False
        last_element = self.stack.pop()  # Also clears stack for next execution
        return self._stack_value_is_true(last_element)


# --- TESTING --- #

if __name__ == "__main__":
    sep = "---" * 80

    print("--- CONDITIONAL SCRIPT TESTING ---  ")

    engine = ScriptEngine()
    test_script = bytes.fromhex("00645268")
    result = engine.validate_script(test_script)
    print(f"TEST SCRIPT: {to_asm(test_script)}")
    print(f"SCRIPT ENGINE STACK RESULT: {result}")
