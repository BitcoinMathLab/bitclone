from dataclasses import FrozenInstanceError

import pytest

from src.data import decode_der_signature, encode_der_signature
from src.script import ECDSASignatureVerificationResult, verify_input_ecdsa_signature
from src.tx import Tx, UTXO
from tests.script_vectors import build_p2pkh_case, build_p2wpkh_case


def test_verifies_candidate_der_against_legacy_input_context():
    case = build_p2pkh_case()
    signature_length = case.tx.inputs[0].scriptsig[0]
    original_signature = case.tx.inputs[0].scriptsig[1:1 + signature_length - 1]

    result = verify_input_ecdsa_signature(case.tx, 0, case.utxos, original_signature)

    assert isinstance(result, ECDSASignatureVerificationResult)
    assert result.script_type == "P2PKH"
    assert result.signature == original_signature
    assert result.sighash_type == 1
    assert result.digest.hex() == "d21483940571a138f8c768a97f1002cc6b6b0c4df9f647feb513b881162d66e6"
    assert result.valid is True


def test_valid_der_with_wrong_signature_returns_false():
    case = build_p2pkh_case()
    signature_length = case.tx.inputs[0].scriptsig[0]
    original_signature = case.tx.inputs[0].scriptsig[1:1 + signature_length - 1]
    r, s = decode_der_signature(original_signature)
    candidate = encode_der_signature(r, s + 1)

    result = verify_input_ecdsa_signature(case.tx, 0, case.utxos, candidate)

    assert result.valid is False


def test_verifies_candidate_der_against_native_p2wpkh_context():
    case = build_p2wpkh_case()
    original_signature = case.tx.witness[0].items[0][:-1]

    result = verify_input_ecdsa_signature(case.tx, 0, case.utxos, original_signature)

    assert result.script_type == "P2WPKH"
    assert result.signature == original_signature
    assert result.sighash_type == 1
    assert result.amount == 1_083_200
    assert result.script_code.hex() == "76a914841b80d2cc75f5345c482af96294d04fdd66b2b788ac"
    assert result.digest.hex() == "e4ce544b38c694f09ca943f9a53a9051c981a81177fc0f9d689e2873c5e95270"
    assert result.valid is True


@pytest.mark.parametrize("candidate", [b"", b"\x30\x01\x00", b"not DER"])
def test_rejects_malformed_der_without_leaking_parser_details(candidate):
    case = build_p2pkh_case()

    with pytest.raises(ValueError, match="not strict DER"):
        verify_input_ecdsa_signature(case.tx, 0, case.utxos, candidate)


def test_rejects_an_unlocking_public_key_that_does_not_match_the_utxo():
    case = build_p2pkh_case()
    tx = Tx.from_bytes(case.tx.to_bytes())
    script = bytearray(tx.inputs[0].scriptsig)
    script[-1] ^= 1
    tx.inputs[0].scriptsig = bytes(script)
    signature_length = case.tx.inputs[0].scriptsig[0]
    signature = case.tx.inputs[0].scriptsig[1:1 + signature_length - 1]

    with pytest.raises(ValueError, match="public key does not match"):
        verify_input_ecdsa_signature(tx, 0, case.utxos, signature)


def test_verification_result_is_immutable():
    case = build_p2wpkh_case()
    result = verify_input_ecdsa_signature(
        case.tx, 0, case.utxos, case.tx.witness[0].items[0][:-1]
    )

    with pytest.raises(FrozenInstanceError):
        result.valid = False
