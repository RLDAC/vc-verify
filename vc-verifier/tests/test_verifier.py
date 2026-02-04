"""Tests for VC Verifier."""

import base64
import gzip
import json

import pytest
import respx
from httpx import Response

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.backends import default_backend

from vc_verifier import (
    VCVerifier,
    VerificationResult,
    DIDResolver,
    StatusListChecker,
    CredentialStatus,
)
from vc_verifier.verifier import VerificationStatus


# Test fixtures
@pytest.fixture
def ec_key_pair():
    """Generate a test EC P-256 key pair."""
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key


@pytest.fixture
def public_key_jwk(ec_key_pair):
    """Get the public key as JWK."""
    _, public_key = ec_key_pair
    public_numbers = public_key.public_numbers()

    x_bytes = public_numbers.x.to_bytes(32, byteorder="big")
    y_bytes = public_numbers.y.to_bytes(32, byteorder="big")

    return {
        "kty": "EC",
        "crv": "P-256",
        "x": base64.urlsafe_b64encode(x_bytes).decode().rstrip("="),
        "y": base64.urlsafe_b64encode(y_bytes).decode().rstrip("="),
    }


@pytest.fixture
def did_document(public_key_jwk):
    """Create a test DID Document."""
    return {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/jwk/v1",
        ],
        "id": "did:web:example.com",
        "verificationMethod": [
            {
                "id": "did:web:example.com#key-1",
                "type": "JsonWebKey",
                "controller": "did:web:example.com",
                "publicKeyJwk": public_key_jwk,
            }
        ],
        "authentication": ["did:web:example.com#key-1"],
        "assertionMethod": ["did:web:example.com#key-1"],
    }


def sign_credential(credential: dict, private_key) -> dict:
    """Sign a credential with the test private key."""
    # Canonicalize
    canonical = json.dumps(credential, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    message_bytes = canonical.encode("utf-8")

    # Sign with ECDSA
    signature = private_key.sign(
        message_bytes,
        ec.ECDSA(hashes.SHA256()),
    )

    # Base64url encode (AWS KMS returns DER format)
    proof_value = base64.urlsafe_b64encode(signature).decode().rstrip("=")

    # Return signed credential
    signed = credential.copy()
    signed["proof"] = {
        "type": "DataIntegrityProof",
        "cryptosuite": "ecdsa-jcs-2022",
        "created": "2025-01-15T10:00:00Z",
        "verificationMethod": "did:web:example.com#key-1",
        "proofPurpose": "assertionMethod",
        "proofValue": proof_value,
    }
    return signed


def create_empty_statuslist(length: int = 131072) -> str:
    """Create an empty (all valid) StatusList."""
    bitstring = bytes(length // 8)
    compressed = gzip.compress(bitstring)
    return base64.b64encode(compressed).decode()


def create_revoked_statuslist(revoked_indices: list[int], length: int = 131072) -> str:
    """Create a StatusList with specific indices revoked."""
    ba = bytearray(length // 8)
    for index in revoked_indices:
        byte_index = index // 8
        bit_position = 7 - (index % 8)
        ba[byte_index] |= 1 << bit_position
    compressed = gzip.compress(bytes(ba))
    return base64.b64encode(compressed).decode()


class TestDIDResolver:
    """Tests for DID resolution."""

    def test_did_to_url_simple(self):
        """Test simple did:web to URL conversion."""
        resolver = DIDResolver()
        url = resolver._did_to_url("did:web:example.com")
        assert url == "https://example.com/.well-known/did.json"

    def test_did_to_url_with_path(self):
        """Test did:web with path to URL conversion."""
        resolver = DIDResolver()
        url = resolver._did_to_url("did:web:example.com:users:alice")
        assert url == "https://example.com/users/alice/did.json"

    def test_did_to_url_with_port(self):
        """Test did:web with port to URL conversion."""
        resolver = DIDResolver()
        url = resolver._did_to_url("did:web:example.com%3A8080")
        assert url == "https://example.com:8080/.well-known/did.json"

    def test_did_to_url_with_fragment(self):
        """Test did:web with fragment."""
        resolver = DIDResolver()
        url = resolver._did_to_url("did:web:example.com#key-1")
        assert url == "https://example.com/.well-known/did.json"

    @respx.mock
    def test_resolve_did(self, did_document):
        """Test DID resolution."""
        respx.get("https://example.com/.well-known/did.json").mock(
            return_value=Response(200, json=did_document)
        )

        resolver = DIDResolver()
        doc = resolver.resolve("did:web:example.com")

        assert doc.id == "did:web:example.com"
        assert len(doc.verification_methods) == 1
        assert doc.verification_methods[0].id == "did:web:example.com#key-1"


class TestStatusListChecker:
    """Tests for StatusList verification."""

    def test_decode_bitstring(self):
        """Test bitstring decoding."""
        checker = StatusListChecker()
        encoded = create_empty_statuslist(1024)
        decoded = checker._decode_bitstring(encoded)
        assert len(decoded) == 1024 // 8

    def test_get_bit_all_zeros(self):
        """Test getting bits from empty (all valid) bitstring."""
        checker = StatusListChecker()
        bitstring = bytes(128)  # 1024 bits, all zeros

        assert checker._get_bit(bitstring, 0) is False
        assert checker._get_bit(bitstring, 100) is False
        assert checker._get_bit(bitstring, 1023) is False

    def test_get_bit_with_revoked(self):
        """Test getting bits from bitstring with revoked credentials."""
        checker = StatusListChecker()

        # Create bitstring with index 42 revoked
        ba = bytearray(128)
        byte_index = 42 // 8
        bit_position = 7 - (42 % 8)
        ba[byte_index] |= 1 << bit_position
        bitstring = bytes(ba)

        assert checker._get_bit(bitstring, 41) is False
        assert checker._get_bit(bitstring, 42) is True
        assert checker._get_bit(bitstring, 43) is False

    @respx.mock
    def test_check_status_valid(self):
        """Test checking status of valid credential."""
        sl_credential = {
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential", "StatusList2021Credential"],
            "credentialSubject": {
                "type": "StatusList2021",
                "statusPurpose": "revocation",
                "encodedList": create_empty_statuslist(),
            },
        }
        respx.get("https://example.com/.well-known/vc/status/revocation").mock(
            return_value=Response(200, json=sl_credential)
        )

        credential = {
            "credentialStatus": {
                "type": "StatusList2021Entry",
                "statusListCredential": "https://example.com/.well-known/vc/status/revocation",
                "statusListIndex": "42",
                "statusPurpose": "revocation",
            }
        }

        checker = StatusListChecker()
        result = checker.check_status(credential)

        assert result is not None
        assert result.status == CredentialStatus.VALID

    @respx.mock
    def test_check_status_revoked(self):
        """Test checking status of revoked credential."""
        sl_credential = {
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential", "StatusList2021Credential"],
            "credentialSubject": {
                "type": "StatusList2021",
                "statusPurpose": "revocation",
                "encodedList": create_revoked_statuslist([42]),
            },
        }
        respx.get("https://example.com/.well-known/vc/status/revocation").mock(
            return_value=Response(200, json=sl_credential)
        )

        credential = {
            "credentialStatus": {
                "type": "StatusList2021Entry",
                "statusListCredential": "https://example.com/.well-known/vc/status/revocation",
                "statusListIndex": "42",
                "statusPurpose": "revocation",
            }
        }

        checker = StatusListChecker()
        result = checker.check_status(credential)

        assert result is not None
        assert result.status == CredentialStatus.REVOKED


class TestVCVerifier:
    """Tests for full VC verification."""

    @respx.mock
    def test_verify_valid_credential(self, ec_key_pair, did_document):
        """Test verifying a valid credential."""
        private_key, _ = ec_key_pair

        # Mock DID resolution
        respx.get("https://example.com/.well-known/did.json").mock(
            return_value=Response(200, json=did_document)
        )

        # Create unsigned credential
        credential = {
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "id": "urn:uuid:test-123",
            "type": ["VerifiableCredential"],
            "issuer": "did:web:example.com",
            "validFrom": "2025-01-01T00:00:00Z",
            "credentialSubject": {
                "id": "did:example:holder",
                "name": "Test User",
            },
        }

        # Sign the credential
        signed_credential = sign_credential(credential, private_key)

        # Verify
        verifier = VCVerifier(verify_status=False)
        result = verifier.verify(signed_credential)

        assert result.status == VerificationStatus.VALID
        assert result.is_valid is True
        assert result.proof is not None
        assert result.proof.valid is True

    @respx.mock
    def test_verify_tampered_credential(self, ec_key_pair, did_document):
        """Test verifying a tampered credential."""
        private_key, _ = ec_key_pair

        # Mock DID resolution
        respx.get("https://example.com/.well-known/did.json").mock(
            return_value=Response(200, json=did_document)
        )

        # Create and sign credential
        credential = {
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "id": "urn:uuid:test-123",
            "type": ["VerifiableCredential"],
            "issuer": "did:web:example.com",
            "validFrom": "2025-01-01T00:00:00Z",
            "credentialSubject": {
                "id": "did:example:holder",
                "name": "Test User",
            },
        }
        signed_credential = sign_credential(credential, private_key)

        # Tamper with the credential
        signed_credential["credentialSubject"]["name"] = "Tampered Name"

        # Verify
        verifier = VCVerifier(verify_status=False)
        result = verifier.verify(signed_credential)

        assert result.status == VerificationStatus.INVALID
        assert result.is_valid is False
        assert result.proof is not None
        assert result.proof.valid is False

    def test_verify_missing_proof(self):
        """Test verifying credential without proof."""
        credential = {
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential"],
            "issuer": "did:web:example.com",
            "credentialSubject": {"id": "did:example:holder"},
        }

        verifier = VCVerifier(verify_status=False)
        result = verifier.verify(credential)

        assert result.status == VerificationStatus.INVALID
        assert "Missing proof" in result.errors

    def test_verify_unsupported_cryptosuite(self):
        """Test verifying credential with unsupported cryptosuite."""
        credential = {
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential"],
            "issuer": "did:web:example.com",
            "credentialSubject": {"id": "did:example:holder"},
            "proof": {
                "type": "DataIntegrityProof",
                "cryptosuite": "unsupported-suite",
                "verificationMethod": "did:web:example.com#key-1",
                "proofValue": "test",
            },
        }

        verifier = VCVerifier(verify_status=False)
        result = verifier.verify(credential)

        assert result.status == VerificationStatus.INVALID
        assert result.proof is not None
        assert result.proof.valid is False
        assert "unsupported" in result.proof.error.lower()


class TestJCSCanonicalization:
    """Tests for JSON Canonicalization Scheme."""

    def test_sort_keys(self):
        """Test that keys are sorted."""
        verifier = VCVerifier()
        data = {"z": 1, "a": 2, "m": 3}
        result = verifier._canonicalize_json(data)
        assert result == '{"a":2,"m":3,"z":1}'

    def test_no_spaces(self):
        """Test that no extra spaces are added."""
        verifier = VCVerifier()
        data = {"key": "value", "number": 123}
        result = verifier._canonicalize_json(data)
        assert " " not in result

    def test_unicode_preserved(self):
        """Test that unicode is preserved (not escaped)."""
        verifier = VCVerifier()
        data = {"name": "Jean-Pierre"}
        result = verifier._canonicalize_json(data)
        # ensure_ascii=False means unicode is preserved
        assert result == '{"name":"Jean-Pierre"}'
