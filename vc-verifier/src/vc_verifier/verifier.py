"""
Verifiable Credentials Verifier.

Verifies W3C Verifiable Credentials with Data Integrity Proofs.

Supported:
- Cryptosuite: ecdsa-jcs-2022
- Curve: P-256 (secp256r1)
- DID Method: did:web
- Status: StatusList2021
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature

from vc_verifier.did_resolver import DIDResolver, DIDResolutionError, PublicKeyJWK
from vc_verifier.statuslist import (
    StatusListChecker,
    StatusCheckResult,
    CredentialStatus,
    StatusListError,
)


class VerificationStatus(Enum):
    """Overall verification status."""

    VALID = "valid"
    INVALID = "invalid"
    ERROR = "error"


@dataclass
class ProofVerificationResult:
    """Result of cryptographic proof verification."""

    valid: bool
    cryptosuite: str
    verification_method: str
    error: str | None = None


@dataclass
class VerificationResult:
    """Complete verification result."""

    status: VerificationStatus
    credential_id: str | None
    issuer: str | None
    proof: ProofVerificationResult | None = None
    credential_status: StatusCheckResult | None = None
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def is_valid(self) -> bool:
        """Check if the credential is fully valid."""
        if self.status != VerificationStatus.VALID:
            return False
        if self.proof and not self.proof.valid:
            return False
        if self.credential_status and self.credential_status.status not in (
            CredentialStatus.VALID,
            None,
        ):
            return False
        return True


class VCVerifier:
    """Verifiable Credentials verifier.

    Supports:
    - Data Integrity Proofs with ecdsa-jcs-2022 cryptosuite
    - did:web DID resolution
    - StatusList2021 revocation checking
    """

    SUPPORTED_CRYPTOSUITES = {"ecdsa-jcs-2022"}
    SUPPORTED_PROOF_TYPES = {"DataIntegrityProof"}

    def __init__(
        self,
        did_resolver: DIDResolver | None = None,
        statuslist_checker: StatusListChecker | None = None,
        verify_status: bool = True,
    ) -> None:
        """Initialize the verifier.

        Args:
            did_resolver: Custom DID resolver. Created if not provided.
            statuslist_checker: Custom StatusList checker. Created if not provided.
            verify_status: Whether to check credential status (revocation).
        """
        self.did_resolver = did_resolver or DIDResolver()
        self.statuslist_checker = statuslist_checker or StatusListChecker()
        self.verify_status = verify_status

    def verify(self, credential: dict[str, Any]) -> VerificationResult:
        """Verify a Verifiable Credential.

        Performs:
        1. Structure validation
        2. Proof verification (cryptographic signature)
        3. Status verification (if credentialStatus present)

        Args:
            credential: The Verifiable Credential to verify.

        Returns:
            VerificationResult with details of all checks.
        """
        errors: list[str] = []
        warnings: list[str] = []

        # Extract basic info
        credential_id = credential.get("id")
        issuer = self._extract_issuer(credential)

        # Validate structure
        structure_errors = self._validate_structure(credential)
        if structure_errors:
            return VerificationResult(
                status=VerificationStatus.INVALID,
                credential_id=credential_id,
                issuer=issuer,
                errors=structure_errors,
            )

        # Verify proof
        proof_result = self._verify_proof(credential)
        if not proof_result.valid:
            errors.append(f"Proof verification failed: {proof_result.error}")

        # Check credential status
        status_result: StatusCheckResult | None = None
        if self.verify_status:
            try:
                status_result = self.statuslist_checker.check_status(credential)
                if status_result and status_result.status == CredentialStatus.REVOKED:
                    errors.append(status_result.message)
                elif status_result and status_result.status == CredentialStatus.SUSPENDED:
                    warnings.append(status_result.message)
            except StatusListError as e:
                warnings.append(f"Could not verify status: {e}")

        # Determine overall status
        if errors:
            status = VerificationStatus.INVALID
        elif not proof_result.valid:
            status = VerificationStatus.INVALID
        else:
            status = VerificationStatus.VALID

        return VerificationResult(
            status=status,
            credential_id=credential_id,
            issuer=issuer,
            proof=proof_result,
            credential_status=status_result,
            errors=errors,
            warnings=warnings,
        )

    def _extract_issuer(self, credential: dict[str, Any]) -> str | None:
        """Extract issuer ID from credential."""
        issuer = credential.get("issuer")
        if isinstance(issuer, str):
            return issuer
        if isinstance(issuer, dict):
            return issuer.get("id")
        return None

    def _validate_structure(self, credential: dict[str, Any]) -> list[str]:
        """Validate basic VC structure.

        Args:
            credential: The credential to validate.

        Returns:
            List of validation errors (empty if valid).
        """
        errors: list[str] = []

        # Required fields
        if "@context" not in credential:
            errors.append("Missing @context")
        if "type" not in credential:
            errors.append("Missing type")
        elif "VerifiableCredential" not in credential.get("type", []):
            errors.append("type must include 'VerifiableCredential'")
        if "issuer" not in credential:
            errors.append("Missing issuer")
        if "credentialSubject" not in credential:
            errors.append("Missing credentialSubject")
        if "proof" not in credential:
            errors.append("Missing proof")

        return errors

    def _verify_proof(self, credential: dict[str, Any]) -> ProofVerificationResult:
        """Verify the cryptographic proof.

        Args:
            credential: The signed credential.

        Returns:
            ProofVerificationResult with verification details.
        """
        proof = credential.get("proof", {})

        # Validate proof type
        proof_type = proof.get("type")
        if proof_type not in self.SUPPORTED_PROOF_TYPES:
            return ProofVerificationResult(
                valid=False,
                cryptosuite=proof.get("cryptosuite", "unknown"),
                verification_method=proof.get("verificationMethod", "unknown"),
                error=f"Unsupported proof type: {proof_type}",
            )

        # Validate cryptosuite
        cryptosuite = proof.get("cryptosuite")
        if cryptosuite not in self.SUPPORTED_CRYPTOSUITES:
            return ProofVerificationResult(
                valid=False,
                cryptosuite=cryptosuite or "unknown",
                verification_method=proof.get("verificationMethod", "unknown"),
                error=f"Unsupported cryptosuite: {cryptosuite}",
            )

        # Get verification method
        verification_method = proof.get("verificationMethod", "")
        if not verification_method:
            return ProofVerificationResult(
                valid=False,
                cryptosuite=cryptosuite,
                verification_method="",
                error="Missing verificationMethod in proof",
            )

        # Resolve DID and get public key
        try:
            public_key = self._resolve_public_key(verification_method)
        except DIDResolutionError as e:
            return ProofVerificationResult(
                valid=False,
                cryptosuite=cryptosuite,
                verification_method=verification_method,
                error=f"DID resolution failed: {e}",
            )

        # Verify signature
        try:
            signature_valid = self._verify_signature(credential, proof, public_key)
        except Exception as e:
            return ProofVerificationResult(
                valid=False,
                cryptosuite=cryptosuite,
                verification_method=verification_method,
                error=f"Signature verification error: {e}",
            )

        return ProofVerificationResult(
            valid=signature_valid,
            cryptosuite=cryptosuite,
            verification_method=verification_method,
            error=None if signature_valid else "Invalid signature",
        )

    def _resolve_public_key(self, verification_method: str) -> PublicKeyJWK:
        """Resolve a verification method to its public key.

        Args:
            verification_method: The verification method ID (e.g., did:web:example.com#key-1).

        Returns:
            The public key as JWK.

        Raises:
            DIDResolutionError: If resolution fails.
        """
        # Extract DID from verification method
        if "#" in verification_method:
            did = verification_method.split("#")[0]
        else:
            did = verification_method

        # Resolve DID Document
        did_document = self.did_resolver.resolve(did)

        # Find the verification method
        vm = did_document.get_verification_method(verification_method)
        if vm is None:
            raise DIDResolutionError(
                f"Verification method {verification_method} not found in DID Document"
            )

        if vm.public_key_jwk is None:
            raise DIDResolutionError(
                f"No publicKeyJwk in verification method {verification_method}"
            )

        if not vm.public_key_jwk.is_valid_p256():
            raise DIDResolutionError(
                f"Public key is not a valid P-256 EC key: {vm.public_key_jwk}"
            )

        return vm.public_key_jwk

    def _verify_signature(
        self,
        credential: dict[str, Any],
        proof: dict[str, Any],
        public_key: PublicKeyJWK,
    ) -> bool:
        """Verify the ECDSA signature.

        Implements ecdsa-jcs-2022 verification:
        1. Remove proof from credential
        2. Canonicalize with JCS (RFC 8785)
        3. Verify ECDSA P-256 signature

        Args:
            credential: The signed credential.
            proof: The proof object.
            public_key: The public key JWK.

        Returns:
            True if signature is valid, False otherwise.
        """
        # Remove proof from credential for verification
        unsigned_credential = {k: v for k, v in credential.items() if k != "proof"}

        # Canonicalize with JCS (JSON Canonicalization Scheme, RFC 8785)
        canonical_json = self._canonicalize_json(unsigned_credential)
        message_bytes = canonical_json.encode("utf-8")

        # Decode the signature (base64url, no padding)
        proof_value = proof.get("proofValue", "")
        signature_bytes = self._base64url_decode(proof_value)

        # Build EC public key from JWK
        ec_public_key = self._jwk_to_ec_public_key(public_key)

        # Verify ECDSA signature
        # Note: AWS KMS returns DER-encoded signatures, we need to handle both formats
        try:
            # First try DER format (from AWS KMS)
            ec_public_key.verify(
                signature_bytes,
                message_bytes,
                ec.ECDSA(hashes.SHA256()),
            )
            return True
        except InvalidSignature:
            return False
        except Exception:
            # Try raw r||s format (64 bytes for P-256)
            if len(signature_bytes) == 64:
                try:
                    # Convert raw r||s to DER
                    r = int.from_bytes(signature_bytes[:32], byteorder="big")
                    s = int.from_bytes(signature_bytes[32:], byteorder="big")
                    from cryptography.hazmat.primitives.asymmetric.utils import (
                        encode_dss_signature,
                    )

                    der_sig = encode_dss_signature(r, s)
                    ec_public_key.verify(
                        der_sig,
                        message_bytes,
                        ec.ECDSA(hashes.SHA256()),
                    )
                    return True
                except InvalidSignature:
                    return False
            return False

    def _canonicalize_json(self, data: dict[str, Any]) -> str:
        """Canonicalize JSON according to JCS (RFC 8785).

        Args:
            data: Dictionary to canonicalize.

        Returns:
            Canonical JSON string.
        """
        return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

    def _base64url_decode(self, data: str) -> bytes:
        """Decode base64url without padding.

        Args:
            data: Base64url encoded string.

        Returns:
            Decoded bytes.
        """
        # Add padding if needed
        padding = 4 - (len(data) % 4)
        if padding != 4:
            data += "=" * padding
        return base64.urlsafe_b64decode(data)

    def _jwk_to_ec_public_key(self, jwk: PublicKeyJWK) -> ec.EllipticCurvePublicKey:
        """Convert a JWK to an EC public key object.

        Args:
            jwk: The public key JWK (P-256).

        Returns:
            EC public key object.
        """
        # Decode x and y coordinates
        x_bytes = self._base64url_decode(jwk.x)
        y_bytes = self._base64url_decode(jwk.y)

        # Convert to integers
        x = int.from_bytes(x_bytes, byteorder="big")
        y = int.from_bytes(y_bytes, byteorder="big")

        # Create public key from numbers
        public_numbers = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1())
        return public_numbers.public_key()


def verify_credential(
    credential: dict[str, Any],
    verify_status: bool = True,
) -> VerificationResult:
    """Convenience function to verify a credential.

    Args:
        credential: The Verifiable Credential to verify.
        verify_status: Whether to check revocation status.

    Returns:
        VerificationResult with details of all checks.
    """
    verifier = VCVerifier(verify_status=verify_status)
    return verifier.verify(credential)
