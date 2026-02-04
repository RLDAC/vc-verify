"""
VC Verifier - Verifiable Credentials verification library.

Supports:
- W3C Data Integrity Proofs (ecdsa-jcs-2022 cryptosuite)
- did:web DID method resolution
- W3C StatusList2021 revocation/suspension checking
- ECDSA P-256 (secp256r1) signatures
"""

from vc_verifier.verifier import (
    VCVerifier,
    VerificationResult,
    verify_credential,
)
from vc_verifier.did_resolver import DIDResolver, DIDResolutionError
from vc_verifier.statuslist import StatusListChecker, CredentialStatus

__version__ = "0.1.0"

__all__ = [
    "VCVerifier",
    "VerificationResult",
    "verify_credential",
    "DIDResolver",
    "DIDResolutionError",
    "StatusListChecker",
    "CredentialStatus",
]
