"""
DID Resolver for did:web method.

Resolves did:web identifiers to DID Documents per W3C DID specification.
https://w3c-ccg.github.io/did-method-web/
"""

from __future__ import annotations

import httpx
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote


class DIDResolutionError(Exception):
    """Raised when DID resolution fails."""


@dataclass
class PublicKeyJWK:
    """EC P-256 public key in JWK format."""

    kty: str
    crv: str
    x: str
    y: str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PublicKeyJWK:
        """Create PublicKeyJWK from a JWK dictionary."""
        return cls(
            kty=data.get("kty", ""),
            crv=data.get("crv", ""),
            x=data.get("x", ""),
            y=data.get("y", ""),
        )

    def is_valid_p256(self) -> bool:
        """Check if this is a valid P-256 EC key."""
        return self.kty == "EC" and self.crv == "P-256" and bool(self.x) and bool(self.y)


@dataclass
class VerificationMethod:
    """DID Document verification method."""

    id: str
    type: str
    controller: str
    public_key_jwk: PublicKeyJWK | None = None


@dataclass
class DIDDocument:
    """W3C DID Document."""

    id: str
    verification_methods: list[VerificationMethod]
    authentication: list[str]
    assertion_method: list[str]

    def get_verification_method(self, method_id: str) -> VerificationMethod | None:
        """Get a verification method by ID."""
        for vm in self.verification_methods:
            if vm.id == method_id:
                return vm
        return None


class DIDResolver:
    """Resolver for did:web DID method."""

    def __init__(
        self,
        timeout: float = 30.0,
        verify_ssl: bool = True,
    ) -> None:
        """Initialize the DID resolver.

        Args:
            timeout: HTTP request timeout in seconds.
            verify_ssl: Whether to verify SSL certificates.
        """
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self._cache: dict[str, DIDDocument] = {}

    def _did_to_url(self, did: str) -> str:
        """Convert a did:web identifier to its resolution URL.

        did:web:example.com -> https://example.com/.well-known/did.json
        did:web:example.com:path:to:doc -> https://example.com/path/to/doc/did.json
        did:web:example.com%3A8080 -> https://example.com:8080/.well-known/did.json

        Args:
            did: The did:web identifier.

        Returns:
            The HTTPS URL to fetch the DID Document.

        Raises:
            DIDResolutionError: If the DID format is invalid.
        """
        if not did.startswith("did:web:"):
            raise DIDResolutionError(f"Invalid did:web identifier: {did}")

        # Remove the did:web: prefix
        domain_path = did[8:]

        # Handle fragment (e.g., did:web:example.com#key-1)
        if "#" in domain_path:
            domain_path = domain_path.split("#")[0]

        # Split by colon to get path segments
        parts = domain_path.split(":")

        # First part is the domain (with potential port encoded as %3A)
        domain = parts[0].replace("%3A", ":")

        # Remaining parts form the path
        if len(parts) > 1:
            path = "/" + "/".join(quote(p, safe="") for p in parts[1:]) + "/did.json"
        else:
            path = "/.well-known/did.json"

        return f"https://{domain}{path}"

    def resolve(self, did: str, use_cache: bool = True) -> DIDDocument:
        """Resolve a did:web identifier to its DID Document.

        Args:
            did: The did:web identifier (e.g., "did:web:example.com").
            use_cache: Whether to use cached results.

        Returns:
            The resolved DIDDocument.

        Raises:
            DIDResolutionError: If resolution fails.
        """
        # Normalize DID (remove fragment for caching)
        base_did = did.split("#")[0] if "#" in did else did

        # Check cache
        if use_cache and base_did in self._cache:
            return self._cache[base_did]

        # Build resolution URL
        url = self._did_to_url(did)

        try:
            with httpx.Client(timeout=self.timeout, verify=self.verify_ssl) as client:
                response = client.get(
                    url,
                    headers={"Accept": "application/did+ld+json, application/json"},
                )
                response.raise_for_status()
                data = response.json()

        except httpx.HTTPStatusError as e:
            raise DIDResolutionError(
                f"HTTP error resolving {did}: {e.response.status_code}"
            ) from e
        except httpx.RequestError as e:
            raise DIDResolutionError(f"Network error resolving {did}: {e}") from e
        except ValueError as e:
            raise DIDResolutionError(f"Invalid JSON in DID Document for {did}") from e

        # Parse DID Document
        doc = self._parse_did_document(data, base_did)

        # Cache result
        if use_cache:
            self._cache[base_did] = doc

        return doc

    def _parse_did_document(self, data: dict[str, Any], did: str) -> DIDDocument:
        """Parse a DID Document from JSON.

        Args:
            data: The raw JSON data.
            did: The expected DID.

        Returns:
            Parsed DIDDocument.

        Raises:
            DIDResolutionError: If the document is invalid.
        """
        # Validate ID matches
        doc_id = data.get("id", "")
        if doc_id != did:
            raise DIDResolutionError(
                f"DID Document id mismatch: expected {did}, got {doc_id}"
            )

        # Parse verification methods
        verification_methods: list[VerificationMethod] = []
        for vm_data in data.get("verificationMethod", []):
            public_key_jwk = None
            if "publicKeyJwk" in vm_data:
                public_key_jwk = PublicKeyJWK.from_dict(vm_data["publicKeyJwk"])

            vm = VerificationMethod(
                id=vm_data.get("id", ""),
                type=vm_data.get("type", ""),
                controller=vm_data.get("controller", ""),
                public_key_jwk=public_key_jwk,
            )
            verification_methods.append(vm)

        # Parse authentication and assertionMethod (can be strings or objects)
        authentication = self._parse_verification_relationship(
            data.get("authentication", [])
        )
        assertion_method = self._parse_verification_relationship(
            data.get("assertionMethod", [])
        )

        return DIDDocument(
            id=doc_id,
            verification_methods=verification_methods,
            authentication=authentication,
            assertion_method=assertion_method,
        )

    def _parse_verification_relationship(
        self, items: list[Any]
    ) -> list[str]:
        """Parse a verification relationship array.

        Items can be either strings (references) or objects (embedded methods).
        We only extract the ID references.

        Args:
            items: List of verification method references or objects.

        Returns:
            List of verification method IDs.
        """
        result: list[str] = []
        for item in items:
            if isinstance(item, str):
                result.append(item)
            elif isinstance(item, dict) and "id" in item:
                result.append(item["id"])
        return result

    def clear_cache(self) -> None:
        """Clear the resolution cache."""
        self._cache.clear()
