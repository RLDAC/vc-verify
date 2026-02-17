"""
StatusList2021 verification module.

Implements W3C StatusList2021 bitstring decoding and status checking.
https://www.w3.org/TR/vc-status-list/
"""

from __future__ import annotations

import base64
import gzip
from dataclasses import dataclass
from enum import Enum
from typing import Any

import httpx


class CredentialStatus(Enum):
    """Credential status values."""

    VALID = "valid"
    REVOKED = "revoked"
    SUSPENDED = "suspended"
    UNKNOWN = "unknown"


class StatusListError(Exception):
    """Raised when StatusList operations fail."""


@dataclass
class StatusListEntry:
    """Parsed credentialStatus from a VC."""

    status_list_credential: str
    status_list_index: int
    status_purpose: str
    id: str | None = None
    type: str = "StatusList2021Entry"


@dataclass
class StatusCheckResult:
    """Result of a status check."""

    status: CredentialStatus
    purpose: str
    index: int
    message: str


class StatusListChecker:
    """Verifies credential status using W3C StatusList2021."""

    def __init__(
        self,
        timeout: float = 30.0,
        verify_ssl: bool = True,
    ) -> None:
        """Initialize the StatusList checker.

        Args:
            timeout: HTTP request timeout in seconds.
            verify_ssl: Whether to verify SSL certificates.
        """
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self._cache: dict[str, bytes] = {}  # Cache decoded bitstrings by URL

    def parse_credential_status(
        self, credential: dict[str, Any]
    ) -> list[StatusListEntry]:
        """Parse credentialStatus from a VC.

        Handles both a single credentialStatus object and an array
        of statuses (e.g. one for revocation, one for suspension).

        Args:
            credential: The Verifiable Credential.

        Returns:
            List of parsed StatusListEntry (empty if no status).

        Raises:
            StatusListError: If a StatusList2021Entry is malformed.
        """
        status_data = credential.get("credentialStatus")
        if not status_data:
            return []

        # Normalize to list
        if not isinstance(status_data, list):
            status_data = [status_data]

        entries: list[StatusListEntry] = []
        for item in status_data:
            if item.get("type") != "StatusList2021Entry":
                continue
            try:
                entries.append(StatusListEntry(
                    id=item.get("id"),
                    type=item.get("type", "StatusList2021Entry"),
                    status_list_credential=item["statusListCredential"],
                    status_list_index=int(item["statusListIndex"]),
                    status_purpose=item["statusPurpose"],
                ))
            except (KeyError, ValueError, TypeError) as e:
                raise StatusListError(f"Invalid credentialStatus: {e}") from e

        return entries

    def check_status(
        self,
        credential: dict[str, Any],
        use_cache: bool = True,
    ) -> list[StatusCheckResult]:
        """Check the revocation/suspension status of a credential.

        Checks every StatusList2021Entry present in credentialStatus
        (supports both single object and array).

        Args:
            credential: The Verifiable Credential to check.
            use_cache: Whether to cache fetched StatusLists.

        Returns:
            List of StatusCheckResult (empty if no credentialStatus).

        Raises:
            StatusListError: If status check fails.
        """
        entries = self.parse_credential_status(credential)
        if not entries:
            return []

        results: list[StatusCheckResult] = []
        for entry in entries:
            # Fetch and decode the StatusList
            bitstring = self._fetch_statuslist(
                entry.status_list_credential,
                use_cache=use_cache,
            )

            # Check the bit at the specified index
            is_set = self._get_bit(bitstring, entry.status_list_index)

            if is_set:
                if entry.status_purpose == "revocation":
                    status = CredentialStatus.REVOKED
                    message = f"Credential is revoked (index {entry.status_list_index})"
                elif entry.status_purpose == "suspension":
                    status = CredentialStatus.SUSPENDED
                    message = f"Credential is suspended (index {entry.status_list_index})"
                else:
                    status = CredentialStatus.UNKNOWN
                    message = f"Unknown status purpose: {entry.status_purpose}"
            else:
                status = CredentialStatus.VALID
                message = f"Credential status is valid ({entry.status_purpose}, index {entry.status_list_index})"

            results.append(StatusCheckResult(
                status=status,
                purpose=entry.status_purpose,
                index=entry.status_list_index,
                message=message,
            ))

        return results

    def _fetch_statuslist(self, url: str, use_cache: bool = True) -> bytes:
        """Fetch and decode a StatusList credential.

        Args:
            url: URL of the StatusList2021Credential.
            use_cache: Whether to use cached results.

        Returns:
            Decoded bitstring as bytes.

        Raises:
            StatusListError: If fetching or decoding fails.
        """
        if use_cache and url in self._cache:
            return self._cache[url]

        try:
            with httpx.Client(timeout=self.timeout, verify=self.verify_ssl) as client:
                response = client.get(
                    url,
                    headers={"Accept": "application/vc+ld+json, application/json"},
                )
                response.raise_for_status()
                sl_credential = response.json()

        except httpx.HTTPStatusError as e:
            raise StatusListError(
                f"HTTP error fetching StatusList from {url}: {e.response.status_code}"
            ) from e
        except httpx.RequestError as e:
            raise StatusListError(f"Network error fetching StatusList: {e}") from e
        except ValueError as e:
            raise StatusListError(f"Invalid JSON in StatusList from {url}") from e

        # Extract encodedList from credentialSubject
        subject = sl_credential.get("credentialSubject", {})
        encoded_list = subject.get("encodedList")

        if not encoded_list:
            raise StatusListError("Missing encodedList in StatusList credential")

        # Decode the bitstring: base64(gzip(bitstring))
        bitstring = self._decode_bitstring(encoded_list)

        if use_cache:
            self._cache[url] = bitstring

        return bitstring

    def _decode_bitstring(self, encoded_list: str) -> bytes:
        """Decode a W3C StatusList2021 encoded bitstring.

        Decoding: gunzip(base64decode(encoded_list))

        Args:
            encoded_list: Base64-encoded gzipped bitstring.

        Returns:
            Raw bytes representing the bitstring.

        Raises:
            StatusListError: If decoding fails.
        """
        try:
            compressed = base64.b64decode(encoded_list)
            return gzip.decompress(compressed)
        except Exception as e:
            raise StatusListError(f"Failed to decode bitstring: {e}") from e

    def _get_bit(self, bitstring: bytes, index: int) -> bool:
        """Get the value of a bit at the given index.

        Per W3C spec, bit 0 is the leftmost (most significant) bit of byte 0.

        Args:
            bitstring: Raw bytes representing the bitstring.
            index: Zero-based index of the bit to read.

        Returns:
            True if the bit is set (1), False if unset (0).

        Raises:
            StatusListError: If index is out of range.
        """
        total_bits = len(bitstring) * 8
        if index < 0 or index >= total_bits:
            raise StatusListError(
                f"StatusList index {index} out of range [0, {total_bits})"
            )

        byte_index = index // 8
        bit_position = 7 - (index % 8)  # MSB first per W3C spec

        return bool((bitstring[byte_index] >> bit_position) & 1)

    def clear_cache(self) -> None:
        """Clear the StatusList cache."""
        self._cache.clear()
