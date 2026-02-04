# VC Verifier

Open-source Verifiable Credentials verifier supporting W3C standards.

## Features

- **W3C Data Integrity Proofs** - `ecdsa-jcs-2022` cryptosuite
- **ECDSA P-256** (secp256r1) signature verification
- **did:web** DID method resolution
- **StatusList2021** revocation/suspension checking
- **JCS** (JSON Canonicalization Scheme, RFC 8785) support

## Installation

```bash
pip install vc-verifier
```

Or from source:

```bash
git clone https://github.com/RLDAC/vc-verify.git
cd vc-verifier
pip install -e .
```

## Quick Start

### Python API

```python
from vc_verifier import verify_credential, VCVerifier

# Verify a credential
credential = {
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    "type": ["VerifiableCredential"],
    "issuer": "did:web:example.com",
    "credentialSubject": {
        "id": "did:example:holder",
        "name": "Alice"
    },
    "proof": {
        "type": "DataIntegrityProof",
        "cryptosuite": "ecdsa-jcs-2022",
        "verificationMethod": "did:web:example.com#key-1",
        "proofValue": "..."
    }
}

# Simple verification
result = verify_credential(credential)
print(f"Valid: {result.is_valid}")

# With more control
verifier = VCVerifier(verify_status=True)
result = verifier.verify(credential)

if result.is_valid:
    print("Credential is valid!")
else:
    print(f"Errors: {result.errors}")
```

### Command Line

```bash
# Verify a local file
vc-verify credential.json

# Verify from URL
vc-verify https://example.com/credentials/123

# Verify from stdin
cat credential.json | vc-verify -

# Output as JSON
vc-verify credential.json --json-output

# Skip revocation check
vc-verify credential.json --no-status
```

## Supported Standards

| Standard | Support |
|----------|---------|
| [W3C VC Data Model 2.0](https://www.w3.org/TR/vc-data-model-2.0/) | Full |
| [W3C Data Integrity](https://www.w3.org/TR/vc-data-integrity/) | `ecdsa-jcs-2022` |
| [did:web](https://w3c-ccg.github.io/did-method-web/) | Full |
| [StatusList2021](https://www.w3.org/TR/vc-status-list/) | Revocation, Suspension |

## Cryptographic Details

### Signature Verification

1. Extract `proof` from credential
2. Canonicalize the unsigned credential using JCS (RFC 8785)
3. Encode as UTF-8 bytes
4. Verify ECDSA P-256 signature against the public key

### JCS Canonicalization (RFC 8785)

```python
json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
```

### DID Resolution

```
did:web:example.com          -> https://example.com/.well-known/did.json
did:web:example.com:path:doc -> https://example.com/path/doc/did.json
did:web:example.com%3A8080   -> https://example.com:8080/.well-known/did.json
```

### StatusList2021

Bitstring encoding: `base64(gzip(bitstring))`

- Bit 0 = MSB of byte 0
- `0` = valid, `1` = revoked/suspended

## API Reference

### `VCVerifier`

```python
class VCVerifier:
    def __init__(
        self,
        did_resolver: DIDResolver | None = None,
        statuslist_checker: StatusListChecker | None = None,
        verify_status: bool = True,
    ) -> None: ...

    def verify(self, credential: dict) -> VerificationResult: ...
```

### `VerificationResult`

```python
@dataclass
class VerificationResult:
    status: VerificationStatus  # VALID, INVALID, or ERROR
    credential_id: str | None
    issuer: str | None
    proof: ProofVerificationResult | None
    credential_status: StatusCheckResult | None
    errors: list[str]
    warnings: list[str]

    @property
    def is_valid(self) -> bool: ...
```

### `DIDResolver`

```python
class DIDResolver:
    def __init__(
        self,
        timeout: float = 30.0,
        verify_ssl: bool = True,
    ) -> None: ...

    def resolve(self, did: str, use_cache: bool = True) -> DIDDocument: ...
```

### `StatusListChecker`

```python
class StatusListChecker:
    def __init__(
        self,
        timeout: float = 30.0,
        verify_ssl: bool = True,
    ) -> None: ...

    def check_status(
        self,
        credential: dict,
        use_cache: bool = True,
    ) -> StatusCheckResult | None: ...
```

## Development

```bash
# Clone
git clone https://github.com/RLDAC/vc-verify.git
cd vc-verifier

# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Lint
ruff check src tests
```

## License

MIT License - see [LICENSE](LICENSE) for details.

## Related

- [W3C Verifiable Credentials](https://www.w3.org/TR/vc-data-model-2.0/)
- [W3C Data Integrity](https://www.w3.org/TR/vc-data-integrity/)
- [DID Core](https://www.w3.org/TR/did-core/)
