# VC Verify

W3C-compliant Verifiable Credentials (VCs) verifier.

## Features

- **W3C Data Integrity Proofs** - `ecdsa-jcs-2022` cryptosuite
- **ECDSA P-256** (secp256r1) - Signature verification
- **did:web** - DID resolution
- **StatusList2021** - Revocation/suspension checking
- **JCS** (JSON Canonicalization Scheme, RFC 8785)

## Supported Standards

| Standard | Support |
|----------|---------|
| [W3C VC Data Model 2.0](https://www.w3.org/TR/vc-data-model-2.0/) | Full |
| [W3C Data Integrity](https://www.w3.org/TR/vc-data-integrity/) | `ecdsa-jcs-2022` |
| [did:web](https://w3c-ccg.github.io/did-method-web/) | Full |
| [StatusList2021](https://www.w3.org/TR/vc-status-list/) | Revocation, Suspension |

## Installation

```bash
# Clone the repo
git clone https://github.com/RLDAC/vc-verify.git
cd vc-verify

# Install the Python package
cd vc-verifier
pip install -e .
```

## Guide: Verify a Credential

### Step 1: Prepare the credential

Your credential must be a JSON file with this structure:

```json
{
  "@context": ["https://www.w3.org/ns/credentials/v2"],
  "id": "urn:uuid:259f734d-4fb1-4ef0-b971-1c8f47c65ae8",
  "type": ["VerifiableCredential"],
  "issuer": "did:web:example.com",
  "validFrom": "2026-02-04T20:29:14.545651+00:00",
  "credentialSubject": {
    "id": "urn:uuid:d4658d2c-0b3d-49a9-a90b-350e4d9b4dc0",
    "name": "John Doe"
  },
  "credentialStatus": {
    "id": "https://example.com/.well-known/vc/status/revocation#2",
    "type": "StatusList2021Entry",
    "statusPurpose": "revocation",
    "statusListIndex": "2",
    "statusListCredential": "https://example.com/.well-known/vc/status/revocation"
  },
  "proof": {
    "type": "DataIntegrityProof",
    "cryptosuite": "ecdsa-jcs-2022",
    "created": "2026-02-04T20:29:15.329402+00:00",
    "verificationMethod": "did:web:example.com#key-1",
    "proofPurpose": "assertionMethod",
    "proofValue": "MEQCIBCxH3Fz8ieQtfccuBtA..."
  }
}
```

### Step 2: Run verification

```bash
vc-verify my_credential.json
```

### Step 3: Interpret the result

**Valid credential:**
```
╭──────────────────────────── Verification Result ─────────────────────────────╮
│   Status                 VALID                                               │
│   Credential ID          urn:uuid:259f734d-4fb1-4ef0-b971-1c8f47c65ae8       │
│   Issuer                 did:web:example.com                                 │
│   Proof                  Valid                                               │
│   Cryptosuite            ecdsa-jcs-2022                                      │
│   Verification Method    did:web:example.com#key-1                           │
│   Credential Status      Valid                                               │
│   Status Purpose         revocation                                          │
│   Status Index           2                                                   │
╰──────────────────────────────────────────────────────────────────────────────╯
```

**Invalid credential:**
```
╭──────────────────────────── Verification Result ─────────────────────────────╮
│   Status                 INVALID                                             │
│   Errors                 Signature verification failed                       │
╰──────────────────────────────────────────────────────────────────────────────╯
```

### Available Options

| Option | Description |
|--------|-------------|
| `--json-output` | Output in JSON format (for integration) |
| `--no-status` | Skip revocation check |
| `--no-ssl-verify` | Disable SSL verification |
| `--timeout N` | HTTP timeout in seconds (default: 30) |

### Examples

```bash
# Verify a local file
vc-verify credential.json

# Verify from URL
vc-verify https://example.com/credentials/123

# Verify from stdin (pipe)
cat credential.json | vc-verify -

# JSON output for scripts
vc-verify credential.json --json-output

# Skip revocation check
vc-verify credential.json --no-status
```

## Advanced Usage

### Python API

```python
from vc_verifier import verify_credential, VCVerifier

# Simple verification
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

## Architecture

```
vc-verify/
├── README.md                 # This file
├── verify.js                 # JS prototype (experimental)
├── package.json              # Node.js config
└── vc-verifier/              # Python package (main implementation)
    ├── pyproject.toml        # Python config
    ├── README.md             # Detailed documentation
    ├── LICENSE               # MIT
    ├── src/vc_verifier/
    │   ├── __init__.py       # Exports
    │   ├── cli.py            # Command-line interface
    │   ├── verifier.py       # Verification logic
    │   ├── did_resolver.py   # DID resolution
    │   └── statuslist.py     # StatusList2021 verification
    └── tests/
        └── test_verifier.py  # Unit tests
```

## Verification Flow

```
Credential (file/URL/stdin)
         │
         ▼
┌─────────────────────┐
│  Structure          │
│  validation         │
└─────────────────────┘
         │
         ▼
┌─────────────────────┐
│  DID resolution     │──► did:web → HTTPS → DID Document
│  (did_resolver.py)  │
└─────────────────────┘
         │
         ▼
┌─────────────────────┐
│  ECDSA signature    │
│  verification       │──► JCS canonicalization + ECDSA P-256
└─────────────────────┘
         │
         ▼
┌─────────────────────┐
│  StatusList2021     │──► Revocation/suspension check
│  (optional)         │
└─────────────────────┘
         │
         ▼
    VerificationResult
```

## Development

```bash
cd vc-verifier

# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Linting
ruff check src tests
```

## CLI Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Valid credential |
| 1 | Invalid credential |
| 2 | Error |

## License

MIT License - see [vc-verifier/LICENSE](vc-verifier/LICENSE)

## Author

RLDAC - contact@rldac.com

## Links

- [W3C Verifiable Credentials](https://www.w3.org/TR/vc-data-model-2.0/)
- [W3C Data Integrity](https://www.w3.org/TR/vc-data-integrity/)
- [DID Core](https://www.w3.org/TR/did-core/)
- [StatusList2021](https://www.w3.org/TR/vc-status-list/)
