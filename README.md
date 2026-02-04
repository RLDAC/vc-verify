# VC Verify

Vérificateur de Verifiable Credentials (VCs) conforme aux standards W3C.

## Fonctionnalités

- **W3C Data Integrity Proofs** - Cryptosuite `ecdsa-jcs-2022`
- **ECDSA P-256** (secp256r1) - Vérification de signatures
- **did:web** - Résolution de DIDs
- **StatusList2021** - Vérification de révocation/suspension
- **JCS** (JSON Canonicalization Scheme, RFC 8785)

## Standards supportés

| Standard | Support |
|----------|---------|
| [W3C VC Data Model 2.0](https://www.w3.org/TR/vc-data-model-2.0/) | Complet |
| [W3C Data Integrity](https://www.w3.org/TR/vc-data-integrity/) | `ecdsa-jcs-2022` |
| [did:web](https://w3c-ccg.github.io/did-method-web/) | Complet |
| [StatusList2021](https://www.w3.org/TR/vc-status-list/) | Révocation, Suspension |

## Installation

```bash
# Cloner le repo
git clone https://github.com/RLDAC/vc-verify.git
cd vc-verify

# Installer le package Python
cd vc-verifier
pip install -e .
```

## Guide : Vérifier un credential

### Étape 1 : Préparer le credential

Votre credential doit être un fichier JSON avec cette structure :

```json
{
  "@context": ["https://www.w3.org/ns/credentials/v2"],
  "id": "urn:uuid:259f734d-4fb1-4ef0-b971-1c8f47c65ae8",
  "type": ["VerifiableCredential"],
  "issuer": "did:web:example.com",
  "validFrom": "2026-02-04T20:29:14.545651+00:00",
  "credentialSubject": {
    "id": "urn:uuid:d4658d2c-0b3d-49a9-a90b-350e4d9b4dc0",
    "nom": "Jean Dupont"
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

### Étape 2 : Lancer la vérification

```bash
vc-verify mon_credential.json
```

### Étape 3 : Interpréter le résultat

**Credential valide :**
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

**Credential invalide :**
```
╭──────────────────────────── Verification Result ─────────────────────────────╮
│   Status                 INVALID                                             │
│   Errors                 Signature verification failed                       │
╰──────────────────────────────────────────────────────────────────────────────╯
```

### Options disponibles

| Option | Description |
|--------|-------------|
| `--json-output` | Sortie au format JSON (pour intégration) |
| `--no-status` | Ignorer la vérification de révocation |
| `--no-ssl-verify` | Désactiver la vérification SSL |
| `--timeout N` | Timeout HTTP en secondes (défaut: 30) |

### Exemples

```bash
# Vérifier un fichier local
vc-verify credential.json

# Vérifier depuis une URL
vc-verify https://example.com/credentials/123

# Vérifier depuis stdin (pipe)
cat credential.json | vc-verify -

# Sortie JSON pour scripts
vc-verify credential.json --json-output

# Sans vérification de révocation
vc-verify credential.json --no-status
```

## Utilisation avancée

### API Python

```python
from vc_verifier import verify_credential, VCVerifier

# Vérification simple
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
print(f"Valide: {result.is_valid}")

# Avec plus de contrôle
verifier = VCVerifier(verify_status=True)
result = verifier.verify(credential)

if result.is_valid:
    print("Credential valide!")
else:
    print(f"Erreurs: {result.errors}")
```

## Architecture

```
vc-verify/
├── README.md                 # Ce fichier
├── verify.js                 # Prototype JS (expérimental)
├── package.json              # Config Node.js
└── vc-verifier/              # Package Python (implémentation principale)
    ├── pyproject.toml        # Config Python
    ├── README.md             # Documentation détaillée
    ├── LICENSE               # MIT
    ├── src/vc_verifier/
    │   ├── __init__.py       # Exports
    │   ├── cli.py            # Interface ligne de commande
    │   ├── verifier.py       # Logique de vérification
    │   ├── did_resolver.py   # Résolution DID
    │   └── statuslist.py     # Vérification StatusList2021
    └── tests/
        └── test_verifier.py  # Tests unitaires
```

## Flux de vérification

```
Credential (fichier/URL/stdin)
         │
         ▼
┌─────────────────────┐
│  Validation         │
│  structurelle       │
└─────────────────────┘
         │
         ▼
┌─────────────────────┐
│  Résolution DID     │──► did:web → HTTPS → DID Document
│  (did_resolver.py)  │
└─────────────────────┘
         │
         ▼
┌─────────────────────┐
│  Vérification       │
│  signature ECDSA    │──► JCS canonicalization + ECDSA P-256
└─────────────────────┘
         │
         ▼
┌─────────────────────┐
│  StatusList2021     │──► Vérification révocation/suspension
│  (optionnel)        │
└─────────────────────┘
         │
         ▼
    VerificationResult
```

## Développement

```bash
cd vc-verifier

# Installer les dépendances dev
pip install -e ".[dev]"

# Lancer les tests
pytest

# Linting
ruff check src tests
```

## Codes de sortie CLI

| Code | Signification |
|------|---------------|
| 0 | Credential valide |
| 1 | Credential invalide |
| 2 | Erreur |

## License

MIT License - voir [vc-verifier/LICENSE](vc-verifier/LICENSE)

## Auteur

RLDAC - contact@rldac.com

## Liens

- [W3C Verifiable Credentials](https://www.w3.org/TR/vc-data-model-2.0/)
- [W3C Data Integrity](https://www.w3.org/TR/vc-data-integrity/)
- [DID Core](https://www.w3.org/TR/did-core/)
- [StatusList2021](https://www.w3.org/TR/vc-status-list/)
