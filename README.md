# MoonGuard

MoonBit supply chain security toolchain.

## Overview

MoonGuard is a lightweight security toolchain for MoonBit packages, focusing on:
- Package manifest generation and hash verification
- Ed25519 signature and verification
- Local trusted key store management
- Dependency verification
- Typosquat attack detection
- Security report generation

## Project Structure

```
moon_guard/
├── lib/
│   ├── manifest/     # Package manifest + SHA-256 hash calculation
│   ├── crypto/       # Ed25519 sign/verify (field arithmetic, SHA-512)
│   ├── trust/        # Trusted key store (in-memory, JSON serialization)
│   ├── verify/       # Package verification + typosquat detection
│   └── report/       # JSON security report generation
├── cmd/main/         # CLI entry point
├── moon.mod.json    # Module manifest
├── README.md        # This file
├── CLAUDE.md        # AI agent guidance
└── AGENTS.md        # Project agent instructions
```

## Modules

### lib/manifest
Package manifest and file hashing with full SHA-256 implementation.
- `FileHash` - File path, hash, size tuple
- `Manifest` - Package manifest with metadata and file list
- `sha256()` - Pure MoonBit SHA-256 implementation
- `generate_manifest()` - Create manifest from file entries
- `verify_manifest()` - Verify files against manifest
- `manifest_to_json()` - Serialize manifest to JSON

### lib/crypto
Ed25519 cryptographic operations.
- `KeyPair` - Public/secret key pair
- `Signature` - Ed25519 signature (r, s components)
- `generate_keypair(seed)` - Generate keypair from seed
- `sign(message, keypair)` - Sign a message
- `verify(message, signature, public_key)` - Verify signature
- Uses SHA-512 and field arithmetic over Ed25519 curve

### lib/trust
Trusted key store management.
- `TrustLevel` - Full, Partial, Untrusted
- `TrustedKey` - Key entry with metadata
- `TrustStore` - In-memory key store
- `add_key()`, `remove_key()`, `get_key()`, `is_trusted()`
- `trust_store_to_json()` - Export to JSON

### lib/verify
Package verification and typosquat detection.
- `VerifyResult` - Verification result with errors/warnings
- `verify_package()` - Verify package signature
- `detect_typosquat()` - Levenshtein-based typosquat detection
- `batch_typosquat_check()` - Batch typosquat checking

### lib/report
Security report generation.
- `RiskLevel` - Critical, High, Medium, Low, Info
- `Finding` - Individual security finding
- `SecurityReport` - Full security report
- `summary()` - Human-readable report
- `report_to_json()` - JSON export

### cmd/main
CLI tool with commands:
```
moon_guard keygen              Generate Ed25519 keypair
moon_guard sign <msg> <seed>  Sign a message
moon_guard verify <msg> <sig> <pubkey>  Verify signature
moon_guard trust <add|list|remove> ...  Manage trust store
moon_guard typosquat <name> <known...>  Check typosquatting
moon_guard manifest <gen|verify|hash> ...  Package manifest ops
moon_guard hash <content>     Compute SHA-256 hash
moon_guard audit <pkg> <ver>  Full security audit with report
```

## Key Design Decisions

1. **Lightweight over feature-rich** - Focus on core, demonstrable features
2. **Ed25519 signatures** - Fast, modern signature algorithm
3. **Local trust store** - No server dependency, works offline
4. **Pure MoonBit implementation** - No external crypto libraries

## Quick Start

```bash
# Build
moon build

# Run CLI
moon run -- keygen
moon run -- sign "Hello" <seed>
moon run -- verify "Hello" <signature> <pubkey>
moon run -- audit my_package 1.0.0
```

## Dependencies

- `moonbitlang/async` v0.10.0 (for async runtime support)

## License

Apache-2.0