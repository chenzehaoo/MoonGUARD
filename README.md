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

## Modules

- `lib/manifest` - Package manifest and file hashing
- `lib/crypto` - Ed25519 cryptographic operations
- `lib/trust` - Trusted key store management
- `lib/verify` - Package and dependency verification
- `lib/report` - Security report generation
- `cmd/main` - CLI tool

## Quick Start

```bash
# Build
moon build

# Run CLI
moon run
```

## License

Apache-2.0