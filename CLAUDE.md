# MoonGuard - AI Agent Guide

This document provides guidance for AI agents working on MoonGuard.

## Project Overview

MoonGuard is a MoonBit supply chain security toolchain written in pure MoonBit. It provides cryptographic signing, manifest generation, trust management, and security reporting.

## Language & Conventions

MoonBit is organized in **blocks** separated by `///|`. The order of blocks is irrelevant - they can be processed independently.

### Code Organization
- MoonBit packages are organized per directory
- Each directory has a `moon.pkg.json` file listing dependencies
- Test files: `*_test.mbt` (blackbox), `*_wbtest.mbt` (whitebox)
- Deprecations go in `deprecated.mbt` in each directory

### Code Style
- Use `moon fmt` to format code
- Run `moon info` to update generated `.mbti` interface files
- Always finish with `moon info && moon fmt`
- Check `.mbti` diffs to verify changes are expected

### Testing
- Run `moon test` to execute tests
- MoonBit supports snapshot testing via `inspect`
- Use `moon test --update` to update snapshots when behavior changes
- Use `assert_eq` in loops where snapshots may vary
- Run `moon coverage analyze > uncovered.log` to check coverage

### Linting
- Run `moon check` for linting

## Module Architecture

```
moon_guard (root - moon.mod.json)
├── lib/ (moon.pkg.json)
│   ├── manifest/  - SHA-256 + manifest generation
│   ├── crypto/    - Ed25519 sign/verify
│   ├── trust/     - In-memory trust store
│   ├── verify/    - Package verification + typosquat
│   └── report/   - Security report generation
└── cmd/main/      - CLI entry point
```

### Dependencies Between Modules
- `manifest` - Self-contained, no dependencies
- `crypto` - Uses `sha512` from field.mbt
- `trust` - Self-contained
- `verify` - Uses `@crypto` for signature verification
- `report` - Self-contained
- `cmd/main` - Uses all modules via `@module` syntax

## Critical Implementation Notes

### SHA-256 (lib/manifest/manifest.mbt)
- Pure MoonBit implementation
- Uses UTF-8 string encoding
- 64 rounds per block
- Big-endian byte order for length encoding

### Ed25519 (lib/crypto/ed25519.mbt)
- Curve25519 point operations
- SHA-512 for hashing
- Scalar clamping for key derivation
- Ed25519 signing: `S = (r + k*a) mod L`

### Trust Store (lib/trust/trust.mbt)
- In-memory only (no persistence in demo)
- Public key format validation: 64 hex chars
- Trust levels: Full, Partial, Untrusted

### Typosquat Detection (lib/verify/typosquat.mbt)
- Levenshtein distance algorithm
- Distance threshold: 0-2 characters
- Separator normalization: `-`, `_`, `.` all map to `-`
- Attack types: separator-swap, character-swap, extra-character, missing-character

## File Naming
- Implementation: `*.mbt`
- Test: `*_test.mbt`
- Generated interface: `*.mbti`
- Documentation: `README.mbt.md` (template for README generation)

## Development Workflow

1. Read `AGENTS.md` for general MoonBit project guidance
2. Check module structure in `moon.pkg.json` files
3. Run `moon test` to verify changes
4. Run `moon info && moon fmt` before committing
5. Check test coverage with `moon coverage analyze`

## Demo/Attack Simulation

The root level `moon_guard_test.mbt` contains an attack simulation demonstrating:
1. Developer creates package with manifest
2. Developer signs manifest
3. Attacker tampers with package
4. MoonGuard detects tampering via hash mismatch
5. Security report generated

Run with: `moon test moon_guard_test.mbt`