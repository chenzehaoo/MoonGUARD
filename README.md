# MoonGuard

MoonBit supply chain security toolchain.

## Overview

MoonGuard is a pure-MoonBit supply chain security toolchain providing:

- **Manifest integrity** — SHA-256 hashes over file contents (pure MoonBit implementation, no external crypto library).
- **Ed25519 signatures** — RFC 8032 sign/verify with field arithmetic and SHA-512, also pure MoonBit.
- **Trusted key store** — in-memory store with `Full` / `Partial` / `Untrusted` levels, JSON and PEM (RFC 7468) persistence.
- **Audit pipeline** — `verify_package` ties manifest integrity, signature verification and trust lookup into one call.
- **Typosquat detection** — Levenshtein distance plus strict mode that also catches look-alike substitutions (`1odash` for `lodash`, `Iodash` etc.) and the `summary` aggregator for batch reports.
- **Security reports** — `SecurityReport` with `Critical` / `High` / `Medium` / `Low` / `Info` findings, cumulative 0–10 risk score, JSON export.
- **CLI** — `moon_guard` executable with subcommands for `keygen` / `sign` / `verify` / `trust` / `typosquat` / `manifest` / `hash` / `audit` / `version`.

## Project Structure

```
moon_guard/
├── lib/
│   ├── manifest/     # Package manifest + SHA-256 hash calculation
│   ├── crypto/       # Ed25519 sign/verify (field arithmetic, SHA-512)
│   ├── trust/        # Trusted key store (in-memory, JSON and PEM persistence)
│   ├── verify/       # Audit pipeline, typosquat detection (Levenshtein + strict)
│   └── report/       # JSON security report with risk score
├── cmd/main/         # CLI entry point (moon_guard)
├── examples/         # Runnable usage examples (see examples/basic_audit)
├── moon.mod.json     # Module manifest
├── README.md         # This file
└── LICENSE           # Apache-2.0
```

## Library API

### lib/manifest
Package manifest and file hashing with full SHA-256 implementation.
- `FileEntry` — `{ path, content }` input shape
- `FileHash` — `{ path, hash, size }` recorded per file
- `Manifest` — full package manifest
- `sha256()` — pure-MoonBit SHA-256
- `generate_manifest()` — produce manifest from entries
- `verify_manifest()` — return mismatched paths for downstream audit
- `manifest_to_json()` / `manifest_summary()` — wire format
- `take_chars_()` / `slice_chars_()` — non-Result string slicing helpers (used internally to dodge deprecated `String::substring`)

### lib/crypto
Ed25519 cryptographic operations.
- `KeyPair` — `{ public_key, secret_key }`
- `Signature` — `{ r, s }` 32-byte halves
- `generate_keypair(seed)` — deterministic Ed25519 keypair from a 32-byte hex seed
- `sign(message, keypair)` — sign a UTF-8 message
- `verify(message, signature, public_key)` — verify a signature
- `signature_to_hex()` — pack `r||s` into 128-char hex

### lib/trust
Trusted key store with persistence.
- `TrustLevel` — `Full` / `Partial` / `Untrusted`
- `TrustedKey` — single key entry with metadata
- `TrustStore` — in-memory store
  - `add_key()` / `remove_key()` / `get_key()` / `is_trusted()` / `find_by_owner()` / `key_count()`
  - `list_all()` — defensive snapshot
  - `replace_all()` — bulk replace (for restore)
- `validate_public_key_format()` — 64-char hex check
- `normalize_public_key()` — fold mixed-case hex into canonical lowercase
- `public_key_to_pem()` / `public_key_from_pem()` — RFC 7468 style `MOONGUARD PUBLIC KEY` envelopes
- `trust_store_to_json()` / `trust_store_from_json()` — versioned JSON with strict validation

### lib/verify
Package verification, full audit pipeline, and typosquat detection.
- `VerifyResult` — `{ package_name, is_valid, signature_ok, trust_status, errors, warnings }`
- `verify_package()` — verify signature against content
- `audit_package()` — full audit: file integrity + signature + trust
- `detect_typosquat()` — Levenshtein ≤ 2 plus separator-swap
- `detect_typosquat_strict()` — adds homoglyph detection (`1` vs `l`, `0` vs `O`, `rn` vs `m` …)
- `batch_typosquat_check()` — run over many suspects
- `typosquat_summary()` — aggregate hits per suspect
- `signature_to_hex()` — re-export so callers don't need `@crypto`
- `generate_demo_keypair()` — demo helper

### lib/report
Security report generation.
- `RiskLevel` — `Critical` / `High` / `Medium` / `Low` / `Info`
- `ReportStatus` — `Pass` / `Warning` / `Fail`
- `Finding` — single security finding
- `TyposquatSummaryEntry` — per-suspect hit summary
- `SecurityReport`
  - `add_finding()` — auto-derives status from severity
  - `recompute_score()` — clamp cumulative risk at 10
  - `summary()` — human-readable text
  - `report_to_json()` — JSON wire format
- `make_finding()` — Finding struct constructor

## CLI

`cmd/main` builds to a `moon_guard` binary. Run via:

```bash
moon run cmd/main -- <command> [args]
```

Subcommands:

```
moon_guard keygen [seed]                       Generate Ed25519 keypair; emit PEM envelope.
moon_guard sign <msg> <seed>                   Sign a UTF-8 message with a hex seed.
moon_guard verify <msg> <sig_hex> <pubkey>     Verify an Ed25519 signature.
moon_guard trust add <key_id> <pubkey> <owner> [level]
                                               Add a trusted key (level = full|partial|untrusted).
moon_guard trust list                          List all keys in the store.
moon_guard trust remove <key_id>               Remove a trusted key.
moon_guard typosquat <name> <known...>         Strict typosquat check (homoglyph aware).
moon_guard manifest gen <pkg> <ver> [f:c...]   Generate manifest from path:content pairs.
moon_guard manifest verify <pkg> <ver> [f:c]   Verify a manifest against inputs.
moon_guard hash <content>                      Compute SHA-256 hash.
moon_guard audit <pkg> <ver> [f:c...]          Run full audit + emit JSON report.
moon_guard version                             Print version and exit.
moon_guard help                                Print usage.
```

### Quick Start

```bash
# 1. Generate a deterministic Ed25519 keypair.
moon run cmd/main -- keygen

# 2. Compute a SHA-256 hash over arbitrary content.
moon run cmd/main -- hash "Hello, MoonBit"

# 3. Sign a UTF-8 message.
moon run cmd/main -- sign "Hello, MoonBit" 9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60

# 4. Run a full audit on a synthetic package (with two files).
moon run cmd/main -- audit demo-pkg 1.0.0 \
  "src/main.mbt:fn main { println(\"hello\") }" \
  "src/lib.mbt:pub fn add(a: Int, b: Int) -> Int { a + b }"

# 5. Detect typosquats.
moon run cmd/main -- typosquat 1odash lodash react express
```

### Library usage (after `moon add chenzehaoo/moon_guard`)

The `examples/basic_audit` directory is the canonical end-to-end usage:

```bash
moon run examples/basic_audit
```

It calls the public API of every `lib/` module — useful as both a
reproducible smoke test and as a copy-paste starting point for downstream
packages.

## Development

| Command | Purpose |
|---------|---------|
| `moon test` | Run the full test suite (81+ tests across 5 modules + CLI). |
| `moon test --target wasm` | Force the wasm backend (matches the CI matrix). |
| `moon check` | Lint and type-check. |
| `moon check --deny-warn` | Fail the build on any warning. |
| `moon fmt --check` | Verify formatting (CI fails on diff). |
| `moon fmt` | Auto-format the code. |
| `moon info` | Regenerate the `.mbti` interface files. |
| `moon coverage analyze` | Print uncovered code paths. |

CI runs `moon fmt --check`, `moon info`, `moon check --deny-warn`, and
`moon test` across `ubuntu-latest` / `macos-latest` / `windows-latest`
for both `wasm` and `native` backends.

## Publishing to mooncakes.io

```bash
moon login     # one-time: paste your mooncakes.io token
moon publish   # uploads the module as chenzehaoo/moon_guard
```

`moon.mod.json` carries the canonical module name, repository URL,
summary, description, keywords, and supported platforms (`native`,
`wasm`, `wasm-gc`) — these flow straight into the mooncakes.io package
page.

## CI

`.github/workflows/ci.yml` runs on every push and PR, executing on a 5-cell
matrix:

| OS | target |
|----|--------|
| ubuntu-latest | wasm |
| ubuntu-latest | native |
| macos-latest | wasm |
| macos-latest | native |
| windows-latest | wasm |

Each cell runs `moon fmt --check`, `moon info`, `moon check --deny-warn`,
and `moon test`.

## Dependencies

None at runtime. MoonGuard is implemented entirely in pure MoonBit using only
the standard `core` libraries (notably `@bigint` for the Ed25519 field).

## License

Apache-2.0