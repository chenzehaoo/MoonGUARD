# MoonGuard Project Guide

## Project Structure

```
moon_guard/
├── lib/
│   ├── manifest/     # Package manifest + hash calculation
│   ├── crypto/       # Ed25519 sign/verify
│   ├── trust/        # Trusted key store (SQLite/TOML)
│   ├── verify/       # Dependency verify + typosquat detection
│   └── report/       # JSON/HTML security reports
└── cmd/main/         # CLI entry point
```

## Key Decisions

1. **Lightweight over feature-rich** - Focus on core, demonstrable features
2. **Ed25519 signatures** - Fast, modern signature algorithm
3. **Local trust store** - No server dependency, works offline
4. **5 core modules** - manifest, crypto, trust, verify, report

## Design Principles

- High completion rate over complex features
- Clear demo scenarios for competitions
- Real use cases with supply chain security focus

## TODO

- [ ] Implement manifest module (file traversal + SHA-256)
- [ ] Implement crypto module (Ed25519 sign/verify)
- [ ] Implement trust store
- [ ] Implement dependency verification
- [ ] Implement typosquat detection
- [ ] Build CLI tool
- [ ] Generate security reports