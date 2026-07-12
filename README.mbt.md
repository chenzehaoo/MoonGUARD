# chenzehaoo/moon_guard

Lightweight supply chain security toolchain for MoonBit packages /
轻量级 MoonBit 供应链安全工具链

MoonGuard provides Ed25519 package signing and verification, SHA-256
manifest integrity checks, JSON+PEM trusted key management, Levenshtein
and homoglyph typosquat detection, CVSS-style cumulative risk scores,
JSON security reports, and a 9-subcommand `moon_guard` CLI — all
implemented in pure MoonBit.

MoonGuard 提供 Ed25519 包签名与验签、SHA-256 清单完整性校验、JSON+PEM
可信公钥管理、Levenshtein 与同形（homoglyph）双模式 typosquat 检测、
CVSS 风格 0–10 风险评分的 JSON 安全审计报告，以及 9 个子命令的
`moon_guard` CLI —— 全部用纯 MoonBit 实现。

## Install / 安装

```bash
moon add chenzehaoo/moon_guard
```

## Quick start / 快速上手

```bash
# Generate an Ed25519 keypair (deterministic from the demo seed) / 生成密钥对
moon run cmd/main -- keygen

# Audit a synthetic 2-file package / 审计合成包
moon run cmd/main -- audit demo-pkg 1.0.0 \
  "src/main.mbt:fn main { println(\"hello\") }" \
  "src/lib.mbt:pub fn add(a: Int, b: Int) -> Int { a + b }"
```

## Library / 作为库使用

See `examples/basic_audit/main.mbt` for a runnable end-to-end
demonstration. / 完整端到端示例见 `examples/basic_audit/main.mbt`。

```mbt-no-doctest
// Pseudocode — see examples/basic_audit/main.mbt for the real file.
let keypair = @crypto.generate_keypair(seed)
let manifest = @manifest.generate_manifest("pkg", "1.0.0", entries)
let sig = @crypto.sign(@manifest.manifest_to_json(manifest), keypair)
let _ = @verify.audit_package(
  "pkg", "1.0.0", manifest, entries,
  @verify.signature_to_hex(sig), "alice", trust_store,
)
```