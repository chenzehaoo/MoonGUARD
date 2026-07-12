# MoonGuard 中文架构说明（API 设计文档）

本文档面向希望深入了解 MoonGuard 内部架构、模块划分、API 约定的开发者，是仓库根目录 `README.zh.md` 的技术深潜版。

## 设计原则

1. **纯 MoonBit**：所有算法（SHA-256、SHA-512、Ed25519、Levenshtein）独立实现，不依赖任何外部加密库。
2. **最小外部依赖**：仅使用 MoonBit 标准 `core` 库（最关键的是 `@bigint`，用于 Ed25519 域算术）。
3. **分层无环依赖**：`lib/manifest` / `lib/crypto` / `lib/trust` 是基础层；`lib/verify` 是组合层；`lib/report` 是表达层。组合层只对基础层有依赖，模块之间无循环引用。
4. **错误可见**：`trust_store_from_json` 等反序列化函数在格式错误时返回 `None`，不允许悄悄吞错。
5. **可观测**：每个 lib 模块的 API 都配套单元测试、E2E 测试，公共副作用（如 PEM 输出）有显式函数 + JSON 双输出。

## 模块依赖图

```
            ┌─────────────────────┐
            │   lib/manifest      │  SHA-256 + take/slice helpers
            │   (基础, 无 deps)    │
            └────────┬────────────┘
                     │ 提供 slice_chars_ / take_chars_
        ┌────────────┼────────────────┐
        │            │                │
┌──────────────┐ ┌──────────────┐ ┌────────────┐
│ lib/crypto   │ │ lib/trust    │ │ lib/verify │←───┐
│ (Ed25519+SHA512, │ (PEM/JSON    │ │ (audit +   │    │
│  仅 core bigint) │  持久化)      │ │  typosquat) │    │
└──────────────┘ └──────┬───────┘ └─────┬──────┘    │
                       │               │             │
                       └─────┐         │             │
                             │         │             │
                       ┌─────┴─────────┴─────────────┘
                       │  lib/report   (风险评分 + JSON)
                       └──────────────────────────────┘

                       ┌──────────────────────────────┐
                       │   cmd/main (CLI, is-main)     │
                       └──────────────────────────────┘

                       ┌──────────────────────────────┐
                       │   examples/basic_audit        │
                       │   (用户可见的复制模板)        │
                       └──────────────────────────────┘
```

## lib/manifest 详解

### 核心类型

```mbt
pub struct FileHash { path : String, hash : String, size : Int }
pub struct Manifest  { version, package_name, package_version, total_files, total_size, created_at, files : Array[FileHash] }
pub(all) struct FileEntry { path : String, content : String }
```

### 关键 API

| 函数 | 用途 |
|------|------|
| `sha256(data : String) -> String` | 纯 MoonBit SHA-256，输出 64 字符 hex |
| `generate_manifest(pkg, ver, entries) -> Manifest` | 对每个 `FileEntry` 计算 SHA-256 后汇总成清单 |
| `verify_manifest(manifest, entries) -> Array[String]` | 返回不匹配路径列表（双向比对：缺失 + 修改） |
| `manifest_to_json(manifest) -> String` | 稳定的 JSON 序列化，可作为签名输入 |
| `manifest_summary(manifest) -> String` | 一行人类可读摘要 |
| `take_chars_/slice_chars_` | 内部 helper，避免 deprecated `String::substring` 与 Result-typed 切片 |

### 数据流

```
FileEntry{path,content}
   │
   ▼
sha256(content) ─────────────┐
   │                          ▼
compute_file_hash ──► FileHash{path,hash,size}
   │                          │
   ▼                          ▼
generate_manifest ──► Manifest{files:[FileHash,...], ...}
   │
   ▼
manifest_to_json ──► string ──► @crypto.sign
                                          │
                                          ▼
                                  Signature{r,s}
```

## lib/crypto 详解

### Ed25519 实现细节

按照 RFC 8032 实现：

1. `clamp_scalar(h)`：从 SHA-512(种子) 取前 32 字节，置位 0、254、255
2. 标量乘法：扩展仿射点 + 字节序 LE，bit-by-bit 累加 + Double
3. `sign`：SHA-512(prefix||message) → r，k = SHA-512(R||A||message)，S = r + k·a (mod L)
4. `verify`：左乘 [S]B，右乘 R + [k]A，比较字节编码

### 关键 API

| 函数 | 用途 |
|------|------|
| `generate_keypair(seed : String) -> KeyPair` | seed 必须是 64 字符 hex；确定性输出密钥对 |
| `sign(message : String, keypair : KeyPair) -> Signature` | sign UTF-8 编码后的 message |
| `verify(message, signature, public_key) -> Bool` | 严格验证 |
| `signature_to_hex(sig) -> String` | 把 `r||s` 拼成 128 字符 hex，便于跨调用传递 |

## lib/trust 详解

### TrustLevel 语义

| 等级 | 含义 |
|------|------|
| `Full` | 完全信任，会签署的包默认视为可信 |
| `Partial` | 部分信任，会被审计但不强制 PASS |
| `Untrusted` | 不信任，违反审计时被显式报错 |

### JSON 持久化 schema

```json
{
  "version": "1",
  "keys": [
    {
      "key_id": "alice",
      "public_key": "<64-char hex>",
      "owner": "alice",
      "trust_level": "full | partial | untrusted",
      "added_at": "2026-01-01"
    }
  ]
}
```

### PEM 信封格式

```
-----BEGIN MOONGUARD PUBLIC KEY-----
<64-char hex, 64 chars per line>
-----END MOONGUARD PUBLIC KEY-----
```

按 RFC 7468 (Section 13, "PUBLIC KEY") 的同一信封风格。

### 关键 API

| 函数 | 用途 |
|------|------|
| `TrustStore::new()` | 空 store |
| `add_key(id, pubkey, owner, level)` | 校验 hex 格式与不重复后插入 |
| `remove_key(id) -> Bool` | 删除并返回是否成功 |
| `get_key(id) -> TrustedKey?` | 未命中返回 None |
| `is_trusted(id) -> Bool` | 在 store 且不是 `Untrusted` |
| `find_by_owner(name) -> Array[TrustedKey]` | 按 owner 聚合 |
| `list_all() -> Array[TrustedKey]` | 防御性快照（防止外部 mutation） |
| `validate_public_key_format(s) -> Bool` | 64 字符 hex 校验 |
| `normalize_public_key(s) -> String?` | 大写 → 小写 |
| `public_key_to_pem(s) -> String` | 64 字符一行 |
| `public_key_from_pem(pem) -> String?` | 兼容大小写 + 自动 normalize |
| `trust_store_to_json(store) -> String` | 带版本号 schema |
| `trust_store_from_json(s) -> TrustStore?` | 严格校验，失败返回 None |

## lib/verify 详解

### audit_package 全链路

`audit_package` 把三件事合并到一次调用，返回 `VerifyResult`：

1. **完整性**：`manifest.verify_manifest(manifest, entries)`，返回 mismatch 列表
2. **签名**：`verify_package(name, sig_hex, pubkey, manifest_to_json(manifest))`
3. **可信度**：根据 `trust_store.is_trusted(signer_key_id)` 决定 trust_status
4. **`is_valid` 决定式**：`signature_ok && mismatches.empty() && trust_status == "trusted"`

### Typosquat 检测策略

| 模式 | 检测原理 |
|------|----------|
| `detect_typosquat` | Levenshtein 距离 ≤ 2 + 分隔符归一化（`-`/`_`/`.` → `-`） |
| `detect_typosquat_strict` | 在上者基础上加同形检测：18 对常见替换（`1`↔`l`、`0`↔`O`、`rn`↔`m`、`s`↔`5` 等） |
| `batch_typosquat_check` | 多 suspect ↔ 多 known |
| `typosquat_summary` | 按 suspect 聚合，给出 `hit_count` 与首个命中 |

## lib/report 详解

### 风险评分算法

```mbt
let weights = {
  Critical => 10.0,
  High     =>  7.0,
  Medium   =>  4.0,
  Low      =>  1.0,
  Info     =>  0.0,
}
score = sum(weights)。clamp(0, 10)
```

### JSON schema（导出格式）

```json
{
  "package": "demo-pkg",
  "version": "1.0.0",
  "status": "pass | warning | fail",
  "risk_score": 0.00,
  "audit_timestamp": "2026-01-01T00:00:00Z",
  "signature_verified": true,
  "file_count": 2,
  "findings": [
    {
      "title": "...",
      "risk": "critical | high | medium | low | info",
      "description": "...",
      "remediation": "..."
    }
  ],
  "typosquat_suspects": []
}
```

## 测试金字塔

```
                  ┌─────────────────────┐
                  │ examples/basic_audit│  E2E: 用户可见入口
                  └─────────┬───────────┘
                            │
        ┌───────────────────┼────────────────────────┐
        │                   │                        │
        ▼                   ▼                        ▼
  moon_guard_test.mbt     cmd/main/main_wbtest.mbt  lib/verify/fuzz_test.mbt
  (根包 E2E)              (CLI whitebox)           (property-based fuzz)
        │                                              │
        └──────────────────┬───────────────────────────┘
                           ▼
        lib/*/_test.mbt  (每个 lib 一份单元测试)
                           │
                           ▼
        lib/verify/bench_test.mbt  (基准/性能烟雾)
```

- **单元测试**：每个 lib 模块一份 `*_test.mbt`，共 ~50 个 test
- **白盒测试**：`cmd/main/main_wbtest.mbt` 直接调用 CLI 内部 helper
- **端到端**：`moon_guard_test.mbt` + `examples/basic_audit/main.mbt`
- **Fuzz**：`lib/verify/fuzz_test.mbt`，50+20 个随机 / 确定性输入
- **Bench**：`lib/verify/bench_test.mbt`，覆盖 SHA-256 / typosquat / verify_package 热路径

## 集成模式（用户视角）

```bash
# Step 1: 在月兔环境下添加 MoonGuard 作为本地依赖
moon add chenzehaoo/moon_guard

# Step 2: 把示例复制到自己的项目
cp examples/basic_audit/main.mbt ./audit.mbt

# Step 3: 调用 MoonGuard 公开 API
moon run -- audit
```

或者直接作为 CLI：

```bash
moon run cmd/main -- audit my-package 1.0.0 "src/main.mbt:fn main { }"
```

## 扩展点

如果需要扩展 MoonGuard，建议保留：

1. **纯 MoonBit 原则**：新算法不要引入外部依赖（除非已被标准 `core` 覆盖）
2. **依赖分层**：新模块放在 `lib/` 下，先看是否已有依赖；只能往下依赖，不可循环
3. **错误可见**：反序列化函数返回 `String?` / `Array?` 而不是抛错，让调用方做恰当处理
4. **测试覆盖**：每个新公开 API 必须有单元测试 + 至少一个 E2E 用例

可以扩展的方向（章程附录一推荐）：

- **CLI**：增加 `trust import/export`（从 PEM 批量导入）、`manifest scan`（文件系统遍历）
- **Typosquat**：增加 brand-similarity 检测（与 npm 已知品牌词比对）
- **Audit**：增加 SARIF / CycloneDX SBOM 导出
- **Trust**：增加 OS keyring 集成（用 `@moonbitlang/async`）
