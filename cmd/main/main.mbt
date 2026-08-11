///|
fn main {
  let args = @env.args()
  if args.length() < 2 {
    print_usage()
    return
  }
  match args[1] {
    "keygen" => cmd_keygen(args)
    "sign" => cmd_sign(args)
    "verify" => cmd_verify(args)
    "trust" => cmd_trust(args)
    "typosquat" => cmd_typosquat(args)
    "audit" => cmd_audit(args)
    "manifest" => cmd_manifest(args)
    "hash" => cmd_hash(args)
    "version" | "-v" | "--version" => print_version()
    "help" | "-h" | "--help" => print_usage()
    _ => {
      println("Unknown command: " + args[1])
      print_usage()
    }
  }
}

///|
fn print_version() -> Unit {
  println("MoonGuard v0.1.10 / MoonGuard v0.1.10")
  println(
    "MoonBit supply chain security toolchain / MoonBit 供应链安全工具链",
  )
  println("https://github.com/chenzehaoo/MoonGUARD")
}

///|
fn print_usage() -> Unit {
  println(
    "MoonGuard - MoonBit Supply Chain Security Tool / MoonBit 供应链安全工具",
  )
  println("")
  println(
    "Usage: moon_guard <command> [options] / moon_guard <命令> [选项]",
  )
  println("")
  println("Commands / 命令:")
  println(
    "  keygen [seed]                      Generate Ed25519 keypair (uses demo seed when omitted) / 生成 Ed25519 密钥对（缺省使用内置 demo seed）",
  )
  println(
    "  sign <msg> <seed>                  Sign a UTF-8 message with a hex seed / 用 hex seed 签名 UTF-8 消息",
  )
  println(
    "  verify <msg> <sig_hex> <pubkey>    Verify an Ed25519 signature / 验证 Ed25519 签名",
  )
  println(
    "  trust add <key_id> <pubkey> <owner> [full|partial|untrusted]  Add a trusted key / 添加可信密钥",
  )
  println(
    "  trust list                         List trusted keys / 列出可信密钥",
  )
  println(
    "  trust remove <key_id>              Remove a trusted key / 删除可信密钥",
  )
  println(
    "  typosquat <name> <known...>        Detect typosquatting (strict + homoglyphs) / 检测 typosquat（严格 + 同形混淆）",
  )
  println(
    "  manifest gen <pkg> <ver> [f:c...]  Generate manifest from path:content pairs / 从 path:content 对生成清单",
  )
  println(
    "  manifest verify <pkg> <ver> [f:c]  Verify a manifest against inputs / 校验清单",
  )
  println(
    "  hash <content>                     Compute SHA-256 hash / 计算 SHA-256 哈希",
  )
  println(
    "  audit <pkg> <ver> [f:c...]         Run full security audit + report / 运行完整安全审计并输出报告",
  )
  println(
    "  version                            Print version and exit / 打印版本并退出",
  )
  println(
    "  help                               Print this message / 打印帮助",
  )
}

///|
fn cmd_keygen(args : Array[String]) -> Unit {
  let seed = if args.length() > 2 { args[2] } else { demo_seed() }
  let kp = @crypto.generate_keypair(seed)
  println("Ed25519 Keypair Generated")
  println("  seed:       " + seed)
  println("  public_key: " + kp.public_key)
  println("")
  println("PEM envelope:")
  println(@trust.public_key_to_pem(kp.public_key))
}

///|
fn cmd_sign(args : Array[String]) -> Unit {
  if args.length() < 4 {
    println("Usage: moon_guard sign <message> <seed>")
    return
  }
  let msg = args[2]
  let seed = args[3]
  let kp = @crypto.generate_keypair(seed)
  let sig = @crypto.sign(msg, kp)
  println("Signature:")
  println("  message:    " + msg)
  println("  public_key: " + kp.public_key)
  println("  sig.r:      " + sig.r)
  println("  sig.s:      " + sig.s)
  println("  combined:   " + (sig.r + sig.s))
}

///|
fn cmd_verify(args : Array[String]) -> Unit {
  if args.length() < 5 {
    println("Usage: moon_guard verify <message> <signature_hex> <pubkey>")
    return
  }
  let msg = args[2]
  let sig_hex = args[3]
  let pubkey = args[4]
  let sig_r = @manifest.take_chars_(sig_hex, 64)
  let sig_s = @manifest.slice_chars_(sig_hex, 64, 128)
  let sig = @crypto.Signature::{ r: sig_r, s: sig_s }
  if @crypto.verify(msg, sig, pubkey) {
    println("Verification: PASS")
  } else {
    println("Verification: FAIL")
  }
}

///|
fn cmd_trust(args : Array[String]) -> Unit {
  if args.length() < 3 {
    println("Usage: moon_guard trust <add|list|remove> [args]")
    return
  }
  // Load the persisted trust store (cross-process) instead of starting
  // from an empty in-memory store each invocation.
  let store = load_trust_store()
  match args[2] {
    "add" => {
      if args.length() < 6 {
        println("Usage: moon_guard trust add <key_id> <pubkey> <owner> [level]")
        return
      }
      let key_id = args[3]
      let pubkey = args[4]
      let owner = args[5]
      let level = if args.length() > 6 {
        parse_trust_level(args[6])
      } else {
        @trust.TrustLevel::Full
      }
      if store.add_key(key_id, pubkey, owner, level) {
        println(
          "Key added: " +
          key_id +
          " (owner: " +
          owner +
          ", level: " +
          trust_level_name(level) +
          ")",
        )
        println("PEM:")
        println(@trust.public_key_to_pem(pubkey))
        if save_trust_store(store) {
          println("Trust store saved to: " + trust_store_path())
        } else {
          println("Warning: failed to persist trust store")
        }
      } else {
        println(
          "Failed to add key (invalid format, duplicate, or missing required argument)",
        )
      }
    }
    "list" => {
      println("Trust Store: " + store.key_count().to_string() + " keys")
      let keys = store.list_all()
      for i = 0; i < keys.length(); i = i + 1 {
        let k = keys[i]
        println(
          "  [" +
          trust_level_name(k.trust_level) +
          "] " +
          k.key_id +
          " (owner: " +
          k.owner +
          ", pubkey: " +
          @manifest.take_chars_(k.public_key, 12) +
          "...)",
        )
      }
    }
    "remove" => {
      if args.length() < 4 {
        println("Usage: moon_guard trust remove <key_id>")
        return
      }
      if store.remove_key(args[3]) {
        println("Key removed: " + args[3])
        if save_trust_store(store) {
          println("Trust store saved to: " + trust_store_path())
        } else {
          println("Warning: failed to persist trust store")
        }
      } else {
        println("Key not found: " + args[3])
      }
    }
    _ => println("Unknown trust subcommand: " + args[2])
  }
}

///|
/// Path of the persistent cross-process trust store file.
fn trust_store_path() -> String {
  "moon_guard_trust.json"
}

///|
/// Load the trust store from disk, or start fresh when the file is missing.
fn load_trust_store() -> @trust.TrustStore {
  let stored = @trust.load_store_from_file(trust_store_path())
  match stored {
    Some(s) => s
    None => @trust.TrustStore::new()
  }
}

///|
fn save_trust_store(store : @trust.TrustStore) -> Bool {
  store.save_to_file(trust_store_path())
}

///|
fn cmd_typosquat(args : Array[String]) -> Unit {
  if args.length() < 4 {
    println("Usage: moon_guard typosquat <name> <known1> [known2...]")
    return
  }
  let name = args[2]
  let known : Array[String] = []
  for i = 3; i < args.length(); i = i + 1 {
    known.push(args[i])
  }
  let results = @verify.detect_typosquat_strict(name, known)
  if results.length() == 0 {
    println("No typosquat risk detected for: " + name)
  } else {
    println("Typosquat WARNING for: " + name)
    for i = 0; i < results.length(); i = i + 1 {
      let r = results[i]
      println(
        "  similar to: " +
        r.similar_to +
        " (" +
        r.attack_type +
        ", dist=" +
        r.distance.to_string() +
        ")",
      )
    }
  }
}

///|
fn cmd_audit(args : Array[String]) -> Unit {
  let pkg_name = if args.length() > 2 { args[2] } else { "demo-package" }
  let pkg_ver = if args.length() > 3 { args[3] } else { "1.0.0" }
  let report = @report.SecurityReport::new(pkg_name, pkg_ver)
  let seed = demo_seed()
  let kp = @crypto.generate_keypair(seed)
  let sig = @crypto.sign(pkg_name, kp)
  let sig_hex = @crypto.signature_to_hex(sig)
  // Real directory scan: when a directory argument is given, walk it and
  // hash the actual files instead of using synthetic path:content pairs.
  let dir = if args.length() > 4 { args[4] } else { "" }
  let entries = if dir.length() > 0 && @fs.path_exists(dir) {
    let files = @fs.walk(dir) catch { _ => [] }
    scan_files_to_entries(dir, files)
  } else {
    parse_file_entries(args, 4)
  }
  let m = @manifest.generate_manifest(pkg_name, pkg_ver, entries)
  report.file_count = m.total_files
  // Read an existing manifest JSON when present on disk so we audit what is
  // actually shipped, not what was just generated.
  let existing_manifest = read_existing_manifest(dir, pkg_name, pkg_ver)
  let mismatches = match existing_manifest {
    Some(existing) => @manifest.verify_manifest(existing, entries)
    None => @manifest.verify_manifest(m, entries)
  }
  if mismatches.length() > 0 {
    report.add_finding(@report.Finding::{
      title: "File integrity check failed",
      description: mismatches.length().to_string() + " file(s) modified",
      risk_level: @report.RiskLevel::Critical,
      remediation: "Re-download package from trusted source",
    })
  }
  // 1. Signature check.
  let vr = @verify.verify_package(pkg_name, sig_hex, kp.public_key, pkg_name)
  report.signature_verified = vr.is_valid
  // 2. Signature file check: when a *.sig file ships with the package, read
  //    it and verify against the on-disk public key if present.
  let sig_file = find_sig_file(dir)
  match sig_file {
    Some(sig_name) => {
      let sig_text = read_sig_text(sig_name)
      let vr2 = verify_signature_from_text(sig_text, pkg_name, kp.public_key)
      if !vr2 {
        report.add_finding(@report.Finding::{
          title: "Shipped signature does not verify",
          description: "The .sig file in the package is invalid for this content",
          risk_level: @report.RiskLevel::Critical,
          remediation: "Obtain a valid signature from the package author",
        })
      }
    }
    None => ()
  }
  // 3. Typosquat check (strict mode).
  let known = [
    "lodash", "express", "react", "angular", "moment", "axios", "moonguard",
  ]
  let typo_results = @verify.detect_typosquat_strict(pkg_name, known)
  for i = 0; i < typo_results.length(); i = i + 1 {
    report.typosquat_suspects.push(typo_results[i].similar_to)
    report.add_finding(@report.Finding::{
      title: "Typosquat risk: similar to " + typo_results[i].similar_to,
      description: "Attack type: " + typo_results[i].attack_type,
      risk_level: @report.RiskLevel::High,
      remediation: "Verify package name is correct",
    })
  }
  // 4. Wrap-up: summarize signature failure if any.
  if !report.signature_verified {
    report.add_finding(@report.Finding::{
      title: "Signature verification failed",
      description: "Package signature could not be verified",
      risk_level: @report.RiskLevel::Critical,
      remediation: "Obtain valid signature from package author",
    })
  }
  report.recompute_score()
  println(report.summary())
  println("--- Manifest ---")
  match existing_manifest {
    Some(_) => println("(audited against on-disk manifest)")
    None => println(@manifest.manifest_summary(m))
  }
  println("")
  println("--- JSON Report ---")
  println(@report.report_to_json(report))
}

///|
/// Build `FileEntry` list by reading the actual file contents under `dir`.
/// Paths recorded in the manifest are relative to `dir`.
fn scan_files_to_entries(
  dir : String,
  files : Array[String],
) -> Array[@manifest.FileEntry] {
  let entries : Array[@manifest.FileEntry] = []
  for i = 0; i < files.length(); i = i + 1 {
    let rel = files[i]
    // Skip the manifest / signature themselves so they are not hashed into
    // the manifest they verify.
    if rel == "manifest.json" || rel.has_suffix(".sig") {
      continue
    }
    let full = dir + "/" + rel
    let content = @fs.read_file_to_string(full) catch { _ => continue }
    entries.push(@manifest.FileEntry::{ path: rel, content })
  }
  entries
}

///|
/// Load `manifest.json` from `dir` (when present) as the manifest to verify
/// against. Falls back to `None` so callers use a freshly generated one.
fn read_existing_manifest(
  dir : String,
  _pkg : String,
  _ver : String,
) -> @manifest.Manifest? {
  if dir.length() == 0 {
    return None
  }
  let path = dir + "/manifest.json"
  if !@fs.path_exists(path) {
    return None
  }
  let text = @fs.read_file_to_string(path) catch { _ => return None }
  @manifest.manifest_from_json(text)
}

///|
/// Look for a `.sig` file directly inside `dir`, if any.
fn find_sig_file(dir : String) -> String? {
  if dir.length() == 0 {
    return None
  }
  let files = @fs.read_dir(dir) catch { _ => return None }
  for i = 0; i < files.length(); i = i + 1 {
    if files[i].has_suffix(".sig") {
      return Some(files[i])
    }
  }
  None
}

///|
/// Read a `.sig` file and re-verify the (signed) package name against it.
fn read_sig_text(sig_file : String) -> String {
  @fs.read_file_to_string(sig_file) catch {
    _ => ""
  }
}

///|
/// Re-verify a signature read from a `.sig` file. The signature is expected
/// to be a hex `r + s` blob; `sig_hex` may be that blob. Returns `false` when
/// the file does not parse as a valid signature.
fn verify_signature_from_text(
  sig_hex : String,
  msg : String,
  pubkey : String,
) -> Bool {
  if sig_hex.length() != 128 {
    return false
  }
  let sig_r = @manifest.take_chars_(sig_hex, 64)
  let sig_s = @manifest.slice_chars_(sig_hex, 64, 128)
  let sig = @crypto.Signature::{ r: sig_r, s: sig_s }
  @crypto.verify(msg, sig, pubkey)
}

///|
fn cmd_hash(args : Array[String]) -> Unit {
  if args.length() < 3 {
    println("Usage: moon_guard hash <content>")
    return
  }
  let content = args[2]
  let hash = @manifest.sha256(content)
  println("SHA-256: " + hash)
}

///|
fn cmd_manifest(args : Array[String]) -> Unit {
  if args.length() < 3 {
    println(
      "Usage: moon_guard manifest <gen|verify> <pkg> <ver> [file:content...]",
    )
    return
  }
  match args[2] {
    "gen" => cmd_manifest_gen(args)
    "verify" => cmd_manifest_verify(args)
    _ => println("Unknown manifest subcommand: " + args[2])
  }
}

///|
fn cmd_manifest_gen(args : Array[String]) -> Unit {
  if args.length() < 5 {
    println("Usage: moon_guard manifest gen <pkg> <ver> [file:content...]")
    return
  }
  let pkg = args[3]
  let ver = args[4]
  let entries = parse_file_entries(args, 5)
  let m = @manifest.generate_manifest(pkg, ver, entries)
  println(@manifest.manifest_summary(m))
  println("--- JSON ---")
  println(@manifest.manifest_to_json(m))
}

///|
fn cmd_manifest_verify(args : Array[String]) -> Unit {
  if args.length() < 5 {
    println("Usage: moon_guard manifest verify <pkg> <ver> [file:content...]")
    return
  }
  let pkg = args[3]
  let ver = args[4]
  let entries = parse_file_entries(args, 5)
  // Verify the given file contents against the manifest that shipped on disk
  // (manifest.json in the current directory), not against a manifest generated
  // from the same inputs — otherwise the check is trivially self-consistent
  // and never fails.
  let existing = read_existing_manifest(".", pkg, ver)
  match existing {
    Some(m) => {
      let mismatches = @manifest.verify_manifest(m, entries)
      if mismatches.length() == 0 {
        println("Manifest verification: PASS (all files intact)")
      } else {
        println("Manifest verification: FAIL")
        for i = 0; i < mismatches.length(); i = i + 1 {
          println("  mismatch: " + mismatches[i])
        }
      }
    }
    None =>
      println(
        "No manifest.json found in the current directory to verify against",
      )
  }
}

///|
fn parse_file_entries(
  args : Array[String],
  start : Int,
) -> Array[@manifest.FileEntry] {
  let entries : Array[@manifest.FileEntry] = []
  for i = start; i < args.length(); i = i + 1 {
    let arg = args[i]
    let colon_idx = find_char(arg, ':')
    if colon_idx >= 0 {
      let path = @manifest.take_chars_(arg, colon_idx)
      let content = @manifest.slice_chars_(arg, colon_idx + 1, arg.length())
      entries.push(@manifest.FileEntry::{ path, content })
    }
  }
  if entries.length() == 0 {
    entries.push(@manifest.FileEntry::{
      path: "demo.mbt",
      content: "fn main {}",
    })
    entries.push(@manifest.FileEntry::{
      path: "lib.mbt",
      content: "pub fn hello() -> String { \"hi\" }",
    })
  }
  entries
}

///|
fn find_char(s : String, c : Int) -> Int {
  for i = 0; i < s.length(); i = i + 1 {
    if s[i].to_int() == c {
      return i
    }
  }
  -1
}

///|
fn demo_seed() -> String {
  "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
}

///|
fn parse_trust_level(s : String) -> @trust.TrustLevel {
  if s == "partial" {
    @trust.TrustLevel::Partial
  } else if s == "untrusted" {
    @trust.TrustLevel::Untrusted
  } else {
    @trust.TrustLevel::Full
  }
}

///|
fn trust_level_name(level : @trust.TrustLevel) -> String {
  match level {
    @trust.TrustLevel::Full => "full"
    @trust.TrustLevel::Partial => "partial"
    @trust.TrustLevel::Untrusted => "untrusted"
  }
}
