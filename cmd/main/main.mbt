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
  println("MoonGuard v0.1.11 / MoonGuard v0.1.11")
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
    "  audit <pkg> <ver> <dir|f:c...> [--signature <file|hex>] [--trust-store <file>] [--signer <key_id>] [--pubkey <file|hex>]  Run audit against external manifest/signature/trust evidence / 基于外部清单、签名和信任库审计",
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
  let dir = audit_dir_arg(args)
  let entries = if dir.length() > 0 {
    let files = @fs.walk(dir) catch { _ => [] }
    scan_files_to_entries(dir, files)
  } else {
    parse_file_entries(args, 4)
  }
  let manifest = read_audit_manifest(args, dir)
  match manifest {
    None => {
      report.add_finding(@report.Finding::{
        title: "Manifest missing or unreadable",
        description: "Audit requires an existing manifest.json or --manifest file",
        risk_level: @report.RiskLevel::Critical,
        remediation: "Generate and ship a manifest before auditing the package",
      })
      report.recompute_score()
      print_audit_report(report, None)
      return
    }
    Some(m) => {
      report.file_count = m.total_files
      let mismatches = @manifest.verify_manifest(m, entries)
      if mismatches.length() > 0 {
        report.add_finding(@report.Finding::{
          title: "File integrity check failed",
          description: mismatches.length().to_string() + " file(s) modified",
          risk_level: @report.RiskLevel::Critical,
          remediation: "Re-download package from trusted source",
        })
      }
      let sig_hex = read_audit_signature(args, dir)
      match sig_hex {
        None =>
          report.add_finding(@report.Finding::{
            title: "External signature missing or invalid",
            description: "Audit requires a 128-character signature hex blob from --signature or a .sig file",
            risk_level: @report.RiskLevel::Critical,
            remediation: "Provide the package author's detached signature",
          })
        Some(sig) => {
          let store = load_audit_trust_store(args, dir)
          match store {
            None =>
              report.add_finding(@report.Finding::{
                title: "Trust store missing or unreadable",
                description: "Audit requires a valid trust store from --trust-store, package directory, or working directory",
                risk_level: @report.RiskLevel::High,
                remediation: "Provide a trust store containing the signer's public key",
              })
            Some(ts) => {
              let signer = audit_signer_key(args, ts)
              match signer {
                None =>
                  report.add_finding(@report.Finding::{
                    title: "Signer key id is ambiguous",
                    description: "Use --signer when the trust store is empty or contains multiple keys",
                    risk_level: @report.RiskLevel::High,
                    remediation: "Pass --signer <key_id> for the package author",
                  })
                Some(key_id) => {
                  check_external_public_key(args, dir, ts, key_id, report)
                  let vr = @verify.audit_package(
                    pkg_name, pkg_ver, m, entries, sig, key_id, ts,
                  )
                  report.signature_verified = vr.signature_ok
                  if !vr.signature_ok {
                    report.add_finding(@report.Finding::{
                      title: "Signature verification failed",
                      description: "Package manifest signature could not be verified with the trusted public key",
                      risk_level: @report.RiskLevel::Critical,
                      remediation: "Obtain a valid signature from the package author",
                    })
                  }
                  if vr.trust_status == "untrusted" {
                    report.add_finding(@report.Finding::{
                      title: "Signer is explicitly untrusted",
                      description: "Signer key " +
                      key_id +
                      " is marked Untrusted",
                      risk_level: @report.RiskLevel::Critical,
                      remediation: "Use a trusted signer key",
                    })
                  } else if vr.trust_status == "unknown" {
                    report.add_finding(@report.Finding::{
                      title: "Signer is not trusted",
                      description: "Signer key " +
                      key_id +
                      " is not present in the trust store",
                      risk_level: @report.RiskLevel::High,
                      remediation: "Add the signer key to the trust store after out-of-band verification",
                    })
                  }
                }
              }
            }
          }
        }
      }
      // Typosquat check (strict mode).
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
      report.recompute_score()
      print_audit_report(report, Some(m))
    }
  }
}

///|
fn print_audit_report(
  report : @report.SecurityReport,
  manifest : @manifest.Manifest?,
) -> Unit {
  println(report.summary())
  println("--- Manifest ---")
  match manifest {
    Some(m) => {
      println("(audited against external manifest)")
      println(@manifest.manifest_summary(m))
    }
    None => println("(no external manifest available)")
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
    if rel == "manifest.json" ||
      rel == "moon_guard_trust.json" ||
      rel.has_suffix(".sig") ||
      rel.has_suffix(".pem") ||
      rel.has_suffix(".pub") {
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
fn read_manifest_file(path : String) -> @manifest.Manifest? {
  if !@fs.path_exists(path) {
    return None
  }
  let text = @fs.read_file_to_string(path) catch { _ => return None }
  @manifest.manifest_from_json(text)
}

///|
fn read_audit_manifest(
  args : Array[String],
  dir : String,
) -> @manifest.Manifest? {
  match arg_value(args, "--manifest") {
    Some(path) => read_manifest_file(path)
    None => read_existing_manifest(dir, "", "")
  }
}

///|
/// Look for a `.sig` file directly inside `dir`, if any. The returned path
/// includes `dir`, so callers can read the file from outside the cwd.
fn find_sig_file(dir : String) -> String? {
  if dir.length() == 0 {
    return None
  }
  let files = @fs.read_dir(dir) catch { _ => return None }
  for i = 0; i < files.length(); i = i + 1 {
    if files[i].has_suffix(".sig") {
      return Some(join_path(dir, files[i]))
    }
  }
  None
}

///|
fn read_audit_signature(args : Array[String], dir : String) -> String? {
  match arg_value(args, "--signature") {
    Some(value) => read_signature_input(value)
    None =>
      match find_sig_file(dir) {
        Some(path) => read_signature_input(path)
        None => None
      }
  }
}

///|
fn read_signature_input(input : String) -> String? {
  let text = if @fs.path_exists(input) {
    @fs.read_file_to_string(input) catch {
      _ => return None
    }
  } else {
    input
  }
  normalize_hex(text, 128)
}

///|
fn load_audit_trust_store(
  args : Array[String],
  dir : String,
) -> @trust.TrustStore? {
  match arg_value(args, "--trust-store") {
    Some(path) => @trust.load_store_from_file(path)
    None => {
      if dir.length() > 0 {
        let store_path = join_path(dir, trust_store_path())
        if @fs.path_exists(store_path) {
          return @trust.load_store_from_file(store_path)
        }
      }
      @trust.load_store_from_file(trust_store_path())
    }
  }
}

///|
fn audit_signer_key(args : Array[String], store : @trust.TrustStore) -> String? {
  match arg_value(args, "--signer") {
    Some(s) => Some(s)
    None => {
      let keys = store.list_all()
      if keys.length() == 1 {
        Some(keys[0].key_id)
      } else {
        None
      }
    }
  }
}

///|
fn check_external_public_key(
  args : Array[String],
  dir : String,
  store : @trust.TrustStore,
  signer : String,
  report : @report.SecurityReport,
) -> Unit {
  let external_key = read_audit_public_key(args, dir)
  match external_key {
    None => ()
    Some(pubkey) =>
      match store.get_key(signer) {
        Some(k) =>
          if k.public_key != pubkey {
            report.add_finding(@report.Finding::{
              title: "Public key does not match trust store",
              description: "The external public key differs from trusted signer " +
              signer,
              risk_level: @report.RiskLevel::Critical,
              remediation: "Verify the signer's public key out of band and update the trust store",
            })
          }
        None => ()
      }
  }
}

///|
fn read_audit_public_key(args : Array[String], dir : String) -> String? {
  match arg_value(args, "--pubkey") {
    Some(value) => read_public_key_input(value)
    None => {
      if dir.length() == 0 {
        return None
      }
      let candidates = [
        "public_key.pem", "moon_guard_public.pem", "moonguard_public.pem", "public_key.pub",
        "moon_guard.pub",
      ]
      for i = 0; i < candidates.length(); i = i + 1 {
        let path = join_path(dir, candidates[i])
        if @fs.path_exists(path) {
          return read_public_key_input(path)
        }
      }
      None
    }
  }
}

///|
fn read_public_key_input(input : String) -> String? {
  let text = if @fs.path_exists(input) {
    @fs.read_file_to_string(input) catch {
      _ => return None
    }
  } else {
    input
  }
  match @trust.public_key_from_pem(text) {
    Some(pubkey) => Some(pubkey)
    None => normalize_hex(text, 64)
  }
}

///|
fn normalize_hex(text : String, expected_len : Int) -> String? {
  let buf = StringBuilder::new(size_hint=expected_len)
  for i = 0; i < text.length(); i = i + 1 {
    let c = text[i]
    if c == ' ' || c == '\n' || c == '\r' || c == '\t' {
      continue
    }
    if c >= 48 && c <= 57 {
      buf.write_char(c.unsafe_to_char())
    } else if c >= 97 && c <= 102 {
      buf.write_char(c.unsafe_to_char())
    } else if c >= 65 && c <= 70 {
      buf.write_char((c + 32).unsafe_to_char())
    } else {
      return None
    }
  }
  let value = buf.to_string()
  if value.length() == expected_len {
    Some(value)
  } else {
    None
  }
}

///|
fn arg_value(args : Array[String], name : String) -> String? {
  for i = 0; i < args.length() - 1; i = i + 1 {
    if args[i] == name {
      return Some(args[i + 1])
    }
  }
  None
}

///|
fn audit_dir_arg(args : Array[String]) -> String {
  if args.length() <= 4 {
    return ""
  }
  let candidate = args[4]
  if candidate.has_prefix("--") {
    return ""
  }
  if @fs.path_exists(candidate) {
    let is_dir = @fs.is_dir(candidate) catch { _ => false }
    if is_dir {
      return candidate
    }
  }
  ""
}

///|
fn join_path(dir : String, name : String) -> String {
  if dir.has_suffix("/") || dir.has_suffix("\\") {
    dir + name
  } else {
    dir + "/" + name
  }
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
