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
  println("MoonGuard v0.1.9 / MoonGuard v0.1.9")
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
  let store = @trust.TrustStore::new()
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
        // Echo the resulting PEM so operators can paste it elsewhere.
        println("PEM:")
        println(@trust.public_key_to_pem(pubkey))
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
      } else {
        println("Key not found: " + args[3])
      }
    }
    _ => println("Unknown trust subcommand: " + args[2])
  }
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
  let entries = parse_file_entries(args, 4)
  let m = @manifest.generate_manifest(pkg_name, pkg_ver, entries)
  report.file_count = m.total_files
  // 1. Signature check.
  let vr = @verify.verify_package(pkg_name, sig_hex, kp.public_key, pkg_name)
  report.signature_verified = vr.is_valid
  // 2. Integrity check.
  let mismatches = @manifest.verify_manifest(m, entries)
  if mismatches.length() > 0 {
    report.add_finding(@report.Finding::{
      title: "File integrity check failed",
      description: mismatches.length().to_string() + " file(s) modified",
      risk_level: @report.RiskLevel::Critical,
      remediation: "Re-download package from trusted source",
    })
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
  if not(report.signature_verified) {
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
  println(@manifest.manifest_summary(m))
  println("")
  println("--- JSON Report ---")
  println(@report.report_to_json(report))
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
  let m = @manifest.generate_manifest(pkg, ver, entries)
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
