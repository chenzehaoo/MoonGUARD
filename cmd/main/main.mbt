///|
fn main {
  let args = @env.args()
  if args.length() < 2 {
    print_usage()
    return
  }
  match args[1] {
    "keygen" => cmd_keygen()
    "sign" => cmd_sign(args)
    "verify" => cmd_verify(args)
    "trust" => cmd_trust(args)
    "typosquat" => cmd_typosquat(args)
    "audit" => cmd_audit(args)
    "manifest" => cmd_manifest(args)
    "hash" => cmd_hash(args)
    "-h" | "--help" => print_usage()
    "-v" | "--version" => println("MoonGuard v0.1.0")
    _ => {
      println("Unknown command: " + args[1])
      print_usage()
    }
  }
}

///|
fn print_usage() -> Unit {
  println("MoonGuard - MoonBit Supply Chain Security Tool")
  println("")
  println("Usage: moon_guard <command> [options]")
  println("")
  println("Commands:")
  println("  keygen              Generate Ed25519 keypair")
  println("  sign <msg> <seed>   Sign a message")
  println("  verify <msg> <sig> <pubkey>  Verify signature")
  println("  trust <add|list|remove> ...  Manage trust store")
  println("  typosquat <name> <known...>  Check for typosquatting")
  println("  manifest <gen|verify|hash> ...  Package manifest ops")
  println("  hash <content>      Compute SHA-256 hash")
  println("  audit <pkg> <ver>   Full security audit with report")
  println("")
  println("  -h, --help          Show this help message")
  println("  -v, --version       Show version")
}

///|
fn cmd_keygen() -> Unit {
  let seed = demo_seed()
  let kp = @crypto.generate_keypair(seed)
  println("Ed25519 Keypair Generated")
  println("  seed:       " + seed)
  println("  public_key: " + kp.public_key)
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
  let result = @verify.verify_package(msg, sig_hex, pubkey, msg)
  if result.is_valid {
    println("Verification: PASS")
  } else {
    println("Verification: FAIL")
    for i = 0; i < result.errors.length(); i = i + 1 {
      println("  error: " + result.errors[i])
    }
  }
}

///|
fn cmd_trust(args : Array[String]) -> Unit {
  if args.length() < 3 {
    println("Usage: moon_guard trust <add|list|remove> [key_id] [pubkey] [owner]")
    return
  }
  let store = @trust.TrustStore::new()
  match args[2] {
    "add" => {
      if args.length() < 6 {
        println("Usage: moon_guard trust add <key_id> <pubkey> <owner>")
        return
      }
      let ok = store.add_key(args[3], args[4], args[5], @trust.TrustLevel::Full)
      if ok {
        println("Key added: " + args[3] + " (owner: " + args[5] + ")")
      } else {
        println("Failed to add key (invalid format or duplicate)")
      }
    }
    "list" => {
      println("Trust Store: " + store.key_count().to_string() + " keys")
      println(@trust.trust_store_to_json(store))
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
  let results = @verify.detect_typosquat(name, known)
  if results.length() == 0 {
    println("No typosquat risk detected for: " + name)
  } else {
    println("Typosquat WARNING for: " + name)
    for i = 0; i < results.length(); i = i + 1 {
      let r = results[i]
      println("  similar to: " + r.similar_to + " (" + r.attack_type + ")")
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
  let sig_hex = sig.r + sig.s
  let vr = @verify.verify_package(pkg_name, sig_hex, kp.public_key, pkg_name)
  report.signature_verified = vr.is_valid
  let demo_entries = [
    @manifest.FileEntry::{ path: "src/main.mbt", content: "fn main {}" },
    @manifest.FileEntry::{ path: "src/lib.mbt", content: "pub fn hello() -> String { \"hi\" }" },
    @manifest.FileEntry::{ path: "moon.pkg.json", content: "{}" },
  ]
  let m = @manifest.generate_manifest(pkg_name, pkg_ver, demo_entries)
  report.file_count = m.total_files
  let mismatches = @manifest.verify_manifest(m, demo_entries)
  if mismatches.length() > 0 {
    report.add_finding(@report.Finding::{
      title: "File integrity check failed",
      description: mismatches.length().to_string() + " file(s) modified",
      risk_level: @report.RiskLevel::Critical,
      remediation: "Re-download package from trusted source",
    })
  }
  let known = ["lodash", "express", "react", "angular", "moment", "axios"]
  let typo_results = @verify.detect_typosquat(pkg_name, known)
  for i = 0; i < typo_results.length(); i = i + 1 {
    report.typosquat_suspects.push(typo_results[i].similar_to)
    report.add_finding(@report.Finding::{
      title: "Typosquat risk: similar to " + typo_results[i].similar_to,
      description: "Attack type: " + typo_results[i].attack_type,
      risk_level: @report.RiskLevel::High,
      remediation: "Verify package name is correct",
    })
  }
  if not(report.signature_verified) {
    report.add_finding(@report.Finding::{
      title: "Signature verification failed",
      description: "Package signature could not be verified",
      risk_level: @report.RiskLevel::Critical,
      remediation: "Obtain valid signature from package author",
    })
  }
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
    println("Usage: moon_guard manifest <gen|verify|hash> ...")
    println("  gen <pkg> <ver> <file:content...>  Generate manifest")
    println("  verify <pkg> <ver> <file:content...>  Verify integrity")
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
fn parse_file_entries(args : Array[String], start : Int) -> Array[@manifest.FileEntry] {
  let entries : Array[@manifest.FileEntry] = []
  for i = start; i < args.length(); i = i + 1 {
    let arg = args[i]
    let colon_idx = find_char(arg, ':')
    if colon_idx >= 0 {
      let path = arg.substring(start=0, end=colon_idx)
      let content = arg.substring(start=colon_idx + 1, end=arg.length())
      entries.push(@manifest.FileEntry::{ path, content })
    }
  }
  if entries.length() == 0 {
    entries.push(@manifest.FileEntry::{ path: "demo.mbt", content: "fn main {}" })
    entries.push(@manifest.FileEntry::{ path: "lib.mbt", content: "pub fn hello() -> String { \"hi\" }" })
  }
  entries
}

///|
fn find_char(s : String, c : Int) -> Int {
  for i = 0; i < s.length(); i = i + 1 {
    if s[i] == c {
      return i
    }
  }
  -1
}

///|
fn demo_seed() -> String {
  "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
}
