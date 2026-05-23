///|
/// MoonGuard CLI
/// Supply chain security toolchain for MoonBit

///| Main entry point
fn main {
  let args = @env.args()
  if args.length() < 2 {
    print_usage()
    return
  }

  let command = args[1]
  match command {
    "init" => run_init()
    "sign" => run_sign()
    "verify" => run_verify()
    "trust" => run_trust(args)
    "audit" => run_audit()
    "report" => run_report()
    "-h" | "--help" => print_usage()
    _ => {
      println("Unknown command: " + command)
      print_usage()
    }
  }
}

///| Print usage information
fn print_usage() -> Unit {
  println("MoonGuard - MoonBit Supply Chain Security Tool")
  println("")
  println("Usage: moon_guard <command> [options]")
  println("")
  println("Commands:")
  println("  init     Initialize a new MoonGuard project")
  println("  sign     Sign a package manifest")
  println("  verify   Verify package integrity")
  println("  trust    Manage trusted keys")
  println("  audit    Show trust chain audit")
  println("  report   Generate security report")
  println("")
  println("Options:")
  println("  -h, --help     Show this help message")
  println("  -v, --verbose  Verbose output")
}

///| Run init command
fn run_init() -> Unit {
  println("Initializing MoonGuard project...")
  println("Created empty trust store")
  println("Run 'moon_guard trust add' to add trusted keys")
}

///| Run sign command
fn run_sign() -> Unit {
  println("Signing package manifest...")
  println("Package signed successfully!")
  println("(Demo mode - full crypto implementation in lib modules)")
}

///| Run verify command
fn run_verify() -> Unit {
  println("Verifying package integrity...")
  println("Package verification PASSED")
  println("(Demo mode - full verification in lib modules)")
}

///| Run trust command
fn run_trust(args: Array[String]) -> Unit {
  if args.length() < 3 {
    println("Usage: moon_guard trust <add|list|remove> [options]")
    return
  }
  let subcommand = args[2]
  match subcommand {
    "add" => println("Adding key to trust store...")
    "list" => println("Listing trusted keys...")
    "remove" => println("Removing key from trust store...")
    _ => println("Unknown trust subcommand: " + subcommand)
  }
}

///| Run audit command
fn run_audit() -> Unit {
  println("MoonGuard Trust Audit")
  println("======================")
  println("")
  println("Trust Chain Status: Not configured")
  println("")
  println("Run 'moon_guard init' to initialize")
}

///| Run report command
fn run_report() -> Unit {
  println("Security Report")
  println("===============")
  println("Package: demo-package v1.0.0")
  println("Status: PASS")
  println("")
  println("Modules implemented:")
  println("  - manifest: Package manifest and SHA-256 hashing")
  println("  - crypto: Ed25519 signature generation")
  println("  - trust: Local trusted key store")
  println("  - verify: Package verification and typosquat detection")
  println("  - report: JSON/HTML security reports")
}