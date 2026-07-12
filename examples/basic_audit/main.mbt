// Minimal end-to-end audit pipeline that calls into MoonGuard's public
// API. After `moon add chenzehaoo/moon_guard` this file is runnable as:
//   moon run examples/basic_audit
//
// It demonstrates:
//   1. Generating an Ed25519 keypair from a deterministic seed.
//   2. Building a manifest from in-memory file entries.
//   3. Signing the canonical manifest JSON.
//   4. Running the full audit pipeline (file integrity + signature + trust).
//   5. Producing a security report and printing it as JSON.

///|
fn main {
  // 1. Deterministic seed -> keypair. Same seed always produces the
  //    same Ed25519 keypair, which is useful for reproducible demos.
  let seed = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
  let keypair = @crypto.generate_keypair(seed)
  println("Public key: " + keypair.public_key)

  // 2. Build a manifest with two files.
  let entries : Array[@manifest.FileEntry] = [
    { path: "src/main.mbt", content: "fn main { println(\"hello\") }" },
    {
      path: "src/lib.mbt",
      content: "pub fn add(a: Int, b: Int) -> Int { a + b }",
    },
  ]
  let manifest = @manifest.generate_manifest("demo_pkg", "1.0.0", entries)
  println("Manifest: " + @manifest.manifest_summary(manifest))

  // 3. Sign the canonical manifest JSON.
  let payload = @manifest.manifest_to_json(manifest)
  let signature = @crypto.sign(payload, keypair)
  println("Signed " + payload.length().to_string() + " bytes.")

  // 4. Run the full audit pipeline. The signer key is in the trust store
  //    at `Full` level, so the audit should pass.
  let store = @trust.TrustStore::new()
  let _ = store.add_key(
    "alice",
    keypair.public_key,
    "alice",
    @trust.TrustLevel::Full,
  )
  let result = @verify.audit_package(
    "demo_pkg",
    "1.0.0",
    manifest,
    entries,
    @verify.signature_to_hex(signature),
    "alice",
    store,
  )
  println("Audit is_valid: " + result.is_valid.to_string())
  println("Audit trust_status: " + result.trust_status)
  for i = 0; i < result.errors.length(); i = i + 1 {
    println("  error: " + result.errors[i])
  }

  // 5. Build and serialize a security report.
  let report = @report.SecurityReport::new("demo_pkg", "1.0.0")
  report.file_count = manifest.total_files
  report.signature_verified = result.is_valid
  if not(result.is_valid) {
    report.add_finding(@report.Finding::{
      title: "Audit failed",
      description: "see errors",
      risk_level: @report.RiskLevel::High,
      remediation: "re-run pipeline",
    })
  }
  report.recompute_score()
  println("--- JSON Report ---")
  println(@report.report_to_json(report))
}
