///|
/// MoonGuard end-to-end smoke test.
///
/// Drives the full MoonGuard pipeline against in-memory files:
///   keygen -> manifest -> sign -> tamper -> verify -> trust -> report
///
/// All calls go through the real `@manifest`, `@crypto`, `@verify`,
/// `@trust`, and `@report` modules — there are no simulators or fake
/// hashes.
test "end-to-end tamper detection" {
  // 1. Legitimate developer creates a package with two files.
  let file1 = "src/main.mbt"
  let content1 = "// Main application code\nfn main() { println(\"Hello\") }"
  let file2 = "src/lib.mbt"
  let content2 = "// Library code\npub fn add(a: Int, b: Int) -> Int { a + b }"
  let entries : Array[@manifest.FileEntry] = [
    { path: file1, content: content1, },
    { path: file2, content: content2, },
  ]
  let manifest = @manifest.generate_manifest("my_package", "1.0.0", entries)
  assert_eq(manifest.total_files, 2)

  // 2. Manifest hashes must match real SHA-256 of each file's content.
  assert_eq(manifest.files[0].hash, @manifest.sha256(content1))
  assert_eq(manifest.files[1].hash, @manifest.sha256(content2))

  // 3. Developer signs the manifest JSON with their Ed25519 key.
  let seed = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
  let keypair = @crypto.generate_keypair(seed)
  let manifest_payload = @manifest.manifest_to_json(manifest)
  let signature = @crypto.sign(manifest_payload, keypair)
  let sig_hex = @crypto.signature_to_hex(signature)

  // 4. The whole-package verifier accepts a (msg, sig, pubkey) triple and
  //    reports `is_valid = true` for the legitimate payload.
  let verify_ok = @verify.verify_package(
    "my_package",
    sig_hex,
    keypair.public_key,
    manifest_payload,
  )
  assert_true(verify_ok.is_valid)
  assert_eq(verify_ok.signature_ok, true)

  // 5. Register the developer's public key in the local trust store.
  let store = @trust.TrustStore::new()
  let added = store.add_key(
    "developer_key_001",
    keypair.public_key,
    "alice",
    @trust.TrustLevel::Full,
  )
  assert_true(added)
  assert_true(store.is_trusted("developer_key_001"))
  assert_eq(store.key_count(), 1)

  // 6. Attacker tampers with file1 — swap in malicious content.
  let tampered_content = "// Malicious code injected!\nfn main() { println(\"HACKED\") }"
  let tampered_entries : Array[@manifest.FileEntry] = [
    { path: file1, content: tampered_content, },
    { path: file2, content: content2, },
  ]
  let mismatches = @manifest.verify_manifest(manifest, tampered_entries)
  assert_eq(mismatches.length(), 1)
  assert_eq(mismatches[0], file1)

  // 7. Re-running the whole-package verifier on the tampered payload must
  //    fail — the bytes changed so the Ed25519 signature no longer matches.
  let tampered_manifest = @manifest.generate_manifest(
    "my_package", "1.0.0", tampered_entries,
  )
  let tampered_payload = @manifest.manifest_to_json(tampered_manifest)
  let verify_after_tamper = @verify.verify_package(
    "my_package",
    sig_hex,
    keypair.public_key,
    tampered_payload,
  )
  assert_false(verify_after_tamper.is_valid)

  // 8. Add the attacker as an Untrusted entry to prove the trust store
  //    correctly rejects it even though the key shape is valid.
  let _ = store.add_key(
    "attacker_key_001",
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    "eve",
    @trust.TrustLevel::Untrusted,
  )
  assert_false(store.is_trusted("attacker_key_001"))
  // Is_trusted on a missing key still returns false — non-strict semantics.
  assert_false(store.is_trusted("ghost_key"))

  // 9. Build a security report surfacing every finding.
  let report = @report.SecurityReport::new("my_package", "1.0.0")
  report.file_count = manifest.total_files
  report.signature_verified = verify_ok.is_valid
  if mismatches.length() > 0 {
    report.add_finding({
      title: "File integrity check failed",
      description: "File hash mismatch detected",
      risk_level: @report.RiskLevel::Critical,
      remediation: "Re-download package from a trusted source",
    })
  }
  if !verify_after_tamper.is_valid {
    report.add_finding({
      title: "Signature verification failed",
      description: "Manifest signature does not match signed content",
      risk_level: @report.RiskLevel::Critical,
      remediation: "Obtain a valid signature from the package author",
    })
  }
  assert_eq(report.overall_status, @report.ReportStatus::Fail)
  let summary = report.summary()
  assert_true(summary.contains("FAIL"))
  assert_true(summary.contains("my_package"))

  // 10. JSON export must include both findings and the failing status.
  let json = @report.report_to_json(report)
  assert_true(json.contains("\"status\":\"fail\""))
  assert_true(json.contains("File integrity check failed"))
  assert_true(json.contains("Signature verification failed"))
}

///|
/// The same pipeline without tampering must report PASS everywhere.
test "legitimate package passes all checks" {
  let entries : Array[@manifest.FileEntry] = [
    { path: "src/main.mbt", content: "fn main {}", },
    { path: "src/lib.mbt", content: "pub fn hello() -> String { \"hi\" }", },
  ]
  let manifest = @manifest.generate_manifest("good_pkg", "0.1.0", entries)
  let mismatches = @manifest.verify_manifest(manifest, entries)
  assert_eq(mismatches.length(), 0)
  let seed = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
  let keypair = @crypto.generate_keypair(seed)
  let payload = @manifest.manifest_to_json(manifest)
  let signature = @crypto.sign(payload, keypair)
  let sig_hex = @crypto.signature_to_hex(signature)
  let verify_result = @verify.verify_package(
    "good_pkg",
    sig_hex,
    keypair.public_key,
    payload,
  )
  assert_true(verify_result.is_valid)
  let report = @report.SecurityReport::new("good_pkg", "0.1.0")
  report.file_count = manifest.total_files
  report.signature_verified = true
  // No findings -> overall status stays at Pass.
  assert_eq(report.overall_status, @report.ReportStatus::Pass)
  let summary = report.summary()
  assert_true(summary.contains("PASS"))
  assert_true(summary.contains("good_pkg"))
}

///|
/// Typosquat detection runs in lib/verify; the E2E suite confirms the
/// batch helper surfaces both separator-swap and character-swap attacks.
test "typosquat detection covers multiple attack types" {
  let known = ["lodash", "express", "react"]
  let r1 = @verify.detect_typosquat("1odash", known)
  inspect(r1.length(), content="1")
  inspect(r1[0].attack_type, content="character-swap")
  let r2 = @verify.detect_typosquat("my_package", ["my-package"])
  inspect(r2.length(), content="1")
  inspect(r2[0].attack_type, content="separator-swap")
  // `react` is itself in `known` so it should be filtered out as exact match.
  let r3 = @verify.detect_typosquat("react", known)
  inspect(r3.length(), content="0")
  // Batch helper aggregates across multiple suspects.
  let batch = @verify.batch_typosquat_check(
    ["1odash", "expresss", "react"],
    known,
  )
  inspect(batch.length(), content="2")
}
