///|
/// MoonGuard Attack Simulation Test
/// Demonstrates how MoonGuard detects package tampering

pub struct PackageFile {
  name: String
  content: String
}

pub struct ManifestEntry {
  path: String
  hash: String
  size: Int
}

pub struct Sig {
  manifest_hash: String
  signer_key_id: String
}

///| Simulated SHA-256 hash (demo only)
fn simulate_sha256(content: String) -> String {
  let prefix = "sha256:"
  let mut hash = ""
  let len = content.length()
  let mut sum = 0
  for i in 0..<len {
    sum = sum + content[i]
  }
  let hex_chars = "0123456789abcdef"
  for i in 0..<64 {
    let idx = (sum + i * 7) % 16
    hash = hash + hex_chars[idx].to_string()
  }
  prefix + hash
}

///| Run the full attack simulation
pub fn run_full_simulation() -> String {
  let mut output = "=== MoonGuard Attack Simulation ===\n\n"

  // Step 1: Legitimate developer creates package
  output = output + "[Step 1] Developer creates package\n"
  output = output + "----------------------------------\n"

  let file1 = "src/main.mbt"
  let content1 = "// Main application code\nfn main() { println(\"Hello\") }"
  let file2 = "src/lib.mbt"
  let content2 = "// Library code\npub fn add(a: Int, b: Int) -> Int { a + b }"

  output = output + "File: " + file1 + "\n"
  output = output + "  Content: " + content1 + "\n"

  // Step 2: Generate manifest (hash each file)
  output = output + "\n[Step 2] Generate manifest (file hashes)\n"
  output = output + "------------------------------------------\n"

  let hash1 = simulate_sha256(content1)
  let hash2 = simulate_sha256(content2)
  output = output + "File: " + file1 + "\n"
  output = output + "  Hash: " + hash1 + "\n"
  output = output + "File: " + file2 + "\n"
  output = output + "  Hash: " + hash2 + "\n"

  // Step 3: Developer signs the manifest
  output = output + "\n[Step 3] Developer signs the manifest\n"
  output = output + "-------------------------------------\n"

  let manifest_content = hash1 + hash2
  let manifest_hash = simulate_sha256(manifest_content)
  output = output + "Manifest Content: " + manifest_content + "\n"
  output = output + "Manifest Hash: " + manifest_hash + "\n"
  output = output + "Signature: [Signed with developer's private key]\n"
  output = output + "Signer: developer_key_001\n"

  // Step 4: Attacker tampers with the package
  output = output + "\n[Step 4] ATTACKER tampers with package!\n"
  output = output + "--------------------------------------------\n"

  let tampered_content = "// Malicious code injected!\nfn main() { println(\"HACKED\") }"
  let tampered_hash = simulate_sha256(tampered_content)
  output = output + "Attacker modified: " + file1 + "\n"
  output = output + "Original hash:    " + hash1 + "\n"
  output = output + "Tampered hash:    " + tampered_hash + "\n"
  output = output + "NEW malicious content: " + tampered_content + "\n"

  // Step 5: Verify the package (should fail!)
  output = output + "\n[Step 5] MoonGuard verifies package\n"
  output = output + "--------------------------------------\n"

  let verification_failed = hash1 != tampered_hash
  if verification_failed {
    output = output + "File: " + file1 + " -> VERIFICATION FAILED!\n"
    output = output + "  Expected: " + hash1 + "\n"
    output = output + "  Actual:   " + tampered_hash + "\n"
    output = output + "  Status:   ATTACK DETECTED!\n"
  }

  // Step 6: Generate security report
  output = output + "\n[Step 6] Generate Security Report\n"
  output = output + "----------------------------------\n"

  output = output + "-----------------------------------\n"
  output = output + "| MoonGuard Security Report      |\n"
  output = output + "-----------------------------------\n"
  output = output + "| Package: my_package v1.0.0     |\n"
  output = output + "| Status: FAIL                   |\n"
  output = output + "-----------------------------------\n"
  output = output + "\n"
  output = output + "Risks Found: 1\n"
  output = output + "---------------\n"
  output = output + "[CRITICAL] File tampering detected!\n"
  output = output + "  File: " + file1 + "\n"
  output = output + "  Issue: Hash mismatch\n"
  output = output + "  Remediation: DO NOT USE\n"

  if verification_failed {
    output = output + "\n========================================\n"
    output = output + "=== ATTACK DETECTED SUCCESSFULLY ===\n"
    output = output + "========================================\n"
  }

  output
}

///|
test "moon_guard attack simulation" {
  let output = run_full_simulation()
  // Just verify the simulation produces output
  inspect(output.length() > 0, content="true")
}