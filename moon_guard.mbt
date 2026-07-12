// Root package re-exports the lib modules so external code (and the
// test-blackbox package) can pull them in via the module path alone.
// Keeping this re-export thin — MoonGuard's public API lives in lib/.
//
// The lib modules are otherwise only reachable through their full
// `chenzehaoo/moon_guard/lib/<name>` paths, which is inconvenient for
// downstream packages that only depend on `chenzehaoo/moon_guard`.

///|
/// Re-export of the lib/manifest package.
pub fn manifest_sha256(data : String) -> String {
  @manifest.sha256(data)
}

///|
/// Re-export of the lib/crypto package — produces an Ed25519 keypair.
pub fn crypto_keypair(seed : String) -> @crypto.KeyPair {
  @crypto.generate_keypair(seed)
}

///|
/// Re-export of the lib/crypto package — signs a UTF-8 message.
pub fn crypto_sign(
  message : String,
  keypair : @crypto.KeyPair,
) -> @crypto.Signature {
  @crypto.sign(message, keypair)
}

///|
/// Re-export of the lib/crypto package — verifies a signature.
pub fn crypto_verify(
  message : String,
  signature : @crypto.Signature,
  public_key : String,
) -> Bool {
  @crypto.verify(message, signature, public_key)
}

///|
/// Re-export of the lib/verify package — verifies a packaged signature.
pub fn verify_package(
  package_name : String,
  signature_hex : String,
  public_key_hex : String,
  content : String,
) -> @verify.VerifyResult {
  @verify.verify_package(package_name, signature_hex, public_key_hex, content)
}

///|
/// Re-export of the lib/trust package — constructs an in-memory store.
pub fn trust_store() -> @trust.TrustStore {
  @trust.TrustStore::new()
}

///|
/// Re-export of the lib/report package — constructs a new security report.
pub fn report_new(
  package_name : String,
  package_version : String,
) -> @report.SecurityReport {
  @report.SecurityReport::new(package_name, package_version)
}
