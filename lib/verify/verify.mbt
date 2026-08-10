///|
pub(all) struct VerifyResult {
  package_name : String
  is_valid : Bool
  signature_ok : Bool
  trust_status : String
  errors : Array[String]
  warnings : Array[String]
}

///|
/// Default `is_valid` threshold: signature must verify, all file hashes
/// must match the manifest, and the signer must be trusted.
pub fn verify_package(
  package_name : String,
  signature_hex : String,
  public_key_hex : String,
  content : String,
) -> VerifyResult {
  let errors : Array[String] = []
  let warnings : Array[String] = []
  if signature_hex.length() != 128 {
    errors.push("invalid signature length")
    return VerifyResult::{
      package_name,
      is_valid: false,
      signature_ok: false,
      trust_status: "unknown",
      errors,
      warnings,
    }
  }
  if public_key_hex.length() != 64 {
    errors.push("invalid public key length")
    return VerifyResult::{
      package_name,
      is_valid: false,
      signature_ok: false,
      trust_status: "unknown",
      errors,
      warnings,
    }
  }
  let sig_r = @manifest.take_chars_(signature_hex, 64)
  let sig_s = @manifest.slice_chars_(signature_hex, 64, 128)
  let sig = @crypto.Signature::{ r: sig_r, s: sig_s }
  let valid = @crypto.verify(content, sig, public_key_hex)
  if !valid {
    errors.push("signature verification failed")
  }
  VerifyResult::{
    package_name,
    is_valid: valid,
    signature_ok: valid,
    trust_status: if valid {
      "verified"
    } else {
      "failed"
    },
    errors,
    warnings,
  }
}

///|
/// Full verification pipeline that ties together manifest integrity,
/// signature verification, and trust-store lookup into one call. Used
/// by the `moon_guard audit` CLI subcommand.
pub fn audit_package(
  package_name : String,
  _package_version : String,
  manifest : @manifest.Manifest,
  entries : Array[@manifest.FileEntry],
  signature_hex : String,
  signer_key_id : String,
  trust_store : @trust.TrustStore,
) -> VerifyResult {
  let errors : Array[String] = []
  let warnings : Array[String] = []
  // 1. File integrity — every entry must match the recorded hash.
  let mismatches = @manifest.verify_manifest(manifest, entries)
  for i = 0; i < mismatches.length(); i = i + 1 {
    errors.push("hash mismatch: " + mismatches[i])
  }
  // 2. Signature — verify against the canonical manifest JSON.
  let manifest_json = @manifest.manifest_to_json(manifest)
  let sig_result = verify_package(
    package_name,
    signature_hex,
    lookup_public_key(trust_store, signer_key_id),
    manifest_json,
  )
  if !sig_result.signature_ok {
    for i = 0; i < sig_result.errors.length(); i = i + 1 {
      errors.push(sig_result.errors[i])
    }
  }
  // 3. Trust — the signer must be in the store at Full or Partial level.
  let trust_status = if trust_store.is_trusted(signer_key_id) {
    "trusted"
  } else if trust_store.get_key(signer_key_id) is Some(_) {
    "untrusted"
  } else {
    "unknown"
  }
  if trust_status == "untrusted" {
    errors.push("signer " + signer_key_id + " is in store with Untrusted level")
  } else if trust_status == "unknown" {
    warnings.push("signer " + signer_key_id + " is not in trust store")
  }
  let is_valid = sig_result.signature_ok &&
    mismatches.length() == 0 &&
    trust_status == "trusted"
  VerifyResult::{
    package_name,
    is_valid,
    signature_ok: sig_result.signature_ok,
    trust_status,
    errors,
    warnings,
  }
}

///|
fn lookup_public_key(store : @trust.TrustStore, key_id : String) -> String {
  match store.get_key(key_id) {
    Some(k) => k.public_key
    None => ""
  }
}

///|
/// Convenience helper for the CLI: hex-encode a `(Signature r, s)` pair
/// without forcing callers to know the inner layout.
pub fn signature_to_hex(sig : @crypto.Signature) -> String {
  @crypto.signature_to_hex(sig)
}

///|
/// Generate a fresh keypair from a 32-byte seed (64 hex chars) and emit
/// both the public and secret halves in hex. Used by `moon_guard keygen`.
pub fn generate_demo_keypair(
  seed : String,
) -> (@crypto.KeyPair, @crypto.KeyPair) {
  let kp = @crypto.generate_keypair(seed)
  (kp, kp)
}
