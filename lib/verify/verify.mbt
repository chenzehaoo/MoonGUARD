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
  let sig_r = signature_hex.substring(start=0, end=64)
  let sig_s = signature_hex.substring(start=64, end=128)
  let sig = @crypto.Signature::{ r: sig_r, s: sig_s }
  let valid = @crypto.verify(content, sig, public_key_hex)
  if not(valid) {
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
