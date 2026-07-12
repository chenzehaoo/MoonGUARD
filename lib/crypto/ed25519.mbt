///|
pub(all) struct KeyPair {
  public_key : String
  secret_key : String
}

///|
pub(all) struct Signature {
  r : String
  s : String
}

///|
pub fn hex_to_bytes(hex : String) -> Array[Byte] {
  let len = hex.length() / 2
  let bytes : Array[Byte] = Array::make(len, b'\x00')
  for i = 0; i < len; i = i + 1 {
    let hi = hex_char_val(hex[i * 2].to_int())
    let lo = hex_char_val(hex[i * 2 + 1].to_int())
    bytes[i] = ((hi << 4) | lo).to_byte()
  }
  bytes
}

///|
fn hex_char_val(c : Int) -> Int {
  if c >= 48 && c <= 57 {
    c - 48
  } else if c >= 97 && c <= 102 {
    c - 87
  } else if c >= 65 && c <= 70 {
    c - 55
  } else {
    0
  }
}

///|
fn bytes_to_hex_str(bytes : Array[Byte]) -> String {
  let mut result = ""
  for i = 0; i < bytes.length(); i = i + 1 {
    let b = bytes[i].to_int()
    let hi = (b >> 4) & 0x0F
    let lo = b & 0x0F
    let ch = if hi < 10 {
      (hi + 48).unsafe_to_char()
    } else {
      (hi - 10 + 97).unsafe_to_char()
    }
    let cl = if lo < 10 {
      (lo + 48).unsafe_to_char()
    } else {
      (lo - 10 + 97).unsafe_to_char()
    }
    result = result + ch.to_string() + cl.to_string()
  }
  result
}

///|
fn bytes_concat(a : Array[Byte], b : Array[Byte]) -> Array[Byte] {
  let result : Array[Byte] = Array::new(capacity=a.length() + b.length())
  for i = 0; i < a.length(); i = i + 1 {
    result.push(a[i])
  }
  for i = 0; i < b.length(); i = i + 1 {
    result.push(b[i])
  }
  result
}

///|
fn clamp_scalar(h : Array[Byte]) -> Array[Byte] {
  let clamped : Array[Byte] = Array::make(32, b'\x00')
  for i = 0; i < 32; i = i + 1 {
    clamped[i] = h[i]
  }
  clamped[0] = (clamped[0].to_int() & 248).to_byte()
  clamped[31] = (clamped[31].to_int() & 127).to_byte()
  clamped[31] = (clamped[31].to_int() | 64).to_byte()
  clamped
}

///|
pub fn generate_keypair(seed : String) -> KeyPair {
  let seed_bytes = hex_to_bytes(seed)
  let h = sha512(seed_bytes)
  let scalar_bytes = clamp_scalar(h)
  let scalar = le_bytes_to_bigint(scalar_bytes)
  let pub_point = scalar_mult(scalar, base_point())
  let pub_bytes = point_encode(pub_point)
  KeyPair::{ public_key: bytes_to_hex_str(pub_bytes), secret_key: seed }
}

///|
pub fn sign(message : String, keypair : KeyPair) -> Signature {
  let seed_bytes = hex_to_bytes(keypair.secret_key)
  let msg_bytes = string_to_utf8(message)
  let h = sha512(seed_bytes)
  let scalar_bytes = clamp_scalar(h)
  let scalar = le_bytes_to_bigint(scalar_bytes)
  // prefix = h[32..64]
  let prefix : Array[Byte] = Array::make(32, b'\x00')
  for i = 0; i < 32; i = i + 1 {
    prefix[i] = h[i + 32]
  }
  // r = SHA-512(prefix || message) mod L
  let r_hash = sha512(bytes_concat(prefix, msg_bytes))
  let r = le_bytes_to_bigint(r_hash) % ed_L
  let r_point = scalar_mult(r, base_point())
  let r_bytes = point_encode(r_point)
  let a_bytes = hex_to_bytes(keypair.public_key)
  // k = SHA-512(R || A || message) mod L
  let k_input = bytes_concat(bytes_concat(r_bytes, a_bytes), msg_bytes)
  let k_hash = sha512(k_input)
  let k = le_bytes_to_bigint(k_hash) % ed_L
  // S = (r + k * scalar) mod L
  let s_val = (r + k * scalar) % ed_L
  let s_bytes = bigint_to_le_bytes(s_val, 32)
  Signature::{ r: bytes_to_hex_str(r_bytes), s: bytes_to_hex_str(s_bytes) }
}

///|
pub fn verify(
  message : String,
  signature : Signature,
  public_key : String,
) -> Bool {
  let msg_bytes = string_to_utf8(message)
  let r_bytes = hex_to_bytes(signature.r)
  let a_bytes = hex_to_bytes(public_key)
  let s_bytes = hex_to_bytes(signature.s)
  let s_val = le_bytes_to_bigint(s_bytes)
  if s_val >= ed_L {
    return false
  }
  let r_point = match point_decode(r_bytes) {
    None => return false
    Some(p) => p
  }
  let a_point = match point_decode(a_bytes) {
    None => return false
    Some(p) => p
  }
  // k = SHA-512(R || A || message) mod L
  let k_input = bytes_concat(bytes_concat(r_bytes, a_bytes), msg_bytes)
  let k_hash = sha512(k_input)
  let k = le_bytes_to_bigint(k_hash) % ed_L
  // Check: [S]B == R + [k]A
  let lhs = scalar_mult(s_val, base_point())
  let rhs = point_add(r_point, scalar_mult(k, a_point))
  let lhs_enc = point_encode(lhs)
  let rhs_enc = point_encode(rhs)
  bytes_equal(lhs_enc, rhs_enc)
}

///|
fn bytes_equal(a : Array[Byte], b : Array[Byte]) -> Bool {
  if a.length() != b.length() {
    return false
  }
  for i = 0; i < a.length(); i = i + 1 {
    if a[i] != b[i] {
      return false
    }
  }
  true
}

///|
pub fn signature_to_hex(sig : Signature) -> String {
  sig.r + sig.s
}
