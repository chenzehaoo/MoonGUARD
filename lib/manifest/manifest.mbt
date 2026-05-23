///|
/// MoonGuard Manifest Module
/// Package manifest generation and hash calculation
pub struct FileHash {
  path : String
  hash : String
  size : Int
}

///|
pub struct Manifest {
  version : String
  package_name : String
  package_version : String
  total_files : Int
  total_size : Int
  created_at : String
}

///|
/// Create a new manifest
pub fn Manifest::new(
  package_name : String,
  package_version : String,
) -> Manifest {
  Manifest::{
    version: "1.0.0",
    package_name,
    package_version,
    total_files: 0,
    total_size: 0,
    created_at: "2025-01-01",
  }
}

///|
/// SHA-256 initial hash values (first 32 bits of fractional parts of square roots of first 8 primes)
let sha256_h0 : Array[UInt] = [
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
  0x5be0cd19,
]

///|
/// SHA-256 round constants (first 32 bits of fractional parts of cube roots of first 64 primes)
let sha256_k : Array[UInt] = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
  0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
  0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
  0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
  0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
  0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
  0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
  0xc67178f2,
]

///|
/// Right-rotate a 32-bit unsigned integer
fn rotr(x : UInt, n : Int) -> UInt {
  (x >> n) | (x << (32 - n))
}

///|
/// SHA-256 Σ0 function
fn sigma0(x : UInt) -> UInt {
  rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)
}

///|
/// SHA-256 Σ1 function
fn sigma1(x : UInt) -> UInt {
  rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)
}

///|
/// SHA-256 σ0 function (message schedule)
fn small_sigma0(x : UInt) -> UInt {
  rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3)
}

///|
/// SHA-256 σ1 function (message schedule)
fn small_sigma1(x : UInt) -> UInt {
  rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10)
}

///|
/// SHA-256 Ch function
fn ch(x : UInt, y : UInt, z : UInt) -> UInt {
  (x & y) ^ (x.lnot() & z)
}

///|
/// SHA-256 Maj function
fn maj(x : UInt, y : UInt, z : UInt) -> UInt {
  (x & y) ^ (x & z) ^ (y & z)
}

///|
/// Convert a string to bytes (UTF-8 encoding)
fn string_to_bytes(s : String) -> Array[Byte] {
  let bytes : Array[Byte] = []
  for i = 0; i < s.length(); i = i + 1 {
    let c = s[i]
    if c < 0x80 {
      bytes.push(c.to_byte())
    } else if c < 0x800 {
      bytes.push((0xC0 | (c >> 6)).to_byte())
      bytes.push((0x80 | (c & 0x3F)).to_byte())
    } else if c < 0x10000 {
      bytes.push((0xE0 | (c >> 12)).to_byte())
      bytes.push((0x80 | ((c >> 6) & 0x3F)).to_byte())
      bytes.push((0x80 | (c & 0x3F)).to_byte())
    } else {
      bytes.push((0xF0 | (c >> 18)).to_byte())
      bytes.push((0x80 | ((c >> 12) & 0x3F)).to_byte())
      bytes.push((0x80 | ((c >> 6) & 0x3F)).to_byte())
      bytes.push((0x80 | (c & 0x3F)).to_byte())
    }
  }
  bytes
}

///|
/// Pad message according to SHA-256 spec
fn sha256_pad(msg : Array[Byte]) -> Array[Byte] {
  let orig_len = msg.length()
  let bit_len = orig_len * 8
  let padded : Array[Byte] = Array::new(capacity=orig_len + 72)
  for i = 0; i < orig_len; i = i + 1 {
    padded.push(msg[i])
  }
  padded.push(b'\x80')
  while padded.length() % 64 != 56 {
    padded.push(b'\x00')
  }
  // 64-bit big-endian length: upper 4 bytes are 0 for messages < 512MB
  padded.push(b'\x00')
  padded.push(b'\x00')
  padded.push(b'\x00')
  padded.push(b'\x00')
  padded.push(((bit_len >> 24) & 0xFF).to_byte())
  padded.push(((bit_len >> 16) & 0xFF).to_byte())
  padded.push(((bit_len >> 8) & 0xFF).to_byte())
  padded.push((bit_len & 0xFF).to_byte())
  padded
}

///|
/// Process a single 512-bit block
fn sha256_process_block(
  block : Array[Byte],
  offset : Int,
  h : Array[UInt],
) -> Unit {
  let w : Array[UInt] = Array::make(64, 0U)
  for i = 0; i < 16; i = i + 1 {
    let base = offset + i * 4
    w[i] = (block[base].to_int().reinterpret_as_uint() << 24) |
      (block[base + 1].to_int().reinterpret_as_uint() << 16) |
      (block[base + 2].to_int().reinterpret_as_uint() << 8) |
      block[base + 3].to_int().reinterpret_as_uint()
  }
  for i = 16; i < 64; i = i + 1 {
    w[i] = small_sigma1(w[i - 2]) +
      w[i - 7] +
      small_sigma0(w[i - 15]) +
      w[i - 16]
  }
  let mut a = h[0]
  let mut b = h[1]
  let mut c = h[2]
  let mut d = h[3]
  let mut e = h[4]
  let mut f = h[5]
  let mut g = h[6]
  let mut hh = h[7]
  for i = 0; i < 64; i = i + 1 {
    let t1 = hh + sigma1(e) + ch(e, f, g) + sha256_k[i] + w[i]
    let t2 = sigma0(a) + maj(a, b, c)
    hh = g
    g = f
    f = e
    e = d + t1
    d = c
    c = b
    b = a
    a = t1 + t2
  }
  h[0] = h[0] + a
  h[1] = h[1] + b
  h[2] = h[2] + c
  h[3] = h[3] + d
  h[4] = h[4] + e
  h[5] = h[5] + f
  h[6] = h[6] + g
  h[7] = h[7] + hh
}

///|
/// Convert a UInt to 8-character hex string
fn uint_to_hex(value : UInt) -> String {
  let mut result = ""
  for i = 7; i >= 0; i = i - 1 {
    let nibble = ((value >> (i * 4)) & 0xFU).reinterpret_as_int()
    let c = if nibble < 10 {
      (nibble + 48).unsafe_to_char()
    } else {
      (nibble - 10 + 97).unsafe_to_char()
    }
    result = result + c.to_string()
  }
  result
}

///|
/// Calculate SHA-256 hash of a string
pub fn sha256(data : String) -> String {
  let bytes = string_to_bytes(data)
  let padded = sha256_pad(bytes)
  let h : Array[UInt] = Array::make(8, 0U)
  for i = 0; i < 8; i = i + 1 {
    h[i] = sha256_h0[i]
  }
  let num_blocks = padded.length() / 64
  for i = 0; i < num_blocks; i = i + 1 {
    sha256_process_block(padded, i * 64, h)
  }
  let mut result = ""
  for i = 0; i < 8; i = i + 1 {
    result = result + uint_to_hex(h[i])
  }
  result
}

///|
/// Hash string content
pub fn hash_string(content : String) -> String {
  sha256(content)
}

///|
/// Get manifest summary
pub fn manifest_summary(manifest : Manifest) -> String {
  "Package: " +
  manifest.package_name +
  " v" +
  manifest.package_version +
  ", Files: 0"
}
