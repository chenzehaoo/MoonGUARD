///|
test "sha512 FIPS vector: abc" {
  let data = @crypto.string_to_utf8("abc")
  let hash = @crypto.sha512(data)
  let hex = bytes_to_hex(hash)
  inspect(
    hex,
    content="ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
  )
}

///|
test "sha512 FIPS vector: empty" {
  let hash = @crypto.sha512([])
  let hex = bytes_to_hex(hash)
  inspect(
    hex,
    content="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
  )
}

///|
test "byte encoding roundtrip" {
  let seed = "0300000000000000000000000000000000000000000000000000000000000000"
  let seed_bytes = @crypto.hex_to_bytes(seed)
  let n = @crypto.le_bytes_to_bigint(seed_bytes)
  let result = @crypto.bigint_to_le_bytes(n, 32)
  let hex = bytes_to_hex(result)
  inspect(hex, content=seed)
}

///|
test "base point encode" {
  let g = @crypto.base_point()
  let g_enc = @crypto.point_encode(g)
  let g_hex = bytes_to_hex(g_enc)
  inspect(
    g_hex,
    content="5866666666666666666666666666666666666666666666666666666666666666",
  )
}

///|
test "scalar mult 2G" {
  let g = @crypto.base_point()
  let two = @bigint.BigInt::from_int(2)
  let result = @crypto.scalar_mult(two, g)
  let enc = @crypto.point_encode(result)
  let hex = bytes_to_hex(enc)
  inspect(
    hex,
    content="c9a3f86aae465f0e56513864510f3997561fa2c9e85ea21dc2292309f3cd6022",
  )
}

///|
test "scalar mult 128bit" {
  let g = @crypto.base_point()
  let s = @bigint.BigInt::from_hex("deadbeefcafebabe1234567890abcdef")
  let result = @crypto.scalar_mult(s, g)
  let enc = @crypto.point_encode(result)
  let hex = bytes_to_hex(enc)
  inspect(
    hex,
    content="554f498bdd1e7a1434d95810b96a35779ddc5c6f9a01fd456fd74f35657e61ba",
  )
}

///|
test "ed25519 pubkey RFC 8032 test vector 1" {
  let seed = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
  let kp = @crypto.generate_keypair(seed)
  inspect(
    kp.public_key,
    content="d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
  )
}

///|
test "ed25519 sign and verify roundtrip" {
  let seed = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
  let kp = @crypto.generate_keypair(seed)
  let sig = @crypto.sign("hello", kp)
  let valid = @crypto.verify("hello", sig, kp.public_key)
  inspect(valid, content="true")
}

///|
test "ed25519 verify rejects tampered message" {
  let seed = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
  let kp = @crypto.generate_keypair(seed)
  let sig = @crypto.sign("hello", kp)
  let invalid = @crypto.verify("world", sig, kp.public_key)
  inspect(invalid, content="false")
}

///|
fn bytes_to_hex(bytes : Array[Byte]) -> String {
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
