///|
let ed_p : BigInt = @bigint.BigInt::from_hex(
  "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed",
)

///|
let ed_d : BigInt = @bigint.BigInt::from_hex(
  "52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3",
)

///|
let ed_L : BigInt = @bigint.BigInt::from_hex(
  "1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed",
)

///|
let ed_Gx : BigInt = @bigint.BigInt::from_hex(
  "216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a",
)

///|
let ed_Gy : BigInt = @bigint.BigInt::from_hex(
  "6666666666666666666666666666666666666666666666666666666666666658",
)

///|
pub(all) struct ExtPoint {
  x : BigInt
  y : BigInt
  z : BigInt
  t : BigInt
}

///|
fn field_add(a : BigInt, b : BigInt) -> BigInt {
  (a + b) % ed_p
}

///|
fn field_sub(a : BigInt, b : BigInt) -> BigInt {
  (a - b + ed_p) % ed_p
}

///|
pub fn field_mul(a : BigInt, b : BigInt) -> BigInt {
  a * b % ed_p
}

///|
pub fn field_inv(a : BigInt) -> BigInt {
  let p_minus_2 = ed_p - @bigint.BigInt::from_int(2)
  a.pow(p_minus_2, modulus=ed_p)
}

///|
fn field_sqrt(a : BigInt) -> BigInt? {
  // p mod 8 = 5, so sqrt(a) = a^((p+3)/8) mod p
  let exp = (ed_p + @bigint.BigInt::from_int(3)) / @bigint.BigInt::from_int(8)
  let candidate = a.pow(exp, modulus=ed_p)
  if field_mul(candidate, candidate) == a % ed_p {
    Some(candidate)
  } else {
    // Try multiplying by sqrt(-1)
    let sqrt_m1 = @bigint.BigInt::from_int(2).pow(
      (ed_p - @bigint.BigInt::from_int(1)) / @bigint.BigInt::from_int(4),
      modulus=ed_p,
    )
    let candidate2 = field_mul(candidate, sqrt_m1)
    if field_mul(candidate2, candidate2) == a % ed_p {
      Some(candidate2)
    } else {
      None
    }
  }
}

///|
fn point_zero() -> ExtPoint {
  ExtPoint::{
    x: @bigint.BigInt::from_int(0),
    y: @bigint.BigInt::from_int(1),
    z: @bigint.BigInt::from_int(1),
    t: @bigint.BigInt::from_int(0),
  }
}

///|
pub fn base_point() -> ExtPoint {
  ExtPoint::{
    x: ed_Gx,
    y: ed_Gy,
    z: @bigint.BigInt::from_int(1),
    t: field_mul(ed_Gx, ed_Gy),
  }
}

///|
fn point_add(p1 : ExtPoint, p2 : ExtPoint) -> ExtPoint {
  let a = field_mul(field_sub(p1.y, p1.x), field_sub(p2.y, p2.x))
  let b = field_mul(field_add(p1.y, p1.x), field_add(p2.y, p2.x))
  let c = field_mul(
    field_mul(p1.t, p2.t),
    field_mul(ed_d, @bigint.BigInt::from_int(2)),
  )
  let d = field_mul(p1.z, field_mul(p2.z, @bigint.BigInt::from_int(2)))
  let e = field_sub(b, a)
  let f = field_sub(d, c)
  let g = field_add(d, c)
  let h = field_add(b, a)
  ExtPoint::{
    x: field_mul(e, f),
    y: field_mul(g, h),
    z: field_mul(f, g),
    t: field_mul(e, h),
  }
}

///|
fn point_double(p : ExtPoint) -> ExtPoint {
  let aa = field_mul(p.x, p.x)
  let bb = field_mul(p.y, p.y)
  let cc = field_mul(field_mul(p.z, p.z), @bigint.BigInt::from_int(2))
  // D = a * A = -A (since a = -1 for Ed25519)
  let dd = field_sub(@bigint.BigInt::from_int(0), aa)
  let e = field_sub(
    field_mul(field_add(p.x, p.y), field_add(p.x, p.y)),
    field_add(aa, bb),
  )
  let g = field_add(dd, bb)
  let f = field_sub(g, cc)
  let h = field_sub(dd, bb)
  ExtPoint::{
    x: field_mul(e, f),
    y: field_mul(g, h),
    z: field_mul(f, g),
    t: field_mul(e, h),
  }
}

///|
pub fn scalar_mult(scalar : BigInt, point : ExtPoint) -> ExtPoint {
  let mut result = point_zero()
  let mut temp = point
  let bits = scalar.bit_length()
  let scalar_bytes = bigint_to_le_bytes(scalar, (bits + 7) / 8)
  for i = 0; i < bits; i = i + 1 {
    let byte_idx = i / 8
    let bit_idx = i % 8
    let bit = (scalar_bytes[byte_idx].to_int() >> bit_idx) & 1
    if bit == 1 {
      result = point_add(result, temp)
    }
    temp = point_double(temp)
  }
  result
}

///|
pub fn bigint_to_le_bytes(n : BigInt, len : Int) -> Array[Byte] {
  let be = n.to_octets(length=len)
  let le : Array[Byte] = Array::make(len, b'\x00')
  for i = 0; i < len; i = i + 1 {
    le[i] = be[len - 1 - i]
  }
  le
}

///|
pub fn le_bytes_to_bigint(bytes : Array[Byte]) -> BigInt {
  let len = bytes.length()
  let be : Array[Byte] = Array::make(len, b'\x00')
  for i = 0; i < len; i = i + 1 {
    be[i] = bytes[len - 1 - i]
  }
  @bigint.BigInt::from_octets(Bytes::from_array(be))
}

///|
pub fn point_encode(p : ExtPoint) -> Array[Byte] {
  let zinv = field_inv(p.z)
  let x = field_mul(p.x, zinv)
  let y = field_mul(p.y, zinv)
  let encoded = bigint_to_le_bytes(y, 32)
  let x_bytes = bigint_to_le_bytes(x, 32)
  if (x_bytes[0].to_int() & 1) == 1 {
    encoded[31] = (encoded[31].to_int() | 0x80).to_byte()
  }
  encoded
}

///|
fn point_decode(bytes : Array[Byte]) -> ExtPoint? {
  if bytes.length() != 32 {
    return None
  }
  let x_sign = (bytes[31].to_int() >> 7) & 1
  let y_bytes : Array[Byte] = Array::make(32, b'\x00')
  for i = 0; i < 32; i = i + 1 {
    y_bytes[i] = bytes[i]
  }
  y_bytes[31] = (y_bytes[31].to_int() & 0x7F).to_byte()
  let y = le_bytes_to_bigint(y_bytes)
  if y >= ed_p {
    return None
  }
  let y2 = field_mul(y, y)
  let u = field_sub(y2, @bigint.BigInt::from_int(1))
  let v = field_add(field_mul(ed_d, y2), @bigint.BigInt::from_int(1))
  let v_inv = field_inv(v)
  let x2 = field_mul(u, v_inv)
  if x2 == @bigint.BigInt::from_int(0) {
    if x_sign != 0 {
      return None
    }
    return Some(ExtPoint::{
      x: @bigint.BigInt::from_int(0),
      y,
      z: @bigint.BigInt::from_int(1),
      t: @bigint.BigInt::from_int(0),
    })
  }
  match field_sqrt(x2) {
    None => None
    Some(x) => {
      let x_le = bigint_to_le_bytes(x, 32)
      let x_parity = x_le[0].to_int() & 1
      let x_final = if x_parity == x_sign {
        x
      } else {
        field_sub(@bigint.BigInt::from_int(0), x)
      }
      Some(ExtPoint::{
        x: x_final,
        y,
        z: @bigint.BigInt::from_int(1),
        t: field_mul(x_final, y),
      })
    }
  }
}
