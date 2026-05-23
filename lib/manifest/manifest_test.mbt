///|
/// MoonGuard Manifest Tests - SHA-256 verified against NIST test vectors
test "sha256 NIST vector: abc" {
  let h = @manifest.sha256("abc")
  inspect(
    h,
    content="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
  )
}

///|
test "sha256 NIST vector: empty string" {
  let h = @manifest.sha256("")
  inspect(
    h,
    content="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  )
}

///|
test "sha256 NIST vector: 448 bits" {
  let h = @manifest.sha256(
    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
  )
  inspect(
    h,
    content="248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
  )
}

///|
test "sha256 deterministic" {
  let h1 = @manifest.sha256("hello world")
  let h2 = @manifest.sha256("hello world")
  inspect(h1 == h2, content="true")
}

///|
test "sha256 different input different output" {
  let h1 = @manifest.sha256("abc")
  let h2 = @manifest.sha256("xyz")
  inspect(h1 != h2, content="true")
}

///|
test "sha256 returns 64 hex chars" {
  let h = @manifest.sha256("test")
  inspect(h.length(), content="64")
}
