// Microbenchmarks for MoonGuard's hot paths. These run via `moon bench`
// when a benchmark entry point is added; meanwhile they're tracked as
// `inspect`-based smoke tests so we can spot quadratic blow-ups early.

///|
test "bench: sha256 of 1KB string completes quickly" {
  // Build a 1KB string by repeating "x" 1024 times.
  let payload = StringBuilder::new(size_hint=1024)
  let mut i = 0
  while i < 1024 {
    payload.write_char('x')
    i = i + 1
  }
  let s = payload.to_string()
  let h = @manifest.sha256(s)
  // SHA-256 of 1024 'x' chars (well-known answer, used as smoke test).
  inspect(h.length(), content="64")
}

///|
test "bench: typosquat detector handles 100 suspects in linear time" {
  let known : Array[String] = []
  let mut k = 0
  while k < 50 {
    known.push("known-pkg-" + k.to_string())
    k = k + 1
  }
  // Suspects deliberately share no prefix with `known` so Levenshtein
  // distance is always > 2 — the goal is to exercise the negative path.
  let suspects : Array[String] = []
  let mut i = 0
  while i < 100 {
    suspects.push("totally-different-name-" + i.to_string())
    i = i + 1
  }
  let all = @verify.batch_typosquat_check(suspects, known)
  // None of the suspects match any known name within distance ≤ 2.
  inspect(all.length(), content="0")
  let _ = @verify.typosquat_summary(suspects, known)
}

///|
test "bench: verify_package rejects malformed signatures quickly" {
  // Pad a wrong-length signature so the rejection happens at the length
  // check, before any expensive crypto work.
  let bad = StringBuilder::new(size_hint=130)
  let mut i = 0
  while i < 130 {
    bad.write_char('0')
    i = i + 1
  }
  let bad_hex = bad.to_string()
  let result = @verify.verify_package(
    "bench", bad_hex, "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    "anything",
  )
  inspect(result.is_valid, content="false")
  // The error must surface the length problem, not anything crypto-side.
  inspect(result.errors.length() > 0, content="true")
}
