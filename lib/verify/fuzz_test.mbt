// Property-based fuzz tests for MoonGuard. Each test runs a small battery
// of random / structured inputs through a public API and checks that
// invariants hold (no panic, valid output shape, etc.). These are kept
// inside a separate file so the deterministic test suite stays clean.

///|
test "fuzz: typo detector never crashes on random names" {
  let known = ["lodash", "express", "react", "angular", "vue"]
  // 50 inputs: empty / single-char / all-ASCII / mixed punctuation.
  let cases : Array[String] = [
    "", "a", "ab", "abc", "ABC", "123", "lodash", "lodash-fork", "  spaced  ", "with\nnewline",
    "react", "reactt", "expres", "ex-press", "angulr", "vue", "not-a-real-pkg", "1111111111111111",
    "________", "react.cloneElement", "1react", "reacct", "lodassh", "expresss",
    "exress", "x", "xx", "xxx", "xxxx", "xxxxx", "xxxxxx", "xxxxxxx", "        ",
    "abc-def", "abc_def", "abc.def", "abc--def", "caffeinate", "ngular", "vue.js",
    "vuex", "mongodb", "monogodb", "mongo-db", "mongo_db", "react-apollo", "reactrouter",
    "redux", "react-redux", "react-relay", "package.json",
  ]
  let mut i = 0
  while i < cases.length() {
    let _ = @verify.detect_typosquat(cases[i], known)
    let _ = @verify.detect_typosquat_strict(cases[i], known)
    let _ = @verify.batch_typosquat_check([cases[i]], known)
    let _ = @verify.typosquat_summary([cases[i]], known)
    i = i + 1
  }
}

///|
test "fuzz: trust store add + from_json roundtrip preserves count" {
  let store = @trust.TrustStore::new()
  // 5 random hex keys of length 64 (deterministic — these come from a fixed
  // SHA-style hash rather than Math.random so the test is reproducible).
  let seeds = [
    "1111111111111111111111111111111111111111111111111111111111111111", "2222222222222222222222222222222222222222222222222222222222222222",
    "3333333333333333333333333333333333333333333333333333333333333333", "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
    "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
  ]
  for i = 0; i < seeds.length(); i = i + 1 {
    let _ = store.add_key(
      "k" + i.to_string(),
      seeds[i],
      "owner-" + i.to_string(),
      if i % 2 == 0 {
        @trust.TrustLevel::Full
      } else {
        @trust.TrustLevel::Partial
      },
    )
  }
  inspect(store.key_count(), content="5")
  let json = @trust.trust_store_to_json(store)
  match @trust.trust_store_from_json(json) {
    Some(restored) => {
      inspect(restored.key_count(), content="5")
      let all_ids = restored.list_all()
      let mut i = 0
      let mut seen_k0 = false
      let mut seen_k4 = false
      while i < all_ids.length() {
        if all_ids[i].key_id == "k0" {
          seen_k0 = true
        }
        if all_ids[i].key_id == "k4" {
          seen_k4 = true
        }
        i = i + 1
      }
      inspect(seen_k0, content="true")
      inspect(seen_k4, content="true")
    }
    None => inspect(false, content="true")
  }
}

///|
test "fuzz: PEM encode/decode roundtrip across 20 random hex strings" {
  let hex_chars = "0123456789abcdef"
  // Generate 20 deterministic 64-char strings.
  let mut i = 0
  while i < 20 {
    let buf = StringBuilder()
    let mut k = 0
    while k < 64 {
      let idx = (i * 7 + k * 13) % 16
      buf.write_char(hex_chars[idx].unsafe_to_char())
      k = k + 1
    }
    let key = buf.to_string()
    let pem = @trust.public_key_to_pem(key)
    match @trust.public_key_from_pem(pem) {
      Some(decoded) => inspect(decoded == key, content="true")
      None => inspect(false, content="true")
    }
    i = i + 1
  }
}

///|
test "fuzz: normalize_public_key roundtrips mixed-case hex" {
  let hex_chars = "0123456789abcdef"
  let mut i = 0
  while i < 20 {
    let lower = StringBuilder()
    let upper = StringBuilder()
    let mut k = 0
    while k < 64 {
      let idx = (i * 11 + k * 5) % 16
      let lc = hex_chars[idx]
      lower.write_char(lc.unsafe_to_char())
      // Upper-case hex character for the same digit.
      if idx < 10 {
        upper.write_char((48 + idx).unsafe_to_char())
      } else {
        upper.write_char((55 + idx).unsafe_to_char())
      }
      k = k + 1
    }
    let lower_str = lower.to_string()
    let upper_str = upper.to_string()
    match @trust.normalize_public_key(upper_str) {
      Some(s) => inspect(s == lower_str, content="true")
      None => inspect(false, content="true")
    }
    i = i + 1
  }
}

///|
test "fuzz: audit pipeline tolerates empty manifest inputs" {
  let empty_manifest = @manifest.generate_manifest("empty", "0.0.1", [])
  let store = @trust.TrustStore::new()
  let result = @verify.audit_package(
    "empty",
    "0.0.1",
    empty_manifest,
    [],
    "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "missing-signer",
    store,
  )
  // Empty package still has to be auditable; it just can't be valid.
  inspect(result.is_valid, content="false")
  inspect(result.trust_status, content="unknown")
}
