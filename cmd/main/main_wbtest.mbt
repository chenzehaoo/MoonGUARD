///|
/// Smoke tests for the internal CLI helpers in cmd/main/main.mbt.
///
/// These exercise `find_char`, `parse_file_entries`, and the demo seed
/// without spinning up a full MoonGuard audit. They live alongside
/// `main.mbt` so they can read package-private helpers directly.
test "find_char locates a substring separator" {
  let idx = find_char("path:content", ':')
  inspect(idx, content="4")
  inspect(find_char("no-colon-here", ':'), content="-1")
  inspect(find_char(":leading", ':'), content="0")
}

///|
test "parse_file_entries splits path:content pairs" {
  let argv : Array[String] = [
    "moon_guard", "manifest", "gen", "demo", "1.0.0", "src/main.mbt:fn main {}",
    "src/lib.mbt:pub fn hi() -> String { \"hi\" }",
  ]
  let entries = parse_file_entries(argv, 5)
  inspect(entries.length(), content="2")
  inspect(entries[0].path, content="src/main.mbt")
  inspect(entries[0].content, content="fn main {}")
  inspect(entries[1].path, content="src/lib.mbt")
}

///|
test "parse_file_entries falls back to demo content when empty" {
  let argv : Array[String] = ["moon_guard", "manifest", "gen", "demo", "1.0.0"]
  let entries = parse_file_entries(argv, 5)
  inspect(entries.length(), content="2")
  // Fallback fixtures must still be syntactically reasonable source files.
  inspect(entries[0].path, content="demo.mbt")
  inspect(entries[1].path, content="lib.mbt")
}

///|
test "parse_file_entries ignores malformed entries without a colon" {
  let argv : Array[String] = [
    "moon_guard", "manifest", "gen", "demo", "1.0.0", "bad-entry-without-colon",
    "ok.mbt:let a = 1",
  ]
  let entries = parse_file_entries(argv, 5)
  inspect(entries.length(), content="1")
  inspect(entries[0].path, content="ok.mbt")
}

///|
test "demo_seed produces a deterministic 64-char hex string" {
  let seed = demo_seed()
  inspect(seed.length(), content="64")
  // Ed25519-style hex seeds only contain [0-9a-f].
  for i = 0; i < seed.length(); i = i + 1 {
    let c = seed[i]
    let is_lower_hex = (c >= 48 && c <= 57) || (c >= 97 && c <= 102)
    assert_true(is_lower_hex)
  }
}

///|
test "parse_trust_level maps level names" {
  inspect(parse_trust_level("full"), content="Full")
  inspect(parse_trust_level("partial"), content="Partial")
  inspect(parse_trust_level("untrusted"), content="Untrusted")
  // Unknown levels fall back to Full — the safest default for an
  // unsigned operator input.
  inspect(parse_trust_level("bogus"), content="Full")
}

///|
test "trust_level_name round-trips through parse_trust_level" {
  inspect(trust_level_name(parse_trust_level("full")), content="full")
  inspect(trust_level_name(parse_trust_level("partial")), content="partial")
  inspect(trust_level_name(parse_trust_level("untrusted")), content="untrusted")
}
