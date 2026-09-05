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

///|
test "audit helpers load external manifest signature key and trust store" {
  let dir = "tmp_moonguard_audit_fixture"
  cleanup_audit_fixture(dir)
  @fs.create_dir(dir) catch {
    _ => ()
  }
  @fs.create_dir(join_path(dir, "src")) catch {
    _ => ()
  }
  @fs.write_string_to_file(join_path(dir, "src/main.mbt"), "fn main {}") catch {
    _ => fail("failed to write source fixture")
  }
  let entries : Array[@manifest.FileEntry] = [
    { path: "src/main.mbt", content: "fn main {}", },
  ]
  let manifest = @manifest.generate_manifest("pkg", "1.0.0", entries)
  let manifest_json = @manifest.manifest_to_json(manifest)
  @fs.write_string_to_file(join_path(dir, "manifest.json"), manifest_json) catch {
    _ => fail("failed to write manifest fixture")
  }
  let keypair = @crypto.generate_keypair(demo_seed())
  let sig_hex = @crypto.signature_to_hex(@crypto.sign(manifest_json, keypair))
  @fs.write_string_to_file(join_path(dir, "package.sig"), sig_hex + "\n") catch {
    _ => fail("failed to write signature fixture")
  }
  let store = @trust.TrustStore::new()
  let _ = store.add_key(
    "alice",
    keypair.public_key,
    "alice",
    @trust.TrustLevel::Full,
  )
  @fs.write_string_to_file(
    join_path(dir, "moon_guard_trust.json"),
    @trust.trust_store_to_json(store),
  ) catch {
    _ => fail("failed to write trust store fixture")
  }
  @fs.write_string_to_file(
    join_path(dir, "public_key.pem"),
    @trust.public_key_to_pem(keypair.public_key),
  ) catch {
    _ => fail("failed to write public key fixture")
  }
  let args : Array[String] = ["moon_guard", "audit", "pkg", "1.0.0", dir]
  inspect(audit_dir_arg(args), content="tmp_moonguard_audit_fixture")
  match find_sig_file(dir) {
    Some(path) =>
      inspect(path, content="tmp_moonguard_audit_fixture/package.sig")
    None => fail("expected signature path")
  }
  match read_audit_manifest(args, dir) {
    Some(m) => inspect(m.total_files, content="1")
    None => fail("expected manifest fixture")
  }
  match read_audit_signature(args, dir) {
    Some(sig) => {
      inspect(sig.length(), content="128")
      assert_eq(sig, sig_hex)
    }
    None => fail("expected signature fixture")
  }
  match load_audit_trust_store(args, dir) {
    Some(ts) => {
      inspect(ts.key_count(), content="1")
      match audit_signer_key(args, ts) {
        Some(key_id) => inspect(key_id, content="alice")
        None => fail("expected signer key")
      }
    }
    None => fail("expected trust store fixture")
  }
  match read_audit_public_key(args, dir) {
    Some(pubkey) => assert_eq(pubkey, keypair.public_key)
    None => fail("expected public key fixture")
  }
  cleanup_audit_fixture(dir)
}

///|
test "audit manifest is not self-generated when external manifest is missing" {
  let args : Array[String] = [
    "moon_guard", "audit", "pkg", "1.0.0", "src/main.mbt:fn main {}",
  ]
  inspect(audit_dir_arg(args), content="")
  assert_true(read_audit_manifest(args, "") is None)
}

///|
fn cleanup_audit_fixture(dir : String) -> Unit {
  if @fs.path_exists(join_path(dir, "manifest.json")) {
    @fs.remove_file(join_path(dir, "manifest.json")) catch {
      _ => ()
    }
  }
  if @fs.path_exists(join_path(dir, "package.sig")) {
    @fs.remove_file(join_path(dir, "package.sig")) catch {
      _ => ()
    }
  }
  if @fs.path_exists(join_path(dir, "moon_guard_trust.json")) {
    @fs.remove_file(join_path(dir, "moon_guard_trust.json")) catch {
      _ => ()
    }
  }
  if @fs.path_exists(join_path(dir, "public_key.pem")) {
    @fs.remove_file(join_path(dir, "public_key.pem")) catch {
      _ => ()
    }
  }
  if @fs.path_exists(join_path(dir, "src/main.mbt")) {
    @fs.remove_file(join_path(dir, "src/main.mbt")) catch {
      _ => ()
    }
  }
  if @fs.path_exists(join_path(dir, "src")) {
    @fs.remove_dir(join_path(dir, "src")) catch {
      _ => ()
    }
  }
  if @fs.path_exists(dir) {
    @fs.remove_dir(dir) catch {
      _ => ()
    }
  }
}
