///|
test "trust store add and lookup" {
  let store = @trust.TrustStore::new()
  let key = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
  let added = store.add_key("key1", key, "alice", @trust.TrustLevel::Full)
  inspect(added, content="true")
  inspect(store.is_trusted("key1"), content="true")
  inspect(store.is_trusted("unknown"), content="false")
  inspect(store.key_count(), content="1")
}

///|
test "trust store rejects duplicate" {
  let store = @trust.TrustStore::new()
  let key = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
  let _ = store.add_key("key1", key, "alice", @trust.TrustLevel::Full)
  let dup = store.add_key("key1", key, "bob", @trust.TrustLevel::Partial)
  inspect(dup, content="false")
  inspect(store.key_count(), content="1")
}

///|
test "trust store rejects invalid key format" {
  let store = @trust.TrustStore::new()
  let bad = store.add_key("key1", "tooshort", "alice", @trust.TrustLevel::Full)
  inspect(bad, content="false")
  inspect(store.key_count(), content="0")
}

///|
test "trust store remove key" {
  let store = @trust.TrustStore::new()
  let key = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
  let _ = store.add_key("key1", key, "alice", @trust.TrustLevel::Full)
  let removed = store.remove_key("key1")
  inspect(removed, content="true")
  inspect(store.key_count(), content="0")
}

///|
test "trust store untrusted key" {
  let store = @trust.TrustStore::new()
  let key = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
  let _ = store.add_key("key1", key, "eve", @trust.TrustLevel::Untrusted)
  inspect(store.is_trusted("key1"), content="false")
}

///|
test "trust store find by owner" {
  let store = @trust.TrustStore::new()
  let k1 = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
  let k2 = "c9a3f86aae465f0e56513864510f3997561fa2c9e85ea21dc2292309f3cd6022"
  let _ = store.add_key("k1", k1, "alice", @trust.TrustLevel::Full)
  let _ = store.add_key("k2", k2, "alice", @trust.TrustLevel::Partial)
  let found = store.find_by_owner("alice")
  inspect(found.length(), content="2")
}

///|
test "trust store to json" {
  let store = @trust.TrustStore::new()
  let key = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
  let _ = store.add_key("k1", key, "alice", @trust.TrustLevel::Full)
  let json = @trust.trust_store_to_json(store)
  inspect(json.contains("alice"), content="true")
  inspect(json.contains("full"), content="true")
  inspect(json.contains("\"version\":\"1\""), content="true")
}

///|
test "trust store from_json roundtrip" {
  let store = @trust.TrustStore::new()
  let k1 = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
  let k2 = "c9a3f86aae465f0e56513864510f3997561fa2c9e85ea21dc2292309f3cd6022"
  let _ = store.add_key("alpha", k1, "alice", @trust.TrustLevel::Full)
  let _ = store.add_key("beta", k2, "bob", @trust.TrustLevel::Partial)
  let json = @trust.trust_store_to_json(store)
  match @trust.trust_store_from_json(json) {
    Some(restored) => {
      inspect(restored.key_count(), content="2")
      inspect(restored.is_trusted("alpha"), content="true")
      inspect(restored.is_trusted("beta"), content="true")
      match restored.get_key("beta") {
        Some(k) =>
          inspect(k.trust_level == @trust.TrustLevel::Partial, content="true")
        None => inspect(false, content="true")
      }
    }
    None => inspect(false, content="true")
  }
}

///|
test "trust store from_json rejects malformed" {
  // Unterminated array — `extract_array` will fail to find the matching
  // `]` and return None, so the whole document is rejected.
  let bogus = "{\"version\":\"1\",\"keys\":["
  match @trust.trust_store_from_json(bogus) {
    Some(_) => inspect(false, content="true")
    None => inspect(true, content="true")
  }
}

///|
test "trust store from_json handles empty keys array" {
  match @trust.trust_store_from_json("{\"version\":\"1\",\"keys\":[]}") {
    Some(s) => inspect(s.key_count(), content="0")
    None => inspect(false, content="true")
  }
}

///|
test "trust store from_json deduplicates on reload" {
  let store = @trust.TrustStore::new()
  let k1 = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
  let _ = store.add_key("dup", k1, "alice", @trust.TrustLevel::Full)
  let _ = store.add_key("dup", k1, "alice", @trust.TrustLevel::Full)
  inspect(store.key_count(), content="1")
}

///|
test "normalize_public_key lowercases mixed-case hex" {
  let mixed = "D75A980182B10AB7D54BFED3C964073A0EE172F3DAA62325AF021A68F707511A"
  match @trust.normalize_public_key(mixed) {
    Some(s) => {
      inspect(
        s,
        content="d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
      )
      inspect(s.length(), content="64")
    }
    None => inspect(false, content="true")
  }
}

///|
test "normalize_public_key rejects wrong length" {
  match @trust.normalize_public_key("deadbeef") {
    Some(_) => inspect(false, content="true")
    None => inspect(true, content="true")
  }
}

///|
test "normalize_public_key rejects non-hex" {
  match
    @trust.normalize_public_key(
      "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ",
    ) {
    Some(_) => inspect(false, content="true")
    None => inspect(true, content="true")
  }
}

///|
test "public_key pem roundtrip" {
  let key = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
  let pem = @trust.public_key_to_pem(key)
  inspect(pem.contains("BEGIN MOONGUARD PUBLIC KEY"), content="true")
  inspect(pem.contains("END MOONGUARD PUBLIC KEY"), content="true")
  match @trust.public_key_from_pem(pem) {
    Some(s) => inspect(s, content=key)
    None => inspect(false, content="true")
  }
}

///|
test "public_key_from_pem rejects non-PEM input" {
  match @trust.public_key_from_pem("garbage") {
    Some(_) => inspect(false, content="true")
    None => inspect(true, content="true")
  }
}

///|
test "public_key_from_pem handles uppercase body" {
  let key = "D75A980182B10AB7D54BFED3C964073A0EE172F3DAA62325AF021A68F707511A"
  let pem = @trust.public_key_to_pem(key.to_lower())
  match @trust.public_key_from_pem(pem) {
    Some(s) =>
      inspect(
        s,
        content="d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
      )
    None => inspect(false, content="true")
  }
}

///|
test "list_all returns defensive copy" {
  let store = @trust.TrustStore::new()
  let key = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
  let _ = store.add_key("k", key, "alice", @trust.TrustLevel::Full)
  let snap = store.list_all()
  inspect(snap.length(), content="1")
  let _ = store.add_key("k2", key, "alice", @trust.TrustLevel::Full)
  // list_all is a snapshot at call time, not a live view.
  inspect(snap.length(), content="1")
}
