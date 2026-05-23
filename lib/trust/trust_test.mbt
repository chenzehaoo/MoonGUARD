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
}
