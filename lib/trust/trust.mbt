///|
pub(all) enum TrustLevel {
  Full
  Partial
  Untrusted
} derive(Eq, Show)

///|
pub(all) struct TrustedKey {
  key_id : String
  public_key : String
  owner : String
  trust_level : TrustLevel
  added_at : String
}

///|
pub(all) struct TrustStore {
  mut keys : Array[TrustedKey]
}

///|
pub fn TrustStore::new() -> TrustStore {
  TrustStore::{ keys: [] }
}

///|
pub fn TrustStore::add_key(
  self : TrustStore,
  key_id : String,
  public_key : String,
  owner : String,
  trust_level : TrustLevel,
) -> Bool {
  if not(validate_public_key_format(public_key)) {
    return false
  }
  for i = 0; i < self.keys.length(); i = i + 1 {
    if self.keys[i].key_id == key_id {
      return false
    }
  }
  self.keys.push(TrustedKey::{
    key_id,
    public_key,
    owner,
    trust_level,
    added_at: "2026-01-01",
  })
  true
}

///|
pub fn TrustStore::remove_key(self : TrustStore, key_id : String) -> Bool {
  let new_keys : Array[TrustedKey] = []
  let mut found = false
  for i = 0; i < self.keys.length(); i = i + 1 {
    if self.keys[i].key_id == key_id {
      found = true
    } else {
      new_keys.push(self.keys[i])
    }
  }
  if found {
    self.keys = new_keys
  }
  found
}

///|
pub fn TrustStore::get_key(self : TrustStore, key_id : String) -> TrustedKey? {
  for i = 0; i < self.keys.length(); i = i + 1 {
    if self.keys[i].key_id == key_id {
      return Some(self.keys[i])
    }
  }
  None
}

///|
pub fn TrustStore::is_trusted(self : TrustStore, key_id : String) -> Bool {
  match self.get_key(key_id) {
    Some(k) => k.trust_level != TrustLevel::Untrusted
    None => false
  }
}

///|
pub fn TrustStore::find_by_owner(
  self : TrustStore,
  owner : String,
) -> Array[TrustedKey] {
  let result : Array[TrustedKey] = []
  for i = 0; i < self.keys.length(); i = i + 1 {
    if self.keys[i].owner == owner {
      result.push(self.keys[i])
    }
  }
  result
}

///|
pub fn TrustStore::key_count(self : TrustStore) -> Int {
  self.keys.length()
}

///|
pub fn validate_public_key_format(public_key : String) -> Bool {
  if public_key.length() != 64 {
    return false
  }
  for i = 0; i < public_key.length(); i = i + 1 {
    let c = public_key[i]
    let valid = (c >= 48 && c <= 57) ||
      (c >= 97 && c <= 102) ||
      (c >= 65 && c <= 70)
    if not(valid) {
      return false
    }
  }
  true
}

///|
pub fn trust_store_to_json(store : TrustStore) -> String {
  let mut result = "{\"keys\":["
  for i = 0; i < store.keys.length(); i = i + 1 {
    if i > 0 {
      result = result + ","
    }
    let k = store.keys[i]
    result = result + "{\"key_id\":\"" + k.key_id + "\","
    result = result + "\"public_key\":\"" + k.public_key + "\","
    result = result + "\"owner\":\"" + k.owner + "\","
    result = result +
      "\"trust_level\":\"" +
      trust_level_str(k.trust_level) +
      "\","
    result = result + "\"added_at\":\"" + k.added_at + "\"}"
  }
  result + "]}"
}

///|
fn trust_level_str(level : TrustLevel) -> String {
  match level {
    Full => "full"
    Partial => "partial"
    Untrusted => "untrusted"
  }
}
