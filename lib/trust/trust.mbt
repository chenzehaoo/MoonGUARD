///|
pub(all) enum TrustLevel {
  Full
  Partial
  Untrusted
} derive(Eq)

///|
pub fn TrustLevel::to_string(self : TrustLevel) -> String {
  match self {
    Full => "Full"
    Partial => "Partial"
    Untrusted => "Untrusted"
  }
}

///|
pub impl Show for TrustLevel with fn output(self : TrustLevel, logger : &Logger) -> Unit {
  match self {
    Full => logger.write_string("Full")
    Partial => logger.write_string("Partial")
    Untrusted => logger.write_string("Untrusted")
  }
}

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
pub fn TrustStore::list_all(self : TrustStore) -> Array[TrustedKey] {
  let result : Array[TrustedKey] = []
  for i = 0; i < self.keys.length(); i = i + 1 {
    result.push(self.keys[i])
  }
  result
}

///|
/// Replace the contents of the store. Used by `load_from_json` to restore
/// from persistence and by tests to set up fixtures.
pub fn TrustStore::replace_all(
  self : TrustStore,
  keys : Array[TrustedKey],
) -> Unit {
  self.keys = keys
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
/// Normalize an Ed25519 public key to lower-case hex, accepting mixed-case
/// input from PEM files or operator copy-paste. Returns `None` when the
/// input has the wrong shape.
pub fn normalize_public_key(public_key : String) -> String? {
  if public_key.length() != 64 {
    return None
  }
  let buf = StringBuilder::new(size_hint=64)
  for i = 0; i < 64; i = i + 1 {
    let c = public_key[i]
    let ok = (c >= 48 && c <= 57) ||
      (c >= 97 && c <= 102) ||
      (c >= 65 && c <= 70)
    if not(ok) {
      return None
    }
    if c >= 65 && c <= 70 {
      // A-F -> a-f
      buf.write_char((c + 32).unsafe_to_char())
    } else {
      buf.write_char(c.unsafe_to_char())
    }
  }
  Some(buf.to_string())
}

///|
/// Stable JSON encoding used by both the CLI and the file persistence path.
/// Kept in one place so the wire format stays consistent across consumers.
pub fn trust_store_to_json(store : TrustStore) -> String {
  let mut result = "{\"version\":\"1\",\"keys\":["
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
/// Parse a `trust_store_to_json` document into a fresh store. Returns
/// `None` when the document is malformed so the caller can surface a
/// useful error rather than a partial store.
pub fn trust_store_from_json(json : String) -> TrustStore? {
  let store = TrustStore::new()
  // Find the version field; default to "1" when omitted (legacy format).
  let version = extract_string_field(json, "version")
  let _ = version // reserved for future migration
  let arr_body = match extract_array(json, "keys") {
    Some(s) => s
    None => return None
  }
  let entries = split_top_level_objects(arr_body)
  for i = 0; i < entries.length(); i = i + 1 {
    let entry = entries[i]
    let key_id = match extract_string_field(entry, "key_id") {
      Some(s) => s
      None => return None
    }
    let public_key = match extract_string_field(entry, "public_key") {
      Some(s) => s
      None => return None
    }
    let owner = match extract_string_field(entry, "owner") {
      Some(s) => s
      None => return None
    }
    let level_str = match extract_string_field(entry, "trust_level") {
      Some(s) => s
      None => "full"
    }
    let trust_level = trust_level_from_str(level_str)
    let added_at = match extract_string_field(entry, "added_at") {
      Some(s) => s
      None => "2026-01-01"
    }
    // Skip entries whose public key isn't 64-char hex — they're invalid.
    if not(validate_public_key_format(public_key)) {
      return None
    }
    // Silently drop duplicate key_ids when re-loading.
    let already = store.get_key(key_id)
    if already is Some(_) {
      continue
    }
    store.keys.push(TrustedKey::{
      key_id,
      public_key,
      owner,
      trust_level,
      added_at,
    })
  }
  Some(store)
}

///|
fn trust_level_str(level : TrustLevel) -> String {
  match level {
    Full => "full"
    Partial => "partial"
    Untrusted => "untrusted"
  }
}

///|
fn trust_level_from_str(s : String) -> TrustLevel {
  if s == "full" {
    TrustLevel::Full
  } else if s == "partial" {
    TrustLevel::Partial
  } else {
    TrustLevel::Untrusted
  }
}

///|
/// PEM encode an Ed25519 public key for storage in `.pem` files.
/// Format follows RFC 7468 section 13 ("PUBLIC KEY") which is the same
/// shape libsodium / age / OpenSSH use for raw Ed25519 keys.
pub fn public_key_to_pem(public_key : String) -> String {
  let prefix = "-----BEGIN MOONGUARD PUBLIC KEY-----\n"
  let suffix = "-----END MOONGUARD PUBLIC KEY-----\n"
  let buf = StringBuilder::new(size_hint=public_key.length() * 2)
  buf.write_string(prefix)
  // Emit 64-char chunks until fewer than 64 remain, then flush the tail.
  let full_chunks = public_key.length() / 64
  let mut chunk_idx = 0
  while chunk_idx < full_chunks {
    // Each chunk is built from 64 individual chars to avoid Result-typed
    // slicing APIs.
    let line = StringBuilder::new(size_hint=64)
    let mut k = 0
    while k < 64 {
      line.write_char(public_key[chunk_idx * 64 + k].unsafe_to_char())
      k = k + 1
    }
    buf.write_string(line.to_string())
    buf.write_char('\n')
    chunk_idx = chunk_idx + 1
  }
  if full_chunks * 64 < public_key.length() {
    let tail = StringBuilder::new(size_hint=public_key.length())
    let mut k = full_chunks * 64
    while k < public_key.length() {
      tail.write_char(public_key[k].unsafe_to_char())
      k = k + 1
    }
    buf.write_string(tail.to_string())
    buf.write_char('\n')
  }
  buf.write_string(suffix)
  buf.to_string()
}

///|
/// Inverse of `public_key_to_pem`. Accepts both upper- and lower-case hex
/// inside the PEM envelope. Returns `None` when the input doesn't look
/// like a MoonGuard public key PEM.
pub fn public_key_from_pem(pem : String) -> String? {
  let start = "-----BEGIN MOONGUARD PUBLIC KEY-----"
  let end = "-----END MOONGUARD PUBLIC KEY-----"
  if not(contains_substring(pem, start)) {
    return None
  }
  if not(contains_substring(pem, end)) {
    return None
  }
  // Find the body between the header and footer lines.
  let mut start_idx = 0
  let mut i = 0
  while i < pem.length() - start.length() {
    if match_substring_at(pem, start, i) {
      start_idx = i + start.length()
      break
    }
    i = i + 1
  }
  if start_idx == 0 {
    return None
  }
  // Skip the newline right after the header line.
  if start_idx < pem.length() && pem[start_idx] == '\n' {
    start_idx = start_idx + 1
  }
  let mut end_idx = pem.length()
  i = start_idx
  while i < pem.length() - end.length() {
    if match_substring_at(pem, end, i) {
      end_idx = i
      break
    }
    i = i + 1
  }
  let body = @manifest.slice_chars_(pem, start_idx, end_idx)
  // Strip whitespace and dashes to isolate the hex digits.
  let buf = StringBuilder::new(size_hint=64)
  i = 0
  while i < body.length() {
    let c = body[i]
    let is_hex = (c >= 48 && c <= 57) ||
      (c >= 65 && c <= 70) ||
      (c >= 97 && c <= 102)
    if is_hex {
      buf.write_char(c.unsafe_to_char())
    }
    i = i + 1
  }
  let hex = buf.to_string()
  if hex.length() != 64 {
    return None
  }
  normalize_public_key(hex)
}

///|
fn contains_substring(haystack : String, needle : String) -> Bool {
  if needle.length() > haystack.length() {
    return false
  }
  let mut i = 0
  while i <= haystack.length() - needle.length() {
    if match_substring_at(haystack, needle, i) {
      return true
    }
    i = i + 1
  }
  false
}

///|
fn match_substring_at(haystack : String, needle : String, offset : Int) -> Bool {
  if offset + needle.length() > haystack.length() {
    return false
  }
  let mut i = 0
  while i < needle.length() {
    if haystack[offset + i] != needle[i] {
      return false
    }
    i = i + 1
  }
  true
}

///|
/// Pull a quoted string field out of a flat JSON object. Returns `None`
/// when the field is missing or the surrounding braces don't match. Only
/// good enough for the trust-store schema, which is small and produced
/// by `trust_store_to_json`.
fn extract_string_field(json : String, field : String) -> String? {
  let needle = "\"" + field + "\":\""
  let idx = find_substring(json, needle)
  if idx < 0 {
    return None
  }
  let value_start = idx + needle.length()
  let mut i = value_start
  while i < json.length() && json[i] != '"' {
    i = i + 1
  }
  if i >= json.length() {
    return None
  }
  Some(@manifest.slice_chars_(json, value_start, i))
}

///|
fn find_substring(haystack : String, needle : String) -> Int {
  if needle.length() == 0 {
    return 0
  }
  if needle.length() > haystack.length() {
    return -1
  }
  let mut i = 0
  while i <= haystack.length() - needle.length() {
    if match_substring_at(haystack, needle, i) {
      return i
    }
    i = i + 1
  }
  -1
}

///|
/// Pull the contents of the `"keys":[ ... ]` array out of a trust-store
/// document so we can split it into individual object entries.
fn extract_array(json : String, field : String) -> String? {
  let needle = "\"" + field + "\":["
  let idx = find_substring(json, needle)
  if idx < 0 {
    return None
  }
  let value_start = idx + needle.length()
  // Walk forward, counting brace depth, to find the matching `]`.
  let mut depth = 1
  let mut i = value_start
  while i < json.length() && depth > 0 {
    let c = json[i]
    if c == '[' {
      depth = depth + 1
    } else if c == ']' {
      depth = depth - 1
    }
    i = i + 1
  }
  if depth != 0 {
    return None
  }
  Some(@manifest.slice_chars_(json, value_start, i - 1))
}

///|
/// Split an array body like `{...},{...},{...}` into individual objects.
/// Respects brace nesting so a string field containing `,` or `{` doesn't
/// break the split.
fn split_top_level_objects(body : String) -> Array[String] {
  let result : Array[String] = []
  let mut i = 0
  let len = body.length()
  while i < len {
    // Skip whitespace and commas between entries.
    while i < len {
      let c = body[i]
      if c == ' ' || c == '\n' || c == '\r' || c == '\t' || c == ',' {
        i = i + 1
      } else {
        break
      }
    }
    if i >= len {
      break
    }
    if body[i] != '{' {
      // Malformed entry — bail out.
      break
    }
    let start = i
    let mut depth = 1
    i = i + 1
    while i < len && depth > 0 {
      let c = body[i]
      if c == '{' {
        depth = depth + 1
      } else if c == '}' {
        depth = depth - 1
      }
      i = i + 1
    }
    if depth != 0 {
      break
    }
    result.push(@manifest.slice_chars_(body, start, i))
  }
  result
}
