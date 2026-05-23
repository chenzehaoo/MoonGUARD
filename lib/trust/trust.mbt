///|
/// MoonGuard Trust Store Module
/// Local trusted key store management

pub struct TrustedKey {
  key_id: String
  public_key: String
  owner: String
  trust_level: TrustLevel
}

pub enum TrustLevel {
  Explicit
  Indirect
  Untrusted
}

pub struct TrustStore {
  version: String
}

///| Create an empty trust store
pub fn TrustStore::new() -> TrustStore {
  TrustStore::{ version: "1.0.0" }
}

///| Check if a key is trusted
pub fn TrustStore::is_trusted(self: TrustStore, key_id: String) -> Bool {
  false
}

///| Calculate key fingerprint
pub fn calculate_key_fingerprint(public_key: String) -> String {
  "fingerprint placeholder"
}

///| Validate public key format
pub fn validate_public_key_format(public_key: String) -> Bool {
  true
}

///| Export trust store to JSON string
pub fn trust_store_to_json(store: TrustStore) -> String {
  "{\"version\": \"1.0.0\", \"keys\": []}"
}