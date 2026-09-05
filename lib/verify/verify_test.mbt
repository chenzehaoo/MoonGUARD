///|
test "typosquat detects character swap" {
  let known = ["lodash", "express", "react", "angular"]
  let results = detect_typosquat("1odash", known)
  inspect(results.length() > 0, content="true")
  inspect(results[0].similar_to, content="lodash")
}

///|
test "typosquat detects extra character" {
  let known = ["lodash", "express", "react"]
  let results = detect_typosquat("expresss", known)
  inspect(results.length() > 0, content="true")
  inspect(results[0].similar_to, content="express")
  inspect(results[0].attack_type, content="extra-character")
}

///|
test "typosquat detects missing character" {
  let known = ["lodash", "express", "react"]
  let results = detect_typosquat("expres", known)
  inspect(results.length() > 0, content="true")
  inspect(results[0].attack_type, content="missing-character")
}

///|
test "typosquat separator trick" {
  let known = ["my-package", "cool-lib"]
  let results = detect_typosquat("my_package", known)
  inspect(results.length() > 0, content="true")
  inspect(results[0].attack_type, content="separator-swap")
}

///|
test "typosquat no false positive on exact match" {
  let known = ["lodash", "express"]
  let results = detect_typosquat("lodash", known)
  inspect(results.length(), content="0")
}

///|
test "typosquat no false positive on unrelated" {
  let known = ["lodash", "express"]
  let results = detect_typosquat("completely-different", known)
  inspect(results.length(), content="0")
}

///|
test "batch typosquat check" {
  let packages = ["1odash", "expresss", "react"]
  let known = ["lodash", "express", "react"]
  let results = batch_typosquat_check(packages, known)
  inspect(results.length(), content="2")
}

///|
test "verify package with valid signature" {
  let seed = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
  let kp = @crypto.generate_keypair(seed)
  let msg = "package-content-hash"
  let sig = @crypto.sign(msg, kp)
  let sig_hex = sig.r + sig.s
  let result = verify_package("my-pkg", sig_hex, kp.public_key, msg)
  inspect(result.is_valid, content="true")
  inspect(result.signature_ok, content="true")
}

///|
test "verify package rejects bad signature" {
  let key = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
  let bad_sig = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
  let result = verify_package("pkg", bad_sig, key, "content")
  inspect(result.is_valid, content="false")
}

///|
test "strict typosquat catches l-1 homoglyph" {
  // Classic npm typosquat: `1odash` (digit 1) impersonating `lodash` (letter l).
  let strict = detect_typosquat_strict("1odash", ["lodash"])
  inspect(strict.length() > 0, content="true")
  inspect(strict[0].attack_type, content="homoglyph")
}

///|
test "strict typosquat still catches separator swap" {
  let results = detect_typosquat_strict("my_package", ["my-package"])
  inspect(results.length() > 0, content="true")
  inspect(results[0].attack_type, content="separator-swap")
}

///|
test "strict typosquat doesn't false-positive on exact match" {
  let results = detect_typosquat_strict("lodash", ["lodash"])
  inspect(results.length(), content="0")
}

///|
test "typosquat_summary aggregates hits per suspect" {
  let known = ["lodash", "express", "react"]
  let entries = typosquat_summary(
    ["1odash", "Iodash", "expresss", "react"],
    known,
  )
  inspect(entries.length() > 0, content="true")
  // react doesn't trigger (exact match). 1odash/Iodash/expresss do.
  let mut react_seen = false
  let mut lodash_seen = false
  let mut express_seen = false
  let mut i = 0
  while i < entries.length() {
    if entries[i].suspect == "react" {
      react_seen = true
    }
    if entries[i].suspect == "1odash" {
      lodash_seen = true
      inspect(entries[i].hit_count >= 1, content="true")
    }
    if entries[i].suspect == "expresss" {
      express_seen = true
    }
    i = i + 1
  }
  inspect(lodash_seen, content="true")
  inspect(express_seen, content="true")
  inspect(react_seen, content="false")
}

///|
test "audit_package rejects when file hashes don't match" {
  let entries = [@manifest.FileEntry::{ path: "a.mbt", content: "hello", }]
  let manifest = @manifest.generate_manifest("audit", "1.0.0", entries)
  let seed = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
  let kp = @crypto.generate_keypair(seed)
  let payload = @manifest.manifest_to_json(manifest)
  let sig = @crypto.sign(payload, kp)
  let store = @trust.TrustStore::new()
  let _ = store.add_key(
    "alice",
    kp.public_key,
    "alice",
    @trust.TrustLevel::Full,
  )
  let tampered = [@manifest.FileEntry::{ path: "a.mbt", content: "world", }]
  let result = audit_package(
    "audit",
    "1.0.0",
    manifest,
    tampered,
    @verify.signature_to_hex(sig),
    "alice",
    store,
  )
  inspect(result.is_valid, content="false")
  // First error must come from the integrity check.
  inspect(result.errors[0].contains("hash mismatch"), content="true")
}

///|
test "audit_package rejects untrusted signer" {
  let entries = [@manifest.FileEntry::{ path: "a.mbt", content: "ok", }]
  let manifest = @manifest.generate_manifest("audit", "1.0.0", entries)
  let seed = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
  let kp = @crypto.generate_keypair(seed)
  let payload = @manifest.manifest_to_json(manifest)
  let sig = @crypto.sign(payload, kp)
  let store = @trust.TrustStore::new()
  // Signer key is in store but explicitly Untrusted.
  let _ = store.add_key(
    "alice",
    kp.public_key,
    "alice",
    @trust.TrustLevel::Untrusted,
  )
  let result = audit_package(
    "audit",
    "1.0.0",
    manifest,
    entries,
    @verify.signature_to_hex(sig),
    "alice",
    store,
  )
  inspect(result.is_valid, content="false")
  inspect(result.trust_status, content="untrusted")
}

///|
test "audit_package warns on missing signer" {
  let entries = [@manifest.FileEntry::{ path: "a.mbt", content: "ok", }]
  let manifest = @manifest.generate_manifest("audit", "1.0.0", entries)
  let seed = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
  let kp = @crypto.generate_keypair(seed)
  let payload = @manifest.manifest_to_json(manifest)
  let sig = @crypto.sign(payload, kp)
  let store = @trust.TrustStore::new() // empty
  let result = audit_package(
    "audit",
    "1.0.0",
    manifest,
    entries,
    @verify.signature_to_hex(sig),
    "alice",
    store,
  )
  // Trust lookup misses; signer key absent → trust_status is "unknown"
  // and the caller gets a warning. Signature itself can't be verified
  // because the store lookup returns an empty pubkey, so is_valid is
  // false but trust_status surfaces the real cause.
  inspect(result.trust_status, content="unknown")
  inspect(result.warnings.length() > 0, content="true")
}

///|
test "audit_package passes on clean trusted package" {
  let entries = [@manifest.FileEntry::{ path: "a.mbt", content: "ok", }]
  let manifest = @manifest.generate_manifest("audit", "1.0.0", entries)
  let seed = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
  let kp = @crypto.generate_keypair(seed)
  let payload = @manifest.manifest_to_json(manifest)
  let sig = @crypto.sign(payload, kp)
  let store = @trust.TrustStore::new()
  let _ = store.add_key(
    "alice",
    kp.public_key,
    "alice",
    @trust.TrustLevel::Full,
  )
  let result = audit_package(
    "audit",
    "1.0.0",
    manifest,
    entries,
    @verify.signature_to_hex(sig),
    "alice",
    store,
  )
  inspect(result.is_valid, content="true")
  inspect(result.trust_status, content="trusted")
}
