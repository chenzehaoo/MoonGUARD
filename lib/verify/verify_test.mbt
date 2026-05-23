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
