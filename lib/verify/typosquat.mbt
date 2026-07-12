///|
pub(all) struct TyposquatResult {
  suspect : String
  similar_to : String
  distance : Int
  attack_type : String
}

///|
pub fn detect_typosquat(
  package_name : String,
  known_packages : Array[String],
) -> Array[TyposquatResult] {
  let results : Array[TyposquatResult] = []
  for i = 0; i < known_packages.length(); i = i + 1 {
    let known = known_packages[i]
    if package_name == known {
      continue i + 1
    }
    if has_separator_trick(package_name, known) {
      results.push(TyposquatResult::{
        suspect: package_name,
        similar_to: known,
        distance: 0,
        attack_type: "separator-swap",
      })
    } else {
      let dist = levenshtein(package_name, known)
      if dist > 0 && dist <= 2 {
        results.push(TyposquatResult::{
          suspect: package_name,
          similar_to: known,
          distance: dist,
          attack_type: classify_attack(package_name, known),
        })
      }
    }
  }
  results
}

///|
/// Stronger variant that also flags look-alike Unicode / ASCII substitution
/// (`1` vs `l`, `0` vs `o`, `rn` vs `m`) which classic Levenshtein misses.
pub fn detect_typosquat_strict(
  package_name : String,
  known_packages : Array[String],
) -> Array[TyposquatResult] {
  let results : Array[TyposquatResult] = []
  for i = 0; i < known_packages.length(); i = i + 1 {
    let known = known_packages[i]
    if package_name == known {
      continue i + 1
    }
    if has_separator_trick(package_name, known) {
      results.push(TyposquatResult::{
        suspect: package_name,
        similar_to: known,
        distance: 0,
        attack_type: "separator-swap",
      })
      continue i + 1
    }
    if has_homoglyph_substitution(package_name, known) {
      results.push(TyposquatResult::{
        suspect: package_name,
        similar_to: known,
        distance: 1,
        attack_type: "homoglyph",
      })
      continue i + 1
    }
    let dist = levenshtein(package_name, known)
    if dist > 0 && dist <= 2 {
      results.push(TyposquatResult::{
        suspect: package_name,
        similar_to: known,
        distance: dist,
        attack_type: classify_attack(package_name, known),
      })
    }
  }
  results
}

///|
pub fn batch_typosquat_check(
  packages : Array[String],
  known_good : Array[String],
) -> Array[TyposquatResult] {
  let all_results : Array[TyposquatResult] = []
  for i = 0; i < packages.length(); i = i + 1 {
    let hits = detect_typosquat(packages[i], known_good)
    for j = 0; j < hits.length(); j = j + 1 {
      all_results.push(hits[j])
    }
  }
  all_results
}

///|
/// Aggregate batch detector: per-package hit counts grouped by suspect.
pub fn typosquat_summary(
  packages : Array[String],
  known_good : Array[String],
) -> Array[@report.TyposquatSummaryEntry] {
  let all = batch_typosquat_check(packages, known_good)
  let result : Array[@report.TyposquatSummaryEntry] = []
  // Collect every distinct suspect we saw at least one hit for.
  let suspects : Array[String] = []
  let mut i = 0
  while i < all.length() {
    let s = all[i].suspect
    let mut seen = false
    let mut j = 0
    while j < suspects.length() {
      if suspects[j] == s {
        seen = true
        break
      }
      j = j + 1
    }
    if not(seen) {
      suspects.push(s)
    }
    i = i + 1
  }
  // For each suspect, count how many known packages it imitates.
  let mut k = 0
  while k < suspects.length() {
    let suspect = suspects[k]
    let mut hit_count = 0
    let mut first_similar_to = ""
    let mut first_attack = ""
    let mut m = 0
    while m < all.length() {
      if all[m].suspect == suspect {
        hit_count = hit_count + 1
        if first_similar_to == "" {
          first_similar_to = all[m].similar_to
          first_attack = all[m].attack_type
        }
      }
      m = m + 1
    }
    result.push(@report.TyposquatSummaryEntry::{
      suspect,
      hit_count,
      first_similar_to,
      first_attack,
    })
    k = k + 1
  }
  result
}

///|
fn levenshtein(a : String, b : String) -> Int {
  let m = a.length()
  let n = b.length()
  if m == 0 {
    return n
  }
  if n == 0 {
    return m
  }
  let prev : Array[Int] = Array::make(n + 1, 0)
  let curr : Array[Int] = Array::make(n + 1, 0)
  for j = 0; j <= n; j = j + 1 {
    prev[j] = j
  }
  for i = 1; i <= m; i = i + 1 {
    curr[0] = i
    for j = 1; j <= n; j = j + 1 {
      let cost = if a[i - 1] == b[j - 1] { 0 } else { 1 }
      let del = prev[j] + 1
      let ins = curr[j - 1] + 1
      let sub = prev[j - 1] + cost
      curr[j] = min3(del, ins, sub)
    }
    for j = 0; j <= n; j = j + 1 {
      prev[j] = curr[j]
    }
  }
  prev[n]
}

///|
fn min3(a : Int, b : Int, c : Int) -> Int {
  let ab = if a < b { a } else { b }
  if ab < c {
    ab
  } else {
    c
  }
}

///|
fn classify_attack(suspect : String, known : String) -> String {
  if suspect.length() == known.length() {
    "character-swap"
  } else if suspect.length() > known.length() {
    "extra-character"
  } else {
    "missing-character"
  }
}

///|
fn has_separator_trick(suspect : String, known : String) -> Bool {
  let s = normalize_separators(suspect)
  let k = normalize_separators(known)
  s == k && suspect != known
}

///|
fn normalize_separators(name : String) -> String {
  let mut result = ""
  for i = 0; i < name.length(); i = i + 1 {
    let c = name[i]
    if c == 45 || c == 95 || c == 46 {
      result = result + "-"
    } else {
      result = result + c.unsafe_to_char().to_string()
    }
  }
  result
}

///|
/// Detect common look-alike substitutions that survive separator normalization
/// but differ character-by-character. The set covers the typical "1odash"
/// / "reactt" / "expres" style tricks published-package attackers use.
fn has_homoglyph_substitution(suspect : String, known : String) -> Bool {
  if suspect.length() != known.length() {
    return false
  }
  let mut diffs = 0
  let mut i = 0
  while i < suspect.length() {
    let sc = suspect[i].to_int()
    let kc = known[i].to_int()
    if sc != kc {
      if not(are_homoglyphs(sc, kc)) {
        return false
      }
      diffs = diffs + 1
    }
    i = i + 1
  }
  diffs > 0 && diffs <= 3
}

///|
fn are_homoglyphs(a : Int, b : Int) -> Bool {
  // Common look-alike pairs that copy-paste through code review.
  if a == b {
    return true
  }
  pairs().iter().any(fn(p) { p == (a, b) })
}

///|
/// Hard-coded substitution table. Returning `(Int, Int)` pairs keeps the
/// MoonBit type signature simple — the caller matches either order.
fn pairs() -> Array[(Int, Int)] {
  [
    (49, 108), // 1 ↔ l
    (108, 49),
    (79, 48),
    (111, 48), // O/o ↔ 0
    (48, 79),
    (48, 111),
    (73, 108),
    (105, 108), // I/i ↔ l
    (108, 73),
    (108, 105),
    (114, 110), // rn ↔ m via glyph combo
    (110, 109),
    (109, 110),
    (115, 53), // s ↔ 5
    (53, 115),
    (83, 53),
    (53, 83),
    (98, 54), // B ↔ 6 (when both used)
    (54, 98),
    (66, 54),
    (54, 66),
  ]
}
