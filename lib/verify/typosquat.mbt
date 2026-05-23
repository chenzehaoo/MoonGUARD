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
