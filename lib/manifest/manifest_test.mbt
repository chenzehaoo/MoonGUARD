///|
/// MoonGuard Manifest Tests - SHA-256 verified against NIST test vectors
test "sha256 NIST vector: abc" {
  let h = @manifest.sha256("abc")
  inspect(
    h,
    content="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
  )
}

///|
test "sha256 NIST vector: empty string" {
  let h = @manifest.sha256("")
  inspect(
    h,
    content="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  )
}

///|
test "sha256 NIST vector: 448 bits" {
  let h = @manifest.sha256(
    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
  )
  inspect(
    h,
    content="248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
  )
}

///|
test "sha256 deterministic" {
  let h1 = @manifest.sha256("hello world")
  let h2 = @manifest.sha256("hello world")
  inspect(h1 == h2, content="true")
}

///|
test "sha256 different input different output" {
  let h1 = @manifest.sha256("abc")
  let h2 = @manifest.sha256("xyz")
  inspect(h1 != h2, content="true")
}

///|
test "sha256 returns 64 hex chars" {
  let h = @manifest.sha256("test")
  inspect(h.length(), content="64")
}

///|
test "compute_file_hash produces correct hash and size" {
  let entry = @manifest.FileEntry::{
    path: "src/main.mbt",
    content: "fn main {}",
  }
  let fh = @manifest.compute_file_hash(entry)
  inspect(fh.path, content="src/main.mbt")
  inspect(fh.size, content="10")
  inspect(fh.hash, content=@manifest.sha256("fn main {}"))
}

///|
test "generate_manifest builds manifest from entries" {
  let entries = [
    @manifest.FileEntry::{ path: "a.mbt", content: "let a = 1", },
    @manifest.FileEntry::{ path: "b.mbt", content: "let b = 2", },
    @manifest.FileEntry::{ path: "c.mbt", content: "let c = 3", },
  ]
  let m = @manifest.generate_manifest("my_pkg", "0.1.0", entries)
  inspect(m.total_files, content="3")
  inspect(m.total_size, content="27")
  inspect(m.package_name, content="my_pkg")
  inspect(m.files[0].path, content="a.mbt")
  inspect(m.files[1].path, content="b.mbt")
  inspect(m.files[2].path, content="c.mbt")
}

///|
test "verify_manifest detects no changes" {
  let entries = [@manifest.FileEntry::{ path: "a.mbt", content: "hello", }]
  let m = @manifest.generate_manifest("pkg", "1.0.0", entries)
  let mismatches = @manifest.verify_manifest(m, entries)
  inspect(mismatches.length(), content="0")
}

///|
test "verify_manifest detects modified file" {
  let entries = [@manifest.FileEntry::{ path: "a.mbt", content: "hello", }]
  let m = @manifest.generate_manifest("pkg", "1.0.0", entries)
  let modified = [@manifest.FileEntry::{ path: "a.mbt", content: "world", }]
  let mismatches = @manifest.verify_manifest(m, modified)
  inspect(mismatches.length(), content="1")
  inspect(mismatches[0], content="a.mbt")
}

///|
test "verify_manifest detects added and removed files" {
  let entries = [
    @manifest.FileEntry::{ path: "a.mbt", content: "aaa", },
    @manifest.FileEntry::{ path: "b.mbt", content: "bbb", },
  ]
  let m = @manifest.generate_manifest("pkg", "1.0.0", entries)
  let changed = [
    @manifest.FileEntry::{ path: "a.mbt", content: "aaa", },
    @manifest.FileEntry::{ path: "c.mbt", content: "ccc", },
  ]
  let mismatches = @manifest.verify_manifest(m, changed)
  // c.mbt is new (not in manifest), b.mbt is missing (in manifest but not in entries)
  inspect(mismatches.length(), content="2")
}

///|
test "manifest_to_json serialization" {
  let entries = [
    @manifest.FileEntry::{ path: "main.mbt", content: "fn main {}", },
  ]
  let m = @manifest.generate_manifest("demo", "0.1.0", entries)
  let json = @manifest.manifest_to_json(m)
  inspect(json.contains("\"package_name\": \"demo\""), content="true")
  inspect(json.contains("\"total_files\": 1"), content="true")
  inspect(json.contains("main.mbt"), content="true")
}

///|
test "manifest_summary" {
  let entries = [
    @manifest.FileEntry::{ path: "a.mbt", content: "12345", },
    @manifest.FileEntry::{ path: "b.mbt", content: "67890", },
  ]
  let m = @manifest.generate_manifest("my_pkg", "2.0.0", entries)
  let s = @manifest.manifest_summary(m)
  inspect(s, content="Package: my_pkg v2.0.0, Files: 2, Size: 10")
}

///|
test "take_chars_ returns first n characters" {
  inspect(@manifest.take_chars_("abcdef", 3), content="abc")
  inspect(@manifest.take_chars_("ab", 5), content="ab")
  inspect(@manifest.take_chars_("", 3), content="")
  inspect(@manifest.take_chars_("x", 0), content="")
}

///|
test "slice_chars_ returns [start, end) substring" {
  inspect(@manifest.slice_chars_("abcdef", 1, 4), content="bcd")
  inspect(@manifest.slice_chars_("abc", 0, 3), content="abc")
  inspect(@manifest.slice_chars_("abc", 5, 10), content="")
}

///|
test "manifest_from_json round-trips manifest_to_json" {
  let entries = [
    @manifest.FileEntry::{ path: "a.mbt", content: "let a = 1", },
    @manifest.FileEntry::{ path: "src/b.mbt", content: "let b = 2", },
  ]
  let m = @manifest.generate_manifest("my_pkg", "2.0.0", entries)
  let json = @manifest.manifest_to_json(m)
  match @manifest.manifest_from_json(json) {
    Some(parsed) => {
      inspect(parsed.package_name, content="my_pkg")
      inspect(parsed.package_version, content="2.0.0")
      inspect(parsed.total_files, content="2")
      fn is_hash64(h : String) -> Bool {
        h.length() == 64
      }
      inspect(
        parsed.files.length(),
        content=(
          #|2
        ),
      )
      inspect(is_hash64(parsed.files[0].hash), content="true")
    }
    None => inspect("parse failed", content="demo")
  }
}

///|
test "manifest_from_json rejects malformed document" {
  match @manifest.manifest_from_json("not json at all") {
    None => inspect(true, content="true")
    _ => inspect(false, content="true")
  }
}
