///|
test "fs roundtrip on native/wasm" {
  let dir = "moon_guard_fs_test_dir"
  ignore(create_dir(dir))
  let file = dir + "/hello.txt"
  write_string_to_file(file, "hello 世界")
  assert_eq(read_file_to_string(file), "hello 世界")
  let listed = read_dir(dir)
  assert_true(listed.contains("hello.txt"))
  assert_true(is_file(file))
  assert_true(is_dir(dir))
  assert_true(path_exists(file))
  remove_file(file)
  remove_dir(dir)
  assert_false(path_exists(file))
}

///|
test "walk scans nested directory" {
  let root = "moon_guard_fs_walk"
  ignore(create_dir(root))
  ignore(create_dir(root + "/src"))
  ignore(create_dir(root + "/src/pkg"))
  ignore(create_dir(root + "/target"))
  write_string_to_file(root + "/top.mbt", "fn top() {} ")
  write_string_to_file(root + "/src/pkg/a.mbt", "fn a() {} ")
  write_string_to_file(root + "/src/pkg/b.mbt", "fn b() {} ")
  write_string_to_file(root + "/build.out", "junk")
  let found = walk(root)
  assert_true(found.length() == 4)
  assert_true(found.contains("top.mbt"))
  assert_true(found.contains("build.out"))
  assert_true(found.contains("src/pkg/a.mbt"))
  assert_true(found.contains("src/pkg/b.mbt"))
  assert_false(found.contains("target/"))
  remove_file(root + "/top.mbt")
  remove_file(root + "/src/pkg/a.mbt")
  remove_file(root + "/src/pkg/b.mbt")
  remove_file(root + "/build.out")
  remove_dir(root + "/target")
  remove_dir(root + "/src/pkg")
  remove_dir(root + "/src")
  remove_dir(root)
}
