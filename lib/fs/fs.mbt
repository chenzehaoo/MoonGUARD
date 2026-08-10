///|
pub(all) suberror IOError {
  IOError(String)
} derive(Debug)

///|
/// Reads the content of a file at `path` as raw bytes.
pub fn read_file_to_bytes(path : String) -> Bytes raise IOError {
  read_file_to_bytes_internal(path)
}

///|
/// Reads the content of a file at `path` as UTF-8 text.
pub fn read_file_to_string(
  path : String,
  encoding? : String = "utf8",
) -> String raise IOError {
  read_file_to_string_internal(path, encoding~)
}

///|
/// Writes `content` to the file at `path`, truncating any existing file.
pub fn write_bytes_to_file(
  path : String,
  content : Bytes,
) -> Unit raise IOError {
  write_bytes_to_file_internal(path, content)
}

///|
/// Writes `content` to the file at `path` as UTF-8 text.
pub fn write_string_to_file(
  path : String,
  content : String,
  encoding? : String = "utf8",
) -> Unit raise IOError {
  write_string_to_file_internal(path, content, encoding~)
}

///|
/// Whether a path exists on disk (file or directory).
pub fn path_exists(path : String) -> Bool {
  path_exists_internal(path)
}

///|
/// Lists the immediate entries (names) of the directory at `path`.
pub fn read_dir(path : String) -> Array[String] raise IOError {
  read_dir_internal(path)
}

///|
/// Creates a directory at `path`.
pub fn create_dir(path : String) -> Unit raise IOError {
  create_dir_internal(path)
}

///|
/// Whether `path` points to a directory.
pub fn is_dir(path : String) -> Bool raise IOError {
  is_dir_internal(path)
}

///|
/// Whether `path` points to a regular file.
pub fn is_file(path : String) -> Bool raise IOError {
  is_file_internal(path)
}

///|
/// Removes the directory at `path`.
pub fn remove_dir(path : String) -> Unit raise IOError {
  remove_dir_internal(path)
}

///|
/// Removes the file at `path`.
pub fn remove_file(path : String) -> Unit raise IOError {
  remove_file_internal(path)
}

///|
/// Recursively walks a directory and returns the relative paths of every
/// regular file under it, using `/` as the separator. The well-known
/// VCS / build-output directories (`.git`, `.mooncakes`, `target`,
/// `node_modules`, `_build`) are skipped so generated artifacts never pollute
/// a manifest. This is the primitive the manifest/audit CLI commands use to
/// scan a real directory instead of a hand-written `path:content` list.
pub fn walk(root : String) -> Array[String] raise IOError {
  let result : Array[String] = []
  walk_into(root, "", result)
  result
}

///|
fn walk_into(
  root : String,
  prefix : String,
  result : Array[String],
) -> Unit raise IOError {
  let dir = if prefix.length() == 0 { root } else { root + "/" + prefix }
  let entries = read_dir_internal(dir)
  for i = 0; i < entries.length(); i = i + 1 {
    let name = entries[i]
    let rel = if prefix.length() == 0 { name } else { prefix + "/" + name }
    let child = dir + "/" + name
    if is_dir_internal(child) {
      if name != ".git" &&
        name != ".mooncakes" &&
        name != "target" &&
        name != "node_modules" &&
        name != "_build" {
        walk_into(root, rel, result)
      }
    } else {
      result.push(rel)
    }
  }
}
