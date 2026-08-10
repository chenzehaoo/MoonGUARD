// wasm / wasm-gc backend: all filesystem operations go through the
// `__moonbit_fs_unstable` host module that the `moonrun` runtime (and the
// wasm CI target) exposes. Self-contained: no dependency on `@ffi`.

///|
#external
priv type XStringCreateHandle

///|
#external
priv type XStringReadHandle

///|
#external
priv type XExternString

///|
#external
priv type XStringArrayReadHandle

///|
#external
priv type XExternStringArray

///|
#external
priv type XByteArrayCreateHandle

///|
#external
priv type XByteArrayReadHandle

///|
#external
priv type XExternByteArray

///|
fn begin_create_string() -> XStringCreateHandle = "__moonbit_fs_unstable" "begin_create_string"

///|
fn string_append_char(handle : XStringCreateHandle, ch : Char) = "__moonbit_fs_unstable" "string_append_char"

///|
fn finish_create_string(handle : XStringCreateHandle) -> XExternString = "__moonbit_fs_unstable" "finish_create_string"

///|
fn string_to_extern(s : String) -> XExternString {
  let handle = begin_create_string()
  for i = 0; i < s.length(); i = i + 1 {
    string_append_char(handle, UInt16::unsafe_to_char(s.code_unit_at(i)))
  }
  finish_create_string(handle)
}

///|
fn begin_read_string(s : XExternString) -> XStringReadHandle = "__moonbit_fs_unstable" "begin_read_string"

///|
/// Read one char from the string, returns -1 if the end of the string is reached.
fn string_read_char(handle : XStringReadHandle) -> Int = "__moonbit_fs_unstable" "string_read_char"

///|
fn finish_read_string(handle : XStringReadHandle) = "__moonbit_fs_unstable" "finish_read_string"

///|
fn string_from_extern(e : XExternString) -> String {
  let buf = StringBuilder::new()
  let handle = begin_read_string(e)
  while true {
    let ch = string_read_char(handle)
    if ch == -1 {
      break
    } else {
      buf.write_char(Int::unsafe_to_char(ch))
    }
  }
  finish_read_string(handle)
  buf.to_string()
}

///|
fn begin_read_string_array(sa : XExternStringArray) -> XStringArrayReadHandle = "__moonbit_fs_unstable" "begin_read_string_array"

///|
fn string_array_read_string(handle : XStringArrayReadHandle) -> XExternString = "__moonbit_fs_unstable" "string_array_read_string"

///|
fn finish_read_string_array(handle : XStringArrayReadHandle) = "__moonbit_fs_unstable" "finish_read_string_array"

///|
fn string_array_from_extern(e : XExternStringArray) -> Array[String] {
  let buf = Array::new()
  let handle = begin_read_string_array(e)
  while true {
    let extern_str = string_array_read_string(handle)
    let str = string_from_extern(extern_str)
    // keep "ffi_end_of_/string_array" same with moonrun
    if str == "ffi_end_of_/string_array" {
      break
    } else {
      buf.push(str)
    }
  }
  finish_read_string_array(handle)
  buf
}

///|
fn begin_read_byte_array(s : XExternByteArray) -> XByteArrayReadHandle = "__moonbit_fs_unstable" "begin_read_byte_array"

///|
fn byte_array_read_byte(handle : XByteArrayReadHandle) -> Int = "__moonbit_fs_unstable" "byte_array_read_byte"

///|
fn finish_read_byte_array(handle : XByteArrayReadHandle) = "__moonbit_fs_unstable" "finish_read_byte_array"

///|
fn begin_create_byte_array() -> XByteArrayCreateHandle = "__moonbit_fs_unstable" "begin_create_byte_array"

///|
fn byte_array_append_byte(handle : XByteArrayCreateHandle, ch : Int) = "__moonbit_fs_unstable" "byte_array_append_byte"

///|
fn finish_create_byte_array(
  handle : XByteArrayCreateHandle,
) -> XExternByteArray = "__moonbit_fs_unstable" "finish_create_byte_array"

///|
fn byte_array_to_extern(s : Bytes) -> XExternByteArray {
  let handle = begin_create_byte_array()
  for i = 0; i < s.length(); i = i + 1 {
    byte_array_append_byte(handle, s[i].to_int())
  }
  finish_create_byte_array(handle)
}

///|
fn byte_array_from_extern(e : XExternByteArray) -> Bytes {
  let buf = Array::new()
  let handle = begin_read_byte_array(e)
  while true {
    let ch = byte_array_read_byte(handle)
    if ch == -1 {
      break
    } else {
      buf.push(ch.to_byte())
    }
  }
  finish_read_byte_array(handle)
  Bytes::from_array(buf)
}

///|
fn get_error_message_ffi() -> XExternString = "__moonbit_fs_unstable" "get_error_message"

///|
fn get_error_message() -> String {
  string_from_extern(get_error_message_ffi())
}

///|
fn get_file_content_ffi() -> XExternByteArray = "__moonbit_fs_unstable" "get_file_content"

///|
fn get_dir_files_ffi() -> XExternStringArray = "__moonbit_fs_unstable" "get_dir_files"

///|
fn read_file_to_bytes_ffi(path : XExternString) -> Int = "__moonbit_fs_unstable" "read_file_to_bytes_new"

///|
fn write_bytes_to_file_ffi(
  path : XExternString,
  content : XExternByteArray,
) -> Int = "__moonbit_fs_unstable" "write_bytes_to_file_new"

///|
fn read_file_to_bytes_internal(path : String) -> Bytes raise IOError {
  let res = read_file_to_bytes_ffi(string_to_extern(path))
  guard res != -1 else { raise IOError(get_error_message()) }
  byte_array_from_extern(get_file_content_ffi())
}

///|
fn read_file_to_string_internal(
  path : String,
  encoding? : String = "utf8",
) -> String raise IOError {
  guard encoding == "utf8" else {
    raise IOError(
      "Unsupported encoding: \{encoding}, only utf8 is supported for now",
    )
  }
  utf8_bytes_to_mbt_string(read_file_to_bytes_internal(path))
}

///|
fn write_bytes_to_file_internal(
  path : String,
  content : Bytes,
) -> Unit raise IOError {
  let res = write_bytes_to_file_ffi(
    string_to_extern(path),
    byte_array_to_extern(content),
  )
  guard res != -1 else { raise IOError(get_error_message()) }
}

///|
fn write_string_to_file_internal(
  path : String,
  content : String,
  encoding? : String = "utf8",
) -> Unit raise IOError {
  guard encoding == "utf8" else {
    raise IOError(
      "Unsupported encoding: \{encoding}, only utf8 is supported for now",
    )
  }
  write_bytes_to_file_internal(path, mbt_string_to_utf8_bytes(content, false))
}

///|
fn path_exists_ffi(path : XExternString) -> Bool = "__moonbit_fs_unstable" "path_exists"

///|
fn path_exists_internal(path : String) -> Bool {
  path_exists_ffi(string_to_extern(path))
}

///|
fn create_dir_ffi(path : XExternString) -> Int = "__moonbit_fs_unstable" "create_dir_new"

///|
fn create_dir_internal(path : String) -> Unit raise IOError {
  let res = create_dir_ffi(string_to_extern(path))
  guard res != -1 else { raise IOError(get_error_message()) }
}

///|
fn read_dir_ffi(path : XExternString) -> Int = "__moonbit_fs_unstable" "read_dir_new"

///|
fn read_dir_internal(path : String) -> Array[String] raise IOError {
  let res = read_dir_ffi(string_to_extern(path))
  guard res != -1 else { raise IOError(get_error_message()) }
  string_array_from_extern(get_dir_files_ffi())
}

///|
fn is_file_ffi(path : XExternString) -> Int = "__moonbit_fs_unstable" "is_file_new"

///|
fn is_file_internal(path : String) -> Bool raise IOError {
  let res = is_file_ffi(string_to_extern(path))
  guard res != -1 else { raise IOError(get_error_message()) }
  res == 1
}

///|
fn is_dir_ffi(path : XExternString) -> Int = "__moonbit_fs_unstable" "is_dir_new"

///|
fn is_dir_internal(path : String) -> Bool raise IOError {
  let res = is_dir_ffi(string_to_extern(path))
  guard res != -1 else { raise IOError(get_error_message()) }
  res == 1
}

///|
fn remove_file_ffi(path : XExternString) -> Int = "__moonbit_fs_unstable" "remove_file_new"

///|
fn remove_file_internal(path : String) -> Unit raise IOError {
  let res = remove_file_ffi(string_to_extern(path))
  guard res != -1 else { raise IOError(get_error_message()) }
}

///|
fn remove_dir_ffi(path : XExternString) -> Int = "__moonbit_fs_unstable" "remove_dir_new"

///|
fn remove_dir_internal(path : String) -> Unit raise IOError {
  let res = remove_dir_ffi(string_to_extern(path))
  guard res != -1 else { raise IOError(get_error_message()) }
}

///|
fn mbt_string_to_utf8_bytes(str : String, is_filename : Bool) -> Bytes {
  let res : Array[Byte] = []
  let len = str.length()
  let mut i = 0
  while i < len {
    let mut c = str.code_unit_at(i).to_int()
    if 0xD800 <= c && c <= 0xDBFF {
      c -= 0xD800
      i = i + 1
      let l = str.code_unit_at(i).to_int() - 0xDC00
      c = (c << 10) + l + 0x10000
    }
    if c < 0x80 {
      res.push(c.to_byte())
    } else if c < 0x800 {
      res.push((0xc0 + (c >> 6)).to_byte())
      res.push((0x80 + (c & 0x3f)).to_byte())
    } else if c < 0x10000 {
      res.push((0xe0 + (c >> 12)).to_byte())
      res.push((0x80 + ((c >> 6) & 0x3f)).to_byte())
      res.push((0x80 + (c & 0x3f)).to_byte())
    } else {
      res.push((0xf0 + (c >> 18)).to_byte())
      res.push((0x80 + ((c >> 12) & 0x3f)).to_byte())
      res.push((0x80 + ((c >> 6) & 0x3f)).to_byte())
      res.push((0x80 + (c & 0x3f)).to_byte())
    }
    i = i + 1
  }
  if is_filename {
    res.push((0).to_byte())
  }
  Bytes::from_array(res)
}

///|
fn utf8_bytes_to_mbt_string(bytes : Bytes) -> String {
  let res : Array[Char] = []
  let len = bytes.length()
  let mut i = 0
  while i < len {
    let mut c = bytes[i].to_int()
    if c < 0x80 {
      res.push(Int::unsafe_to_char(c))
      i += 1
    } else if c < 0xE0 {
      if i + 1 >= len {
        break
      }
      c = ((c & 0x1F) << 6) | (bytes[i + 1].to_int() & 0x3F)
      res.push(Int::unsafe_to_char(c))
      i += 2
    } else if c < 0xF0 {
      if i + 2 >= len {
        break
      }
      c = ((c & 0x0F) << 12) |
        ((bytes[i + 1].to_int() & 0x3F) << 6) |
        (bytes[i + 2].to_int() & 0x3F)
      res.push(Int::unsafe_to_char(c))
      i += 3
    } else {
      if i + 3 >= len {
        break
      }
      c = ((c & 0x07) << 18) |
        ((bytes[i + 1].to_int() & 0x3F) << 12) |
        ((bytes[i + 2].to_int() & 0x3F) << 6) |
        (bytes[i + 3].to_int() & 0x3F)
      c -= 0x10000
      res.push(Int::unsafe_to_char((c >> 10) + 0xD800))
      res.push(Int::unsafe_to_char((c & 0x3FF) + 0xDC00))
      i += 4
    }
  }
  String::from_array(res)
}
