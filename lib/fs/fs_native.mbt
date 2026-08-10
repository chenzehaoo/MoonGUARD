// native / llvm backend: file access via a small C shim shipped as
// `fs_native.c` (the `native-stub` option in moon.pkg).

///|
#external
priv type Handler

///|
#borrow(path, mode)
extern "C" fn fopen_ffi(path : Bytes, mode : Bytes) -> Handler = "moon_guard_fs_fopen"

///|
extern "C" fn is_null(ptr : Handler) -> Int = "moon_guard_fs_is_null"

///|
#borrow(ptr)
extern "C" fn fread_ffi(
  ptr : Bytes,
  size : Int,
  nitems : Int,
  stream : Handler,
) -> Int = "moon_guard_fs_fread"

///|
#borrow(ptr)
extern "C" fn fwrite_ffi(
  ptr : Bytes,
  size : Int,
  nitems : Int,
  stream : Handler,
) -> Int = "moon_guard_fs_fwrite"

///|
extern "C" fn get_error_message_ffi() -> Bytes = "moon_guard_fs_get_error_message"

///|
extern "C" fn fseek_ffi(file : Handler, offset : Int, whence : Int) -> Int = "moon_guard_fs_fseek"

///|
extern "C" fn ftell_ffi(file : Handler) -> Int = "moon_guard_fs_ftell"

///|
extern "C" fn fflush_ffi(stream : Handler) -> Int = "moon_guard_fs_fflush"

///|
extern "C" fn fclose_ffi(file : Handler) -> Int = "moon_guard_fs_fclose"

///|
fn errmsg() -> String {
  utf8_bytes_to_mbt_string(get_error_message_ffi())
}

///|
fn read_file_to_bytes_internal(path : String) -> Bytes raise IOError {
  let file = fopen_ffi(mbt_string_to_utf8_bytes(path, true), b"rb\x00")
  guard is_null(file) == 0 else { raise IOError(errmsg()) }
  guard fseek_ffi(file, 0, 2) == 0 else { raise IOError(errmsg()) }
  let size = ftell_ffi(file)
  guard size != -1 else { raise IOError(errmsg()) }
  guard fseek_ffi(file, 0, 0) == 0 else { raise IOError(errmsg()) }
  let bytes = Bytes::make(size, 0)
  let bytes_read = fread_ffi(bytes, 1, size, file)
  guard bytes_read == size else { raise IOError(errmsg()) }
  guard fclose_ffi(file) == 0 else { raise IOError(errmsg()) }
  bytes
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
  let file = fopen_ffi(mbt_string_to_utf8_bytes(path, true), b"wb\x00")
  guard is_null(file) == 0 else { raise IOError(errmsg()) }
  let written = fwrite_ffi(content, 1, content.length(), file)
  guard written == content.length() else { raise IOError(errmsg()) }
  guard fflush_ffi(file) == 0 else { raise IOError(errmsg()) }
  guard fclose_ffi(file) == 0 else { raise IOError(errmsg()) }
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
#borrow(path)
extern "C" fn stat_ffi(path : Bytes) -> Int = "moon_guard_fs_stat"

///|
fn path_exists_internal(path : String) -> Bool {
  stat_ffi(mbt_string_to_utf8_bytes(path, true)) != -1
}

///|
#borrow(path)
extern "C" fn read_dir_ffi(path : Bytes) -> Handler = "moon_guard_fs_read_dir"

///|
fn handler_to_fixed_array(handler : Handler) -> FixedArray[Bytes] = "%identity"

///|
fn read_dir_internal(path : String) -> Array[String] raise IOError {
  let res = read_dir_ffi(mbt_string_to_utf8_bytes(path, true))
  guard is_null(res) == 0 else { raise IOError(errmsg()) }
  let files = Array::from_fixed_array(handler_to_fixed_array(res))
  files.map(utf8_bytes_to_mbt_string)
}

///|
#borrow(path)
extern "C" fn create_dir_ffi(path : Bytes) -> Int = "moon_guard_fs_create_dir"

///|
fn create_dir_internal(path : String) -> Unit raise IOError {
  guard create_dir_ffi(mbt_string_to_utf8_bytes(path, true)) == 0 else {
    raise IOError(errmsg())
  }
}

///|
#borrow(path)
extern "C" fn is_dir_ffi(path : Bytes) -> Int = "moon_guard_fs_is_dir"

///|
fn is_dir_internal(path : String) -> Bool raise IOError {
  let res = is_dir_ffi(mbt_string_to_utf8_bytes(path, true))
  guard res != -1 else { raise IOError(errmsg()) }
  res == 1
}

///|
#borrow(path)
extern "C" fn is_file_ffi(path : Bytes) -> Int = "moon_guard_fs_is_file"

///|
fn is_file_internal(path : String) -> Bool raise IOError {
  let res = is_file_ffi(mbt_string_to_utf8_bytes(path, true))
  guard res != -1 else { raise IOError(errmsg()) }
  res == 1
}

///|
#borrow(path)
extern "C" fn remove_dir_ffi(path : Bytes) -> Int = "moon_guard_fs_remove_dir"

///|
fn remove_dir_internal(path : String) -> Unit raise IOError {
  guard remove_dir_ffi(mbt_string_to_utf8_bytes(path, true)) == 0 else {
    raise IOError(errmsg())
  }
}

///|
#borrow(path)
extern "C" fn remove_file_ffi(path : Bytes) -> Int = "moon_guard_fs_remove_file"

///|
fn remove_file_internal(path : String) -> Unit raise IOError {
  guard remove_file_ffi(mbt_string_to_utf8_bytes(path, true)) == 0 else {
    raise IOError(errmsg())
  }
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
