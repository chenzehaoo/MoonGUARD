// C shim backing the native/llvm backend of `moon_guard/lib/fs`.
// Self-contained port of the `moonbitlang/x/fs` native stub, renamed to
// `moon_guard_fs_*` and stripped of third-party imports.

#ifdef __cplusplus
extern "C" {
#endif

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#ifdef _WIN32
#include <direct.h>
#include <windows.h>
#else
#include <dirent.h>
#include <unistd.h>
#endif

#include "moonbit.h"

MOONBIT_FFI_EXPORT FILE *moon_guard_fs_fopen(moonbit_bytes_t path,
                                             moonbit_bytes_t mode) {
  return fopen((const char *)path, (const char *)mode);
}

MOONBIT_FFI_EXPORT int moon_guard_fs_is_null(void *ptr) {
  return ptr == NULL;
}

MOONBIT_FFI_EXPORT size_t moon_guard_fs_fread(moonbit_bytes_t ptr, int size,
                                              int nitems, FILE *stream) {
  return fread(ptr, size, nitems, stream);
}

MOONBIT_FFI_EXPORT size_t moon_guard_fs_fwrite(moonbit_bytes_t ptr, int size,
                                               int nitems, FILE *stream) {
  return fwrite(ptr, size, nitems, stream);
}

MOONBIT_FFI_EXPORT int moon_guard_fs_fseek(FILE *stream, long offset,
                                           int whence) {
  return fseek(stream, offset, whence);
}

MOONBIT_FFI_EXPORT long moon_guard_fs_ftell(FILE *stream) {
  return ftell(stream);
}

MOONBIT_FFI_EXPORT int moon_guard_fs_fflush(FILE *file) {
  return fflush(file);
}

MOONBIT_FFI_EXPORT int moon_guard_fs_fclose(FILE *stream) {
  return fclose(stream);
}

MOONBIT_FFI_EXPORT moonbit_bytes_t moon_guard_fs_get_error_message(void) {
  const char *err_str = strerror(errno);
  size_t len = strlen(err_str);
  moonbit_bytes_t bytes = moonbit_make_bytes(len, 0);
  memcpy(bytes, err_str, len);
  return bytes;
}

MOONBIT_FFI_EXPORT int moon_guard_fs_stat(moonbit_bytes_t path) {
  struct stat buffer;
  return stat((const char *)path, &buffer);
}

MOONBIT_FFI_EXPORT int moon_guard_fs_is_dir(moonbit_bytes_t path) {
#ifdef _WIN32
  DWORD attrs = GetFileAttributes((const char *)path);
  if (attrs == INVALID_FILE_ATTRIBUTES) {
    return -1;
  }
  return (attrs & FILE_ATTRIBUTE_DIRECTORY) ? 1 : 0;
#else
  struct stat buffer;
  int status = stat((const char *)path, &buffer);
  if (status == -1) {
    return -1;
  }
  return S_ISDIR(buffer.st_mode) ? 1 : 0;
#endif
}

MOONBIT_FFI_EXPORT int moon_guard_fs_is_file(moonbit_bytes_t path) {
#ifdef _WIN32
  DWORD attrs = GetFileAttributes((const char *)path);
  if (attrs == INVALID_FILE_ATTRIBUTES) {
    return -1;
  }
  return (attrs & FILE_ATTRIBUTE_DIRECTORY) ? 0 : 1;
#else
  struct stat buffer;
  int status = stat((const char *)path, &buffer);
  if (status == -1) {
    return -1;
  }
  return S_ISREG(buffer.st_mode) ? 1 : 0;
#endif
}

MOONBIT_FFI_EXPORT int moon_guard_fs_remove_dir(moonbit_bytes_t path) {
#ifdef _WIN32
  return _rmdir((const char *)path);
#else
  return rmdir((const char *)path);
#endif
}

MOONBIT_FFI_EXPORT int moon_guard_fs_remove_file(moonbit_bytes_t path) {
  return remove((const char *)path);
}

MOONBIT_FFI_EXPORT int moon_guard_fs_create_dir(moonbit_bytes_t path) {
#ifdef _WIN32
  return _mkdir((const char *)path);
#else
  return mkdir((const char *)path, 0777);
#endif
}

MOONBIT_FFI_EXPORT moonbit_bytes_t *moon_guard_fs_read_dir(moonbit_bytes_t path) {
#ifdef _WIN32
  WIN32_FIND_DATA find_data;
  HANDLE dir;
  moonbit_bytes_t *result = NULL;
  int count = 0;

  size_t path_len = strlen((const char *)path);
  char *search_path = malloc(path_len + 3);
  if (search_path == NULL) {
    return NULL;
  }

  sprintf(search_path, "%s\\*", (const char *)path);
  dir = FindFirstFile(search_path, &find_data);
  if (dir == INVALID_HANDLE_VALUE) {
    free(search_path);
    return NULL;
  }

  do {
    if (strcmp(find_data.cFileName, ".") != 0 &&
        strcmp(find_data.cFileName, "..") != 0) {
      count++;
    }
  } while (FindNextFile(dir, &find_data));

  FindClose(dir);
  dir = FindFirstFile(search_path, &find_data);
  free(search_path);

  result = (moonbit_bytes_t *)moonbit_make_ref_array(count, NULL);
  if (result == NULL) {
    FindClose(dir);
    return NULL;
  }

  int index = 0;
  do {
    if (strcmp(find_data.cFileName, ".") != 0 &&
        strcmp(find_data.cFileName, "..") != 0) {
      size_t name_len = strlen(find_data.cFileName);
      moonbit_bytes_t item = moonbit_make_bytes(name_len, 0);
      memcpy(item, find_data.cFileName, name_len);
      result[index++] = item;
    }
  } while (FindNextFile(dir, &find_data));

  FindClose(dir);
  return result;
#else
  DIR *dir;
  struct dirent *entry;
  moonbit_bytes_t *result = NULL;
  int count = 0;

  dir = opendir((const char *)path);
  if (dir == NULL) {
    return NULL;
  }

  while ((entry = readdir(dir)) != NULL) {
    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
      continue;
    }
    count++;
  }

  rewinddir(dir);

  result = (moonbit_bytes_t *)moonbit_make_ref_array(count, NULL);
  if (result == NULL) {
    closedir(dir);
    return NULL;
  }

  int index = 0;
  while ((entry = readdir(dir)) != NULL) {
    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
      continue;
    }
    size_t name_len = strlen(entry->d_name);
    moonbit_bytes_t item = moonbit_make_bytes(name_len, 0);
    memcpy(item, entry->d_name, name_len);
    result[index++] = item;
  }

  closedir(dir);
  return result;
#endif
}

#ifdef __cplusplus
}
#endif
