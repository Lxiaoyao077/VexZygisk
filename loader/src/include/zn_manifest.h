#ifndef ZN_MANIFEST_H
#define ZN_MANIFEST_H

/* INFO: The zn_modules.txt reader. It lives in a header rather than next to one
         of its callers because the daemon reads the same file for two purposes -
         the plan it hands a process, and the target list it reports to the
         monitor - and because a manifest line is pure text, so the host test
         suite can exercise the whole reader without a device.

         The format is Zygisk Next's, read the way YukiZygisk's
         native_modules.hpp reads it:

             <name=|path=><target> [flags] <library>

         with `companion` the only flag defined today. Two details decide whether
         a module loads at all, and both are the reason there is one reader:

           - `companion` is a flag, not a position. It is recognised wherever it
             sits between the target and the library, and the library is the last
             token that is not a flag. Reading the library as "the last token"
             gave a manifest that wrote the flag after the library a library path
             of the literal string "companion" - a module that silently never
             loaded.
           - "${moduleId}" and "$moduleId" in the library path stand for the
             directory the manifest was read from, which is the name the root
             solution knows the module by. Neither used to be expanded, so such a
             manifest resolved to a literal file name that cannot exist.

         The caller owns the two strings it gets back. */

#include <ctype.h>
#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

/* INFO: One target, one library and room for fourteen flags. A line past that
         is not a manifest this reader understands, and it is refused rather than
         read with a silently wrong library; the bound also keeps the parse of a
         file the daemon re-reads on every fork from growing an allocation. */
#define ZN_MANIFEST_MAX_TOKENS 16

#define ZN_MANIFEST_PREFIX_LEN 5

/* INFO: Copies `token_len` bytes of `token` into `out`, replacing every
         "${moduleId}" and "$moduleId" with `module_id`, and terminates it.
         Returns false when the result does not fit, which is the caller's cue to
         drop the line: a truncated path is one that names no file. */
static inline bool zn_manifest_expand_module_id(const char *token, size_t token_len, const char *module_id,
                                                char *out, size_t out_size) {
  static const char kBraced[] = "${moduleId}";
  static const char kBare[] = "$moduleId";

  const size_t braced_len = sizeof(kBraced) - 1;
  const size_t bare_len = sizeof(kBare) - 1;
  const size_t id_len = module_id != NULL ? strlen(module_id) : 0;

  if (out_size == 0) return false;

  size_t written = 0;
  size_t index = 0;

  while (index < token_len) {
    size_t consumed = 0;

    /* INFO: The braced spelling is tested first. It also starts with '$', so a
             bare-only test would consume that character and leave "moduleId}"
             behind in the path. */
    if (index + braced_len <= token_len && strncmp(token + index, kBraced, braced_len) == 0) {
      consumed = braced_len;
    } else if (index + bare_len <= token_len && strncmp(token + index, kBare, bare_len) == 0) {
      consumed = bare_len;
    }

    if (consumed == 0) {
      if (written + 1 >= out_size) return false;

      out[written] = token[index];
      written++;
      index++;

      continue;
    }

    if (id_len + 1 > out_size - written) return false;

    if (id_len > 0) memcpy(out + written, module_id, id_len);

    written += id_len;
    index += consumed;
  }

  out[written] = '\0';

  return true;
}

/* INFO: Splits one manifest line. `module_id` is the directory name the file was
         read from, `module_dir` its full path; the library is resolved against
         the latter unless the manifest wrote it absolute. On success the caller
         receives the target with its "name="/"path=" prefix removed, which
         prefix it was, whether a companion was asked for, and the resolved
         library path. */
static inline bool zn_manifest_parse_line(const char *module_id, const char *module_dir, const char *line,
                                          bool *is_name, char **target, bool *companion, char **lib_path) {
  const char *tokens[ZN_MANIFEST_MAX_TOKENS];
  size_t lengths[ZN_MANIFEST_MAX_TOKENS];
  size_t token_count = 0;
  bool too_many = false;

  const char *cursor = line;

  for (;;) {
    while (*cursor != '\0' && isspace((unsigned char)*cursor)) cursor++;
    if (*cursor == '\0') break;

    if (token_count == ZN_MANIFEST_MAX_TOKENS) {
      too_many = true;

      break;
    }

    const char *start = cursor;
    while (*cursor != '\0' && !isspace((unsigned char)*cursor)) cursor++;

    tokens[token_count] = start;
    lengths[token_count] = (size_t)(cursor - start);

    token_count++;
  }

  if (too_many) return false;
  if (token_count < 2) return false;

  /* INFO: A bare "name=" carries nothing to match against and is refused, the
           same as a line whose first token is neither prefix. */
  if (lengths[0] > ZN_MANIFEST_PREFIX_LEN && strncmp(tokens[0], "name=", ZN_MANIFEST_PREFIX_LEN) == 0) {
    *is_name = true;
  } else if (lengths[0] > ZN_MANIFEST_PREFIX_LEN && strncmp(tokens[0], "path=", ZN_MANIFEST_PREFIX_LEN) == 0) {
    *is_name = false;
  } else {
    return false;
  }

  const size_t target_len = lengths[0] - ZN_MANIFEST_PREFIX_LEN;

  char *parsed_target = malloc(target_len + 1);
  if (parsed_target == NULL) return false;

  memcpy(parsed_target, tokens[0] + ZN_MANIFEST_PREFIX_LEN, target_len);
  parsed_target[target_len] = '\0';

  *companion = false;

  size_t library_index = 0;

  for (size_t i = 1; i < token_count; i++) {
    if (lengths[i] == 9 && strncmp(tokens[i], "companion", 9) == 0) {
      *companion = true;

      continue;
    }

    library_index = i;
  }

  /* INFO: Every token after the target was a flag, so the line names no
           library. */
  if (library_index == 0) {
    free(parsed_target);

    return false;
  }

  char expanded[PATH_MAX];
  if (!zn_manifest_expand_module_id(tokens[library_index], lengths[library_index], module_id, expanded, sizeof(expanded))) {
    free(parsed_target);

    return false;
  }

  /* INFO: Assembled with an explicit bound instead of snprintf because both
           halves are already known lengths here, and the truncation snprintf
           would have to be checked for is the one thing this cannot get away
           with doing quietly. */
  char resolved[PATH_MAX];
  size_t written;

  if (expanded[0] == '/') {
    written = strlen(expanded);
    if (written >= sizeof(resolved)) {
      free(parsed_target);

      return false;
    }

    memcpy(resolved, expanded, written + 1);
  } else {
    const size_t dir_len = strlen(module_dir);
    const size_t rel_len = strlen(expanded);

    if (dir_len + rel_len + 2 > sizeof(resolved)) {
      free(parsed_target);

      return false;
    }

    memcpy(resolved, module_dir, dir_len);
    resolved[dir_len] = '/';
    memcpy(resolved + dir_len + 1, expanded, rel_len + 1);

    written = dir_len + rel_len + 1;
  }

  char *parsed_library = malloc(written + 1);
  if (parsed_library == NULL) {
    free(parsed_target);

    return false;
  }

  memcpy(parsed_library, resolved, written + 1);

  *target = parsed_target;
  *lib_path = parsed_library;

  return true;
}

#endif /* ZN_MANIFEST_H */
