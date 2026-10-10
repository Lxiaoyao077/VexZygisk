/* INFO: Host-side tests for the zn_modules.txt reader.

         A manifest line is pure text, and every part of it that goes wrong goes
         wrong quietly on a device: a library that resolves to a name no file has
         is a module that simply never loads, with nothing in the log to say why.
         The reader is a header, so it is read here on its own - no device, no
         daemon, and the two details that decide whether a module loads at all
         (the ${moduleId} expansion and where `companion` may sit) are asserted
         directly. */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "check.h"
#include "zn_manifest.h"

#define MODULE_ID  "my_zn_module"
#define MODULE_DIR "/data/adb/modules/" MODULE_ID

static void check_relative_library(const char *line, const char *want_lib) {
  bool is_name = false;
  bool companion = false;
  char *target = NULL;
  char *lib_path = NULL;

  CHECK(zn_manifest_parse_line(MODULE_ID, MODULE_DIR, line, &is_name, &target, &companion, &lib_path),
        "line %s was refused", line);

  if (lib_path != NULL) CHECK(strcmp(lib_path, want_lib) == 0, "line %s -> %s, wanted %s", line, lib_path, want_lib);
  if (target != NULL) CHECK(strcmp(target, "com.example.app") == 0, "line %s -> target %s", line, target);
  CHECK(is_name, "line %s lost its name= prefix", line);
  CHECK(!companion, "line %s asked for no companion", line);

  free(target);
  free(lib_path);
}

/* INFO: The line a Zygisk Next manifest writes most often: a name target and a
         library relative to the module directory. */
static void check_plain_line(void) {
  check_relative_library("name=com.example.app lib64/libexample.so", MODULE_DIR "/lib64/libexample.so");
}

/* INFO: An absolute library stays absolute; the module directory is not glued
         in front of it. */
static void check_absolute_library(void) {
  bool is_name = false;
  bool companion = false;
  char *target = NULL;
  char *lib_path = NULL;

  CHECK(zn_manifest_parse_line(MODULE_ID, MODULE_DIR, "path=/system/bin/app_process64 /data/local/lib.so",
                               &is_name, &target, &companion, &lib_path), "absolute line refused");
  CHECK(!is_name, "path= was read as a name target");
  CHECK(target != NULL && strcmp(target, "/system/bin/app_process64") == 0, "path target came back as %s",
        target != NULL ? target : "(null)");
  CHECK(lib_path != NULL && strcmp(lib_path, "/data/local/lib.so") == 0, "absolute library came back as %s",
        lib_path != NULL ? lib_path : "(null)");

  free(target);
  free(lib_path);
}

/* INFO: Both spellings of the module id placeholder, including one that uses
         each of them twice, and one where the id is longer than the placeholder
         it replaces. */
static void check_module_id_expansion(void) {
  check_relative_library("name=com.example.app ${moduleId}.so", MODULE_DIR "/" MODULE_ID ".so");
  check_relative_library("name=com.example.app $moduleId/lib.so", MODULE_DIR "/" MODULE_ID "/lib.so");
  check_relative_library("name=com.example.app ${moduleId}/$moduleId.so",
                         MODULE_DIR "/" MODULE_ID "/" MODULE_ID ".so");
  check_relative_library("name=com.example.app lib/${moduleId}-asan.so",
                         MODULE_DIR "/lib/" MODULE_ID "-asan.so");
}

/* INFO: `companion` is a flag, not a position. Both orders have to resolve to
         the same library - reading the last token as the library, which the
         reader used to do, turned the second one into the literal string
         "companion" and the module never loaded. */
static void check_companion_position(void) {
  static const char *lines[] = {
    "name=com.example.app companion lib64/libexample.so",
    "name=com.example.app lib64/libexample.so companion",
  };

  for (size_t i = 0; i < sizeof(lines) / sizeof(lines[0]); i++) {
    bool is_name = false;
    bool companion = false;
    char *target = NULL;
    char *lib_path = NULL;

    CHECK(zn_manifest_parse_line(MODULE_ID, MODULE_DIR, lines[i], &is_name, &target, &companion, &lib_path),
          "line %s was refused", lines[i]);
    CHECK(companion, "line %s did not report a companion", lines[i]);
    CHECK(lib_path != NULL && strcmp(lib_path, MODULE_DIR "/lib64/libexample.so") == 0,
          "line %s -> %s", lines[i], lib_path != NULL ? lib_path : "(null)");

    free(target);
    free(lib_path);
  }

  /* INFO: A manifest with no companion flag must not report one, and the
           library still resolves. */
  check_relative_library("name=com.example.app lib64/libexample.so", MODULE_DIR "/lib64/libexample.so");
}

/* INFO: Lines no reader can use. Each of them used to be accepted, or accepted
         with a wrong answer, which is why they are asserted here. */
static void check_refused_lines(void) {
  static const char *lines[] = {
    "",                                  /* empty */
    "   \t ",                            /* whitespace only */
    "# a comment",                       /* a comment */
    "com.example.app lib.so",            /* no name=/path= prefix */
    "name=",                             /* a prefix and nothing else */
    "name=com.example.app",              /* no library */
    "name=com.example.app companion",    /* only a flag where a library belongs */
    "path=com.example.app",              /* a path target and no library */
  };

  for (size_t i = 0; i < sizeof(lines) / sizeof(lines[0]); i++) {
    bool is_name = false;
    bool companion = false;
    char *target = NULL;
    char *lib_path = NULL;
    bool accepted = zn_manifest_parse_line(MODULE_ID, MODULE_DIR, lines[i], &is_name, &target, &companion, &lib_path);

    CHECK(!accepted, "line \"%s\" was accepted", lines[i]);

    free(target);
    free(lib_path);
  }
}

/* INFO: A line with more tokens than the reader holds is refused rather than
         read with a library that is not the one the manifest named: twenty
         tokens, where the library is the last. */
static void check_token_overflow(void) {
  static const char *line =
    "name=com.example.app f0 f1 f2 f3 f4 f5 f6 f7 f8 f9 f10 f11 f12 f13 f14 f15 f16 f17 lib.so";

  bool is_name = false;
  bool companion = false;
  char *target = NULL;
  char *lib_path = NULL;

  CHECK(!zn_manifest_parse_line(MODULE_ID, MODULE_DIR, line, &is_name, &target, &companion, &lib_path),
        "an overlong line was accepted");

  free(target);
  free(lib_path);
}

/* INFO: The expansion is a copy with a bound, and the bound is what refuses a
         line instead of handing back a truncated path. */
static void check_expansion_bound(void) {
  char small[8] = { 0 };

  CHECK(zn_manifest_expand_module_id("abc", 3, "id", small, sizeof(small)), "short expansion refused");
  CHECK(strcmp(small, "abc") == 0, "short expansion -> %s", small);

  CHECK(!zn_manifest_expand_module_id("abcdefgh", 8, "id", small, sizeof(small)), "an overflowing copy was accepted");
  CHECK(!zn_manifest_expand_module_id("$moduleId", 9, "muchlongerid", small, sizeof(small)),
        "an overflowing substitution was accepted");
  CHECK(!zn_manifest_expand_module_id("abc", 3, "id", small, 0), "a zero-sized buffer was accepted");
}

int main(void) {
  check_plain_line();
  check_absolute_library();
  check_module_id_expansion();
  check_companion_position();
  check_refused_lines();
  check_token_overflow();
  check_expansion_bound();

  if (g_failures == 0) {
    printf("all zn manifest checks passed\n");

    return 0;
  }

  printf("%d zn manifest check(s) failed\n", g_failures);

  return 1;
}
