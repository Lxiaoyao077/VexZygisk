/* INFO: Host-side tests for what hiding.c treats as a module trace in a maps
         listing.

         Replacing a mapping only ever happens on a device, but deciding which
         mappings to replace is pure text handling, and it is the part that
         breaks quietly: too wide and ashmem or the ART images become private
         copies, too narrow and every module library stays named. The .c is
         included so the static predicate is reachable. */

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <sys/types.h>

#include "check.h"

#include "../../loader/src/injector/hiding.c"

/* INFO: hide_module_maps() reaches the maps through these two, which live in
         the loader's common code and are never exercised here. The stubs keep
         the predicate linkable without pulling the rest of the loader in. */
struct maps_info *parse_maps_safe(const char *pid) {
  (void) pid;

  return NULL;
}

void free_maps(struct maps_info *maps) {
  (void) maps;
}

#define DATA_DEV  ((dev_t) 0x0a03)
#define OTHER_DEV ((dev_t) 0x0b04)

static bool hides(const char *path, bool is_private, dev_t map_dev) {
  struct map_entry map = {
    .start = 0x70000000,
    .end = 0x70001000,
    .perms = PROT_READ | PROT_EXEC,
    .is_private = is_private,
    .offset = 0,
    .dev = map_dev,
    .inode = 1,
    .path = (char *) path
  };

  return is_module_map(&map, DATA_DEV);
}

static void check_module_libraries(void) {
  printf("-- what a hidden process has to stop naming\n");

  CHECK(hides("/data/adb/modules/any_module/lib/libexample.so", true, DATA_DEV),
        "a module library is not hidden");
  CHECK(hides("/data/adb/modules/any_module/lib/libexample.so (deleted)", true, DATA_DEV),
        "a deleted module library is not hidden");
  CHECK(hides("/data/local/tmp/loader.so", true, DATA_DEV),
        "a library mapped from /data/local/tmp is not hidden");
  CHECK(hides(ZYGISK_ZN_MEMFD, true, DATA_DEV),
        "the Zygisk Next memfd is not hidden");
  CHECK(hides(ZYGISK_ZN_MEMFD " (deleted)", true, DATA_DEV),
        "a deleted Zygisk Next memfd is not hidden");
}

static void check_everything_else(void) {
  printf("-- what it must leave alone\n");

  CHECK(!hides(NULL, true, DATA_DEV), "an anonymous map is hidden");
  CHECK(!hides("/system/lib64/libc.so", true, DATA_DEV), "a system library is hidden");
  CHECK(!hides("/memfd:/boot-image-methods.art", true, DATA_DEV), "the ART image is hidden");
  CHECK(!hides("/data/adb/modules/any_module/lib/libexample.so", false, DATA_DEV),
        "a shared map is hidden");
  CHECK(!hides(ZYGISK_MODULE_DIR "/lib/libzygisk.so", true, DATA_DEV),
        "our own library is hidden");
  CHECK(!hides("/data/adb/modules/any_module/lib/libexample.so", true, OTHER_DEV),
        "a matching path on another device is hidden");
}

int main(void) {
  check_module_libraries();
  check_everything_else();

  if (g_failures == 0) {
    printf("all hiding checks passed\n");

    return 0;
  }

  printf("%d hiding check(s) failed\n", g_failures);

  return 1;
}
