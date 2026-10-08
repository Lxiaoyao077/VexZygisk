/* INFO: Host-side tests for the zygote revert logic in unmount.c.

   The unmount itself can never run here, but everything that decides what
   would be unmounted is pure text handling: parsing /proc/self/mountinfo,
   picking the root traces out of it, and refusing the /product cases. That is
   exactly the part that breaks when a mountinfo layout changes, and it is now
   exercised with fixtures instead of relying on a device.

   The .c is included rather than linked so the static helpers are reachable;
   mount_list_parse takes a path, so a fixture file stands in for the real
   mountinfo. */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "check.h"

#include "../../loader/src/injector/unmount.c"

/* INFO: Path to the file the static assertions below read. Relative to the
         repository root, which is where the host test suite is invoked from
         on CI; a missing file only fails the checks that read it. */
#define UNMOUNT_SOURCE_PATH "loader/src/injector/unmount.c"

/* INFO: Reads UNMOUNT_SOURCE_PATH into a heap buffer, or NULL when it cannot
         be read. The caller frees it. */
static char *read_unmount_source(void) {
  FILE *file = fopen(UNMOUNT_SOURCE_PATH, "re");
  if (file == NULL) return NULL;

  size_t capacity = 4096;
  size_t length = 0;
  char *buffer = malloc(capacity);
  if (buffer == NULL) {
    fclose(file);

    return NULL;
  }

  size_t read;
  while ((read = fread(buffer + length, 1, capacity - length - 1, file)) > 0) {
    length += read;

    if (length + 1 >= capacity) {
      capacity *= 2;

      char *grown = realloc(buffer, capacity);
      if (grown == NULL) {
        free(buffer);
        fclose(file);

        return NULL;
      }

      buffer = grown;
    }
  }

  buffer[length] = '\0';

  fclose(file);

  return buffer;
}

/* INFO: True when any *code* line of `source` contains `needle`. Block
         comments and single-line comments are tracked and skipped, because the
         revert explains in prose why a hard umount is wrong: a whole-file
         search would match that explanation and flag the very call the check
         exists to catch. Only the first needle per line is considered, which is
         enough for a source scan. */
static bool code_line_contains(const char *source, const char *needle) {
  size_t needle_len = strlen(needle);
  const char *cursor = source;
  bool in_block_comment = false;

  while (*cursor != '\0') {
    const char *line_end = strchr(cursor, '\n');
    size_t line_len = line_end != NULL ? (size_t)(line_end - cursor) : strlen(cursor);

    bool line_is_comment = in_block_comment;

    for (size_t i = 0; i < line_len; i++) {
      if (in_block_comment) {
        if (cursor[i] == '*' && i + 1 < line_len && cursor[i + 1] == '/') {
          in_block_comment = false;

          i++;
        }

        continue;
      }

      if (cursor[i] == '/' && i + 1 < line_len && cursor[i + 1] == '/') {
        line_is_comment = true;

        break;
      }

      if (cursor[i] == '/' && i + 1 < line_len && cursor[i + 1] == '*') {
        in_block_comment = true;
        line_is_comment = true;

        i++;

        continue;
      }

      if (!line_is_comment && needle_len > 0 && i + needle_len <= line_len &&
          strncmp(cursor + i, needle, needle_len) == 0) {
        return true;
      }
    }

    if (line_end == NULL) break;

    cursor = line_end + 1;
  }

  return false;
}

/* INFO: A KernelSU-shaped mountinfo: the modules live on a loop device and
         every module overlay carries the loop name as its source, while the
         overlay root keeps the /adb/modules prefix. */
static const char kKsuMountinfo[] =
    "1 0 8:3 / / rw - rootfs rootfs rw\n"
    "36 1 7:0 / /system ro - erofs erofs ro\n"
    "47 36 0:31 / /vendor ro - erofs erofs ro\n"
    "14 36 0:42 / /data/adb/modules rw - overlay /dev/block/loop14 rw\n"
    "15 14 0:42 /adb/modules/zygisk_test /data/adb/modules/zygisk_test/zygisk rw - overlay /dev/block/loop14 rw\n"
    "16 14 0:42 /adb/modules/violet /data/adb/modules/violet rw - overlay /dev/block/loop14 rw\n"
    "18 36 0:29 / /mnt/passage rw - tmpfs tmpfs rw\n";

static void check_parse_and_select(void) {
  printf("-- mountinfo parse and selection\n");

  /* INFO: mkstemp keeps the fixture out of any fixed location: the test has
           to run on the CI host and just as well on a Windows checkout,
           where a hard-coded /tmp path only exists by Git Bash accident. */
  char path[] = "vz_mountinfo_fixtureXXXXXX";
  int fixture_fd = mkstemp(path);
  CHECK(fixture_fd != -1, "cannot create fixture");
  if (fixture_fd == -1) return;

  FILE *file = fdopen(fixture_fd, "w");
  CHECK(file != NULL, "cannot open fixture stream");
  if (file == NULL) {
    close(fixture_fd);
    remove(path);

    return;
  }

  fputs(kKsuMountinfo, file);
  fclose(file);

  struct mount_list all = { 0 };
  CHECK(mount_list_parse(path, &all), "mount_list_parse failed");
  CHECK(all.len == 7, "expected 7 parsed entries, got %zu", all.len);
  if (all.len == 7) {
    /* INFO: The second section of each line must have been split off
             correctly, or the sources would carry the fs options. */
    CHECK(strcmp(all.items[4].target, "/data/adb/modules/zygisk_test/zygisk") == 0,
          "target misparsed: %s", all.items[4].target);
    CHECK(strcmp(all.items[4].source, "/dev/block/loop14") == 0,
          "source misparsed: %s", all.items[4].source);
    CHECK(strcmp(all.items[6].source, "tmpfs") == 0,
          "source misparsed: %s", all.items[6].source);
  }

  const char *loop_source = find_module_loop_source(&all);
#ifndef ROOT_IMPL_APATCH
  CHECK(loop_source != NULL && strcmp(loop_source, "/dev/block/loop14") == 0,
        "loop source not detected, got %s", loop_source ? loop_source : "(null)");

  CHECK(carries_root_trace(&all.items[4], loop_source), "module overlay not selected");
  CHECK(carries_root_trace(&all.items[5], loop_source), "second module overlay not selected");
#else
  /* INFO: The APatch flavour skips the loop probe, so the module overlays
           are matched purely by their /adb/modules root. */
  CHECK(loop_source == NULL, "APatch flavour must not probe loop devices");
  CHECK(carries_root_trace(&all.items[4], NULL), "module overlay not selected");
#endif
  CHECK(!carries_root_trace(&all.items[1], loop_source), "/system falsely selected");
  CHECK(carries_root_trace(&all.items[3], loop_source), "modules dir overlay not selected");
  CHECK(!carries_root_trace(&all.items[6], loop_source), "tmpfs mount falsely selected");

  mount_list_free(&all);
  remove(path);
}

/* INFO: A metamodule overlay carries the root solution's source name and may
         cover system paths, so the selection picks it up no matter which path
         it sits on. That is intended - the hiding is the mount *detach*, not a
         narrower selection - but it is exactly the case that used to break
         WebView when the detach was a hard umount. Both halves are asserted
         here: the overlay is selected, and reverting it never escalates to an
         unmount that would tear the underlying filesystem down. */
static void check_system_covering_overlay(void) {
  printf("-- module overlay over system paths\n");

  char path[] = "vz_overlay_fixtureXXXXXX";
  int fixture_fd = mkstemp(path);
  CHECK(fixture_fd != -1, "cannot create overlay fixture");
  if (fixture_fd == -1) return;

  FILE *file = fdopen(fixture_fd, "w");
  CHECK(file != NULL, "cannot open overlay fixture stream");
  if (file == NULL) {
    close(fixture_fd);
    remove(path);

    return;
  }

  /* INFO: The overlay a metamodule hangs below /system carries the root
           solution's own source name, which is all the selection looks at.
           The fixture is built from the flavour's own name so the KernelSU and
           APatch builds both exercise the branch they ship. */
  fprintf(file,
          "36 1 7:0 / /system ro - erofs erofs ro\n"
          "41 36 0:52 /framework /system/framework ro - overlay %s ro\n"
          "42 36 0:52 /lib64 /system/lib64 ro - overlay %s ro\n",
          kRootSources[0], kRootSources[0]);
  fclose(file);

  struct mount_list all = { 0 };
  CHECK(mount_list_parse(path, &all), "overlay fixture did not parse");
  CHECK(all.len == 3, "expected 3 overlay entries, got %zu", all.len);
  if (all.len == 3) {
    CHECK(carries_root_trace(&all.items[1], NULL), "framework overlay not selected");
    CHECK(carries_root_trace(&all.items[2], NULL), "lib64 overlay not selected");
  }

  mount_list_free(&all);
  remove(path);
}

/* INFO: The revert must stay a detach. A hard umount2(target, 0) is what
         removed the framework and provider overlays for real and left WebView
         unable to initialize, so the call shape is pinned here rather than
         left to review. */
static void check_revert_stays_detached(void) {
  printf("-- revert uses a lazy detach\n");

  char *source = read_unmount_source();
  CHECK(source != NULL, "cannot read " UNMOUNT_SOURCE_PATH);
  if (source == NULL) return;

  CHECK(code_line_contains(source, "umount2(target, 0)") == false,
        "revert must not escalate to a hard umount");
  CHECK(code_line_contains(source, "umount2(target, MNT_DETACH)") == true,
        "revert must detach the mount");

  free(source);
}

/* INFO: The selection feeds abort_zygote_unmount, which is the safety that
         decides whether any unmount happens at all. */
static void check_abort_refusals(void) {
  printf("-- /product abort refusals\n");

  struct mount_info entries[3] = { 0 };
  struct mount_list traces = { .items = entries, .len = 0, .cap = 3 };

  /* INFO: An empty trace list means "nothing to do", which is an abort. */
  CHECK(abort_zygote_unmount(&traces), "empty list must abort");

  entries[0].target = "/product/bin";
  entries[1].target = "/system";
  traces.len = 1;
  CHECK(!abort_zygote_unmount(&traces), "/product/bin alone must not abort");

  traces.items[1].target = "/product";
  traces.len = 2;
  CHECK(abort_zygote_unmount(&traces), "exact /product mount must abort");

  /* INFO: Overlays *under* /product but not /product itself are fine. */
  traces.items[1].target = "/product/overlay/lib";
  CHECK(!abort_zygote_unmount(&traces), "overlay below /product must not abort");
}

static void check_id_ordering(void) {
  printf("-- descending mount id ordering\n");

  struct mount_info entries[3] = { 0 };
  struct mount_list traces = { .items = entries, .len = 3, .cap = 3 };

  for (size_t i = 0; i < 3; i++) {
    traces.items[i].id = (unsigned int)(1 + 2 * i);
    traces.items[i].target = NULL;
    traces.items[i].root = NULL;
    traces.items[i].source = NULL;
  }

  qsort(traces.items, traces.len, sizeof(struct mount_info), compare_by_id_descending);

  CHECK(traces.items[0].id == 5 && traces.items[1].id == 3 && traces.items[2].id == 1,
        "not sorted by descending id: %u %u %u",
        traces.items[0].id, traces.items[1].id, traces.items[2].id);
}

/* INFO: The boundary rule a trace path is selected by lives in root_mounts.h,
         now shared by the loader and the daemon instead of written out in each.
         Pinned here because both sides decide from it what a process loses: a
         prefix that matches one byte too many would revert a sibling directory
         such as /data/adb/modules_extra, and one that matches one too few would
         leave the module mounts of a real installation behind. */
static void check_path_boundaries(void) {
  printf("-- trace path boundaries\n");

  CHECK(mount_path_at_or_under(ROOT_MODULES_DIR, ROOT_MODULES_DIR),
        "the prefix itself must match");

  CHECK(mount_path_at_or_under("/data/adb/modules/violet/system", ROOT_MODULES_DIR),
        "a path below the prefix must match");

  CHECK(mount_path_at_or_under("/adb/modules/violet", ROOT_MODULES_ROOT),
        "a module root below the prefix must match");

  CHECK(!mount_path_at_or_under("/data/adb/modules_extra", ROOT_MODULES_DIR),
        "a sibling sharing the prefix text must not match");

  CHECK(!mount_path_at_or_under("/adb/modules_backup/violet", ROOT_MODULES_ROOT),
        "a sibling below a longer name must not match");

  CHECK(!mount_path_at_or_under("/system", ROOT_MODULES_DIR),
        "an unrelated path must not match");
}

int main(void) {
  check_parse_and_select();
  check_system_covering_overlay();
  check_abort_refusals();
  check_id_ordering();
  check_path_boundaries();
  check_revert_stays_detached();

  if (g_failures == 0) {
    printf("all unmount checks passed\n");

    return 0;
  }

  printf("%d unmount check(s) failed\n", g_failures);

  return 1;
}
