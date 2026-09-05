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

#include "../../loader/src/injector/unmount.c"

static int g_failures = 0;

#define CHECK(condition, ...)                                              \
  do {                                                                     \
    if (!(condition)) {                                                    \
      g_failures++;                                                        \
      printf("FAIL %s:%d: ", __FILE__, __LINE__);                          \
      printf(__VA_ARGS__);                                                 \
      printf("\n");                                                        \
    }                                                                      \
  } while (0)

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

  const char *path = "/tmp/vz_mountinfo_fixture";
  FILE *file = fopen(path, "w");
  CHECK(file != NULL, "cannot create fixture");
  if (file == NULL) return;

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

/* INFO: The selection feeds abort_zygote_unmount, which is the safety that
         decides whether any unmount happens at all. */
static void check_abort_refusals(void) {
  printf("-- /product abort refusals\n");

  struct mount_info entries[3];
  struct mount_list traces = { .items = entries, .len = 0, .cap = 3 };

  /* INFO: An empty trace list means "nothing to do", which is an abort. */
  CHECK(abort_zygote_unmount(&traces), "empty list must abort");

  entries[0].target = "/product/bin";
  entries[1].target = "/system";
  entries[1].root = strdup("/");
  entries[1].source = strdup("erofs");
  traces.len = 1;
  CHECK(!abort_zygote_unmount(&traces), "/product/bin alone must not abort");

  traces.items[1].target = "/product";
  traces.len = 2;
  CHECK(abort_zygote_unmount(&traces), "exact /product mount must abort");

  /* INFO: Overlays *under* /product but not /product itself are fine. */
  traces.items[1].target = "/product/overlay/lib";
  CHECK(!abort_zygote_unmount(&traces), "overlay below /product must not abort");

  free(entries[1].root);
  free(entries[1].source);
}

static void check_id_ordering(void) {
  printf("-- descending mount id ordering\n");

  struct mount_info entries[3];
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

int main(void) {
  check_parse_and_select();
  check_abort_refusals();
  check_id_ordering();

  if (g_failures == 0) {
    printf("all unmount checks passed\n");

    return 0;
  }

  printf("%d unmount check(s) failed\n", g_failures);

  return 1;
}
