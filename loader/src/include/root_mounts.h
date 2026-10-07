#ifndef ROOT_MOUNTS_H
#define ROOT_MOUNTS_H

/* INFO: What counts as a root trace in a mount table, shared by the loader
         (injector/unmount.c, which reverts them in the hidden process) and the
         daemon (utils.c, which builds the clean namespace). Both walk the same
         /proc/<pid>/mountinfo and must remove the same set; a name added on one
         side alone would leave them disagreeing and a process half hidden. The
         walk itself stays per-binary, since only the loader needs the mount id. */

#include <stdbool.h>
#include <string.h>

#define MOUNT_SOURCE_LOOP "/dev/block/loop"
#define ROOT_MODULES_DIR "/data/adb/modules"
#define ROOT_MODULES_ROOT "/adb/modules"

/* INFO: The system partitions a magic mount may cover. An overlay rooted in
         one of these is what a mount detector reads as "the module system has
         rewritten the system partition", so they are handled apart from the
         rest: unmounting them for real takes the framework's own view of
         /system with it, and every provider resource resolved through one
         stops existing for the process.

         The prefix test is deliberately on a path component boundary, so
         /systemless is not read as /system. */
static const char *const kSystemPartitions[] = {
  "/system",
  "/system_ext",
  "/product",
  "/vendor",
  "/odm",
};
#define SYSTEM_PARTITION_COUNT (sizeof(kSystemPartitions) / sizeof(kSystemPartitions[0]))

static inline bool root_mounts_is_system_partition(const char *path, const char *prefix) {
  size_t len = strlen(prefix);

  if (strncmp(path, prefix, len) != 0) return false;

  char next = path[len];

  return next == '\0' || next == '/';
}

/* INFO: True when a magic mount covers a system partition, which is what a
         detector reads as the module system having rewritten the system.
         Shared so the loader and the daemon cannot disagree on the set and end
         up reverting different mounts from the same table. */
static inline bool mount_path_on_system_partition(const char *path) {
  for (size_t i = 0; i < SYSTEM_PARTITION_COUNT; i++) {
    if (root_mounts_is_system_partition(path, kSystemPartitions[i])) return true;
  }

  return false;
}

/* INFO: Overlay sources each root solution reports: KernelSU mounts as "KSU"
         and APatch, being KernelPatch based, as "APatch" or "kpatch". The
         flavour is fixed at build time, so only the matching names are
         compiled in. */
#ifdef ROOT_IMPL_APATCH
  static const char *const kRootSources[] = { "APatch", "kpatch" };
  #define ROOT_SOURCE_COUNT 2
#else
  static const char *const kRootSources[] = { "KSU" };
  #define ROOT_SOURCE_COUNT 1
#endif

#endif /* ROOT_MOUNTS_H */
