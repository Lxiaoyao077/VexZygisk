#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <mntent.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "hiding.h"
#include "logging.h"
#include "misc.h"
#include "zygisk_paths.h"

/* INFO: Prefixes rather than whole paths: a file deleted after it was mapped
         keeps its name and only gains a " (deleted)" suffix, and which module
         owns a library makes no difference to whether it is a trace. */
#define ADB_PREFIX "/data/adb/"
#define TMP_PREFIX "/data/local/tmp/"

/* INFO: What a hidden process has to stop naming in its own maps.

         The device matters: a matching path is only a module library while it
         sits on /data, and a bind mount or an sdcard can put the same names
         on another device, where they are not ours to replace.

         Shared mappings are left alone. They are how a process reaches ashmem
         and the ART images, and turning one into a private copy would leave
         it holding a stale view of someone else's memory.

         Our own library is skipped: the unloader unmaps it once specialization
         ends, so nothing of it is left to name by then - and replacing the
         mapping this code runs from would be a risk taken for nothing. */
static bool is_module_map(const struct map_entry *map, dev_t data_dev) {
  const char *path = map->path;

  if (path == NULL) return false;

  if (!map->is_private) return false;

  if (map->dev != data_dev) return false;

  if (strncmp(path, ZYGISK_MODULE_DIR "/", sizeof(ZYGISK_MODULE_DIR "/") - 1) == 0) return false;

  if (strncmp(path, ADB_PREFIX, sizeof(ADB_PREFIX) - 1) == 0) return true;
  if (strncmp(path, TMP_PREFIX, sizeof(TMP_PREFIX) - 1) == 0) return true;

  return strncmp(path, ZYGISK_ZN_MEMFD, sizeof(ZYGISK_ZN_MEMFD) - 1) == 0;
}

/* INFO: A module library that is still mapped - every one the loader abandons
         rather than unloads, and every Zygisk Next library the system linker
         holds - names its own file in /proc/self/maps. The mapping is replaced
         with an anonymous copy of the same bytes at the same address, so the
         library keeps running out of the same place and the name is gone. */
static bool hide_map(const struct map_entry *map) {
  size_t size = map->end - map->start;

  void *copy = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  if (copy == MAP_FAILED) {
    PLOGE("allocate a copy of [%s]", map->path);

    return false;
  }

  /* INFO: A mapping without PROT_READ cannot be copied out of, so it is made
            readable for the duration of the copy and put back afterwards. */
  if ((map->perms & PROT_READ) == 0 &&
      mprotect((void *)map->start, size, map->perms | PROT_READ) == -1) {
    PLOGE("make [%s] readable", map->path);

    munmap(copy, size);

    return false;
  }

  memcpy(copy, (void *)map->start, size);

  if (mremap(copy, size, size, MREMAP_MAYMOVE | MREMAP_FIXED, (void *)map->start) == MAP_FAILED) {
    PLOGE("move the copy of [%s] over the original", map->path);

    munmap(copy, size);

    return false;
  }

  if (mprotect((void *)map->start, size, map->perms) == -1) {
    PLOGE("restore the permissions of [%s]", map->path);

    return false;
  }

  LOGD("Hid [%s]", map->path);

  return true;
}

bool hide_module_maps(void) {
  struct stat data;
  if (stat("/data", &data) == -1) {
    PLOGE("stat /data");

    return false;
  }

  /* INFO: The safe variant, as everywhere else in the loader: reading this
            process's own maps directly would leave a fresh access time on the
            file for the application to find. */
  struct maps_info *maps = parse_maps_safe("self");
  if (maps == NULL) {
    LOGE("Failed to read the maps of this process");

    return false;
  }

  size_t hidden = 0;
  for (size_t i = 0; i < maps->length; i++) {
    const struct map_entry *map = &maps->maps[i];

    if (is_module_map(map, data.st_dev) && hide_map(map)) hidden++;
  }

  free_maps(maps);

  if (hidden > 0) LOGD("Hid %zu module map(s)", hidden);

  return true;
}
