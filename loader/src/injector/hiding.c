#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <mntent.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "hiding.h"
#include "logging.h"
#include "misc.h"
#include "zygisk_paths.h"

/* INFO: A prefix rather than a whole path: a file deleted after it was mapped
         keeps its name and only gains a " (deleted)" suffix, and which module
         owns a library makes no difference to whether it is a trace. */
#define ADB_PREFIX "/data/adb/"

/* INFO: What a hidden process has to stop naming in its own maps.

         The device decides a path: a module library only counts while it sits
         on /data, and a bind mount or an sdcard can put the same names on
         another device, where they are not ours to replace.

         The memfd is the exception, and it is checked first. A Zygisk Next
         library is copied into one to be dlopen'd at all, and a memfd is on no
         filesystem this process could hold a device number for - so the name
         is the whole of what identifies it, and it is one only this loader
         creates.

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

  if (strncmp(path, ZYGISK_ZN_MEMFD, sizeof(ZYGISK_ZN_MEMFD) - 1) == 0) return true;

  if (map->dev != data_dev) return false;

  if (strncmp(path, ZYGISK_MODULE_DIR "/", sizeof(ZYGISK_MODULE_DIR "/") - 1) == 0) return false;

  return strncmp(path, ADB_PREFIX, sizeof(ADB_PREFIX) - 1) == 0;
}

/* INFO: One mapping selected for hiding, collected while the maps stream is
         read and acted on after it has closed. A hidden process is a running
         one: replacing a mapping with mremap splits and merges the vmas the
         stream is still walking, and an entry read from a table that changed
         under its reader describes a range this code would then mprotect or
         remap blind - which is how a read-only remnant can land on memory as
         unrelated as bionic's own atexit array and take a process tree down
         with it (issue #30). */
struct hide_target {
  void *start;
  size_t size;
  int perms;
  bool made_readable;
  char *path;
};

struct hide_state {
  dev_t data_dev;
  struct hide_target *targets;
  size_t count;
  size_t capacity;
};

static bool collect_one_map(const struct map_entry *map, void *userdata) {
  struct hide_state *state = userdata;

  if (!is_module_map(map, state->data_dev)) return true;

  if (state->count == state->capacity) {
    size_t capacity = state->capacity == 0 ? 8 : state->capacity * 2;

    struct hide_target *grown = realloc(state->targets, capacity * sizeof(struct hide_target));
    if (grown == NULL) {
      PLOGE("allocate the hide list");

      return false;
    }

    state->targets = grown;
    state->capacity = capacity;
  }

  struct hide_target *target = &state->targets[state->count];

  target->start = (void *)map->start;
  target->size = map->end - map->start;
  target->perms = map->perms;
  target->made_readable = (map->perms & PROT_READ) == 0;
  target->path = strdup(map->path);

  if (target->path == NULL) {
    PLOGE("allocate the path of [%s]", map->path);

    return false;
  }

  state->count++;

  return true;
}

/* INFO: A module library that is still mapped - every one the loader abandons
         rather than unloads, and every Zygisk Next library the system linker
         holds - names its own file in /proc/self/maps. The mapping is replaced
         with an anonymous copy of the same bytes at the same address, so the
         library keeps running out of the same place and the name is gone. */
static bool hide_map(struct hide_target *target) {
  size_t size = target->size;

  void *copy = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  if (copy == MAP_FAILED) {
    PLOGE("allocate a copy of [%s]", target->path);

    return false;
  }

  /* INFO: A mapping without PROT_READ cannot be copied out of, so it is made
            readable for the duration of the copy and put back afterwards. */
  if (target->made_readable && mprotect(target->start, size, target->perms | PROT_READ) == -1) {
    PLOGE("make [%s] readable", target->path);

    munmap(copy, size);

    return false;
  }

  memcpy(copy, target->start, size);

  /* INFO: The copy receives its final permissions before it is moved into
            place. A replacement that lands with the permissions it will keep
            from its first byte needs no mprotect after the move - which is
            the window where an executable segment of a running process is
            neither executable nor writable, and where a second thread walking
            memory can find a mapping that lies about itself. */
  if (mprotect(copy, size, target->perms) == -1) {
    PLOGE("set the permissions of the copy of [%s]", target->path);

    if (target->made_readable && mprotect(target->start, size, target->perms) == -1)
      PLOGE("restore the permissions of [%s]", target->path);

    munmap(copy, size);

    return false;
  }

  if (mremap(copy, size, size, MREMAP_MAYMOVE | MREMAP_FIXED, target->start) == MAP_FAILED) {
    PLOGE("move the copy of [%s] over the original", target->path);

    munmap(copy, size);

    /* INFO: The original is still the mapping on this path, and it may still
              carry the PROT_READ added to copy it out of. */
    if (target->made_readable && mprotect(target->start, size, target->perms) == -1)
      PLOGE("restore the permissions of [%s]", target->path);

    return false;
  }

  LOGD("Hid [%s]", target->path);

  return true;
}

bool hide_module_maps(void) {
  struct stat data;
  if (stat("/data", &data) == -1) {
    PLOGE("stat /data");

    return false;
  }

  struct hide_state state = { .data_dev = data.st_dev };

  /* INFO: The safe variant, as everywhere else in the loader: reading this
            process's own maps directly would leave a fresh access time on the
            file for the application to find. */
  if (!scan_maps_safe("self", collect_one_map, &state)) {
    LOGE("Failed to read the maps of this process");

    return false;
  }

  /* INFO: Nothing is hidden until the stream has closed and the child reading
            the maps is gone: the entries above were collected from a table
            that was still whole, and acting on them now cannot race the
            reader that produced them. */
  size_t maps = 0;
  size_t bytes = 0;

  for (size_t i = 0; i < state.count; i++) {
    struct hide_target *target = &state.targets[i];

    if (hide_map(target)) {
      maps++;
      bytes += target->size;
    }

    free(target->path);
  }

  free(state.targets);

  if (maps > 0) LOGD("Hid %zu module map(s), %zu KiB", maps, bytes / 1024);

  return true;
}

/* INFO: bionic parses a mount table one line at a time into a single static
         buffer, and whatever that buffer held when the zygote forked is what
         every application inherits - read while the zygote still carried the
         module mounts, so a process whose mount tree was cleaned afterwards
         can still read them straight out of its own libc. No mount operation
         reaches that buffer; the only way to replace its content is to parse a
         mount table here, which leaves the last line of it behind. Specialize
         time is when the tree is already the cleaned one, and it is before the
         application gets to observe the buffer in any other state. */
bool refresh_mount_line(void) {
  FILE *mounts = setmntent("/proc/self/mounts", "r");
  if (mounts == NULL) {
    PLOGE("open /proc/self/mounts");

    return false;
  }

  size_t lines = 0;
  while (getmntent(mounts) != NULL) lines++;

  endmntent(mounts);

  if (lines == 0) {
    LOGE("/proc/self/mounts has no entries");

    return false;
  }

  return true;
}
