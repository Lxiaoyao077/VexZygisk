#include <stdlib.h>
#include <string.h>

#include <errno.h>
#include <stdio.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>

#include "logging.h"

#include "root_mounts.h"
#include "unmount.h"
#include "zygisk_paths.h"

#define PRODUCT_MOUNT "/product"

/* INFO: The fields of one /proc/<pid>/mountinfo line. Only what the trace
         selection and the unmount actually need is kept. */
struct mount_info {
  unsigned int id;
  char *root;
  char *target;
  char *source;
};

struct mount_list {
  struct mount_info *items;
  size_t len;
  size_t cap;
};

static void mount_list_free(struct mount_list *list) {
  for (size_t i = 0; i < list->len; i++) {
    free(list->items[i].root);
    free(list->items[i].target);
    free(list->items[i].source);
  }

  free(list->items);

  list->items = NULL;
  list->len = 0;
  list->cap = 0;
}

static bool mount_list_reserve(struct mount_list *list, size_t wanted) {
  if (list->cap >= wanted) return true;

  size_t cap = list->cap ? list->cap * 2 : 16;
  if (cap < wanted) cap = wanted;

  struct mount_info *items = realloc(list->items, cap * sizeof(struct mount_info));
  if (items == NULL) {
    LOGE("Failed growing the mount list to %zu entries", cap);

    return false;
  }

  list->items = items;
  list->cap = cap;

  return true;
}

/* INFO: One mountinfo line, split on the " - " separator, which is the only
         delimiter that cannot appear inside a field. The separator is cut in
         place so the head is never copied into a fixed buffer — long paths
         used to be dropped as "oversized" and their mounts silently skipped:

           36 35 98:0 /root /target rw,... - type source rw,...

         The mount id has to be parsed out because nested mounts only come
         down in the reverse order of their ids. */
static bool mount_info_parse(char *line, struct mount_info *out) {
  char *separator = strstr(line, " - ");
  if (separator == NULL) {
    LOGV("Skipping malformed mountinfo line (no separator)");

    return false;
  }

  *separator = '\0';

  /* INFO: The parent id and the "major:minor" device are skipped, nothing
            here needs them. */
  unsigned int id = 0;
  char root[4096], target[4096], source[4096], type[128];

  if (sscanf(line, "%u %*u %*u:%*u %4095s %4095s", &id, root, target) != 3) {
    LOGV("Skipping malformed mountinfo line: %s", line);

    return false;
  }

  if (sscanf(separator + 3, "%127s %4095s", type, source) != 2) {
    LOGV("Skipping mountinfo line without a source: %s", line);

    return false;
  }

  out->id = id;
  out->root = strdup(root);
  out->target = strdup(target);
  out->source = strdup(source);

  if (out->root == NULL || out->target == NULL || out->source == NULL) {
    free(out->root);
    free(out->target);
    free(out->source);

    out->root = NULL;
    out->target = NULL;
    out->source = NULL;

    LOGE("Failed copying a mountinfo entry");

    return false;
  }

  return true;
}

static bool mount_list_parse(const char *path, struct mount_list *out) {
  FILE *file = fopen(path, "re");
  if (file == NULL) {
    PLOGE("Failed opening %s", path);

    return false;
  }

  char *line = NULL;
  size_t capacity = 0;
  bool ok = true;

  while (getline(&line, &capacity, file) > 0) {
    char *newline = strchr(line, '\n');
    if (newline != NULL) *newline = '\0';

    if (!mount_list_reserve(out, out->len + 1)) {
      ok = false;

      break;
    }

    struct mount_info info = { 0 };
    if (mount_info_parse(line, &info)) {
      out->items[out->len] = info;
      out->len++;
    }
  }

  free(line);
  fclose(file);

  return ok;
}

/* INFO: KernelSU keeps its modules on a loop device, and that device name
         shows up as the source of every module mount. APatch mounts them as a
         plain overlay, so only the KernelSU flavour looks for it. */
static const char *find_module_loop_source(const struct mount_list *all) {
#ifndef ROOT_IMPL_APATCH
  for (size_t i = 0; i < all->len; i++) {
    const struct mount_info *info = &all->items[i];

    if (strcmp(info->target, ROOT_MODULES_DIR) == 0 &&
        strncmp(info->source, MOUNT_SOURCE_LOOP, strlen(MOUNT_SOURCE_LOOP)) == 0) {
      LOGV("Detected the KernelSU module loop source: %s", info->source);

      return info->source;
    }
  }
#else
  (void) all;
#endif

  return NULL;
}

static bool carries_root_trace(const struct mount_info *info, const char *loop_source) {
  if (mount_path_at_or_under(info->root, ROOT_MODULES_ROOT)) return true;
  if (mount_path_at_or_under(info->target, ROOT_MODULES_DIR)) return true;

  for (size_t i = 0; i < ROOT_SOURCE_COUNT; i++) {
    if (strcmp(info->source, kRootSources[i]) == 0) return true;
  }

  return loop_source != NULL && strcmp(info->source, loop_source) == 0;
}

static int compare_by_id_descending(const void *a, const void *b) {
  const struct mount_info *left = (const struct mount_info *)a;
  const struct mount_info *right = (const struct mount_info *)b;

  if (left->id == right->id) return 0;

  /* INFO: Highest id first, so a mount is always removed before the one it
            is stacked on top of. */
  return left->id > right->id ? -1 : 1;
}

/* INFO: Refusing to unmount is safer than unmounting the wrong thing: a
         zygote resource overlay sits under /product on some ROMs, and taking
         it down breaks the process that is forked next. Only an exact
         /product mount is treated as a root trace worth aborting over. */
static bool abort_zygote_unmount(const struct mount_list *traces) {
  if (traces->len == 0) {
    LOGV("Nothing to revert from zygote");

    return true;
  }

  for (size_t i = 0; i < traces->len; i++) {
    const char *target = traces->items[i].target;

    if (strcmp(target, PRODUCT_MOUNT) != 0) continue;

    LOGW("Refusing to revert zygote, %s is mounted", target);

    return true;
  }

  return false;
}

/* INFO: Revert-only is the active mount mode unless a disable-revert marker
         next to the module opts the device out, in which case denylisted
         processes are isolated by switching them into the cached clean
         namespace instead. */
bool revert_mode_enabled(void) {
  static int enabled = -1;

  if (enabled == -1) {
    struct stat st;

    /* INFO: Both locations are checked because which one a process can
              actually see depends on the label the root solution gives
              /data/adb on that device. */
    enabled = !(stat(ZYGISK_TMP_PATH "/disable-revert", &st) == 0 ||
                stat(ZYGISK_MODULE_DIR "/disable-revert", &st) == 0);
  }

  return enabled == 1;
}

bool revert_root_traces_here(void) {
  struct mount_list all = { 0 };
  if (!mount_list_parse("/proc/self/mountinfo", &all)) {
    mount_list_free(&all);

    return false;
  }

  struct mount_list traces = { 0 };
  /* INFO: loop_source borrows a string owned by `all`; it is only consulted
           across the selection loop below and must not be read after the
           mount_list_free(&all) call that follows it. */
  const char *loop_source = find_module_loop_source(&all);

  for (size_t i = 0; i < all.len; i++) {
    if (!carries_root_trace(&all.items[i], loop_source)) continue;

    if (!mount_list_reserve(&traces, traces.len + 1)) break;

    traces.items[traces.len] = all.items[i];

    /* INFO: The entry now belongs to the trace list, detaching it keeps the
              cleanup below from freeing it twice. From here on the strings it
              named are gone from `all` while `all.len` still counts the entry,
              so it reads back as a NULL target: anything that has to look at
              the whole table must run before this loop, and none of it after.
              (`all` is released on the next statement, which is what makes the
              hand-over safe - keep it that way.) */
    all.items[i].root = NULL;
    all.items[i].target = NULL;
    all.items[i].source = NULL;

    traces.len++;
  }

  mount_list_free(&all);

  if (abort_zygote_unmount(&traces)) {
    /* INFO: Refused, not failed. The caller falls back to the clean
              namespace, which hides the mounts by moving the process into a
              namespace that never had them. */
    mount_list_free(&traces);

    return false;
  }

  qsort(traces.items, traces.len, sizeof(struct mount_info), compare_by_id_descending);

  bool complete = true;

  for (size_t i = 0; i < traces.len; i++) {
    const char *target = traces.items[i].target;

    /* INFO: MNT_DETACH, deliberately. A detached mount disappears from this
              namespace's mount tree while the filesystem instance stays alive
              for whoever already holds a reference, which is exactly what
              hiding a trace is meant to mean: the paths stop resolving to the
              overlay, yet nothing built on top of it is torn down. A plain
              umount2(target, 0) reaches further than that. Root solution
              overlays carry the source name of the solution and, on a
              metamodule setup, cover system paths as well - framework and
              provider resources among them - so unmounting one for real
              leaves WebView looking at a path its own mountinfo still claims
              is overlaid and it fails to initialize, which surfaces as blank
              module WebUIs. The lazy detach hides the same set without
              breaking them. */
    if (umount2(target, MNT_DETACH) == 0) {
      LOGV("Reverted %s (mount id %u)", target, traces.items[i].id);

      continue;
    }

    LOGW("Failed reverting %s: %s", target, strerror(errno));

    complete = false;
  }

  mount_list_free(&traces);

  /* INFO: A partial revert still returns false, so the caller can fall back
            to the clean namespace rather than leaving the process with some of
            the traces still visible. */
  return complete;
}
