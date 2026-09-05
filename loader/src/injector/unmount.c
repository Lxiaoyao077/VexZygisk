#include <stdlib.h>
#include <string.h>

#include <errno.h>
#include <stdio.h>
#include <sys/mount.h>
#include <sys/sysmacros.h>

#include "logging.h"

#include "unmount.h"

#define MOUNT_SOURCE_LOOP "/dev/block/loop"
#define KSU_MODULES_DIR "/data/adb/modules"
#define KSU_MODULES_ROOT "/adb/modules"
#define PRODUCT_MOUNT "/product"
#define PRODUCT_BIN_MOUNT "/product/bin"

/* INFO: The overlay mounts of each root solution carry its own source name:
         KernelSU reports "KSU" and APatch reports "APatch" or "kpatch". The
         flavour is fixed at build time, so only the matching names are
         compiled in. */
#ifdef ROOT_IMPL_APATCH
  static const char *const kRootSources[] = { "APatch", "kpatch" };
  #define ROOT_SOURCE_COUNT 2
#else
  static const char *const kRootSources[] = { "KSU" };
  #define ROOT_SOURCE_COUNT 1
#endif

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

static bool g_zygote_reverted = false;

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
         delimiter that cannot appear inside a field:

           36 35 98:0 /root /target rw,... - type source rw,...

         The mount id has to be parsed out because nested mounts only come
         down in the reverse order of their ids. */
static bool mount_info_parse(const char *line, struct mount_info *out) {
  const char *separator = strstr(line, " - ");
  if (separator == NULL) {
    LOGV("Skipping malformed mountinfo line (no separator)");

    return false;
  }

  char head[1024];
  size_t head_len = (size_t)(separator - line);
  if (head_len >= sizeof(head)) {
    LOGW("Skipping oversized mountinfo line");

    return false;
  }

  memcpy(head, line, head_len);
  head[head_len] = '\0';

  /* INFO: The parent id and the "major:minor" device are skipped, nothing
            here needs them. */
  unsigned int id = 0;
  char root[512], target[512], source[512], type[128];

  if (sscanf(head, "%u %*u %*u:%*u %511s %511s", &id, root, target) != 3) {
    LOGV("Skipping malformed mountinfo line: %s", line);

    return false;
  }

  if (sscanf(separator + 3, "%127s %511s", type, source) != 2) {
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

static bool mount_list_parse(struct mount_list *out) {
  FILE *file = fopen("/proc/self/mountinfo", "re");
  if (file == NULL) {
    PLOGE("Failed opening /proc/self/mountinfo");

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
         shows up as the source of every module mount. It is not known ahead
         of time, so it is taken from the modules directory mount itself. */
/* INFO: KernelSU keeps its modules on a loop device, and that device name
         shows up as the source of every module mount. APatch mounts them as a
         plain overlay, so only the KernelSU flavour looks for it. */
static const char *find_module_loop_source(const struct mount_list *all) {
#ifndef ROOT_IMPL_APATCH
  for (size_t i = 0; i < all->len; i++) {
    const struct mount_info *info = &all->items[i];

    if (strcmp(info->target, KSU_MODULES_DIR) == 0 &&
        strncmp(info->source, MOUNT_SOURCE_LOOP, strlen(MOUNT_SOURCE_LOOP)) == 0) {
      LOGV("Detected the KernelSU module loop source: %s", info->source);

      return info->source;
    }
  }
#endif

  return NULL;
}

static bool carries_root_trace(const struct mount_info *info, const char *loop_source) {
  if (strncmp(info->root, KSU_MODULES_ROOT, strlen(KSU_MODULES_ROOT)) == 0) return true;
  if (strncmp(info->target, KSU_MODULES_DIR, strlen(KSU_MODULES_DIR)) == 0) return true;

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

    if (strncmp(target, PRODUCT_MOUNT, strlen(PRODUCT_MOUNT)) != 0) continue;
    if (strncmp(target, PRODUCT_BIN_MOUNT, strlen(PRODUCT_BIN_MOUNT)) == 0) continue;
    if (strcmp(target, PRODUCT_MOUNT) != 0) continue;

    LOGW("Refusing to revert zygote, %s is mounted", target);

    return true;
  }

  return false;
}

bool zygote_mounts_revert(void) {
  if (g_zygote_reverted) return true;

  struct mount_list all = { 0 };
  if (!mount_list_parse(&all)) {
    mount_list_free(&all);

    return false;
  }

  struct mount_list traces = { 0 };
  const char *loop_source = find_module_loop_source(&all);

  for (size_t i = 0; i < all.len; i++) {
    if (!carries_root_trace(&all.items[i], loop_source)) continue;

    if (!mount_list_reserve(&traces, traces.len + 1)) break;

    traces.items[traces.len] = all.items[i];

    /* INFO: The entry now belongs to the trace list, detaching it keeps the
              cleanup below from freeing it twice. */
    all.items[i].root = NULL;
    all.items[i].target = NULL;
    all.items[i].source = NULL;

    traces.len++;
  }

  mount_list_free(&all);

  if (abort_zygote_unmount(&traces)) {
    mount_list_free(&traces);

    return false;
  }

  qsort(traces.items, traces.len, sizeof(struct mount_info), compare_by_id_descending);

  bool complete = true;

  for (size_t i = 0; i < traces.len; i++) {
    const char *target = traces.items[i].target;

    if (umount2(target, MNT_DETACH) == 0) {
      LOGV("Reverted %s (mount id %u)", target, traces.items[i].id);

      continue;
    }

    LOGW("Failed reverting %s: %s", target, strerror(errno));

    complete = false;
  }

  mount_list_free(&traces);

  if (!complete) {
    LOGV("Zygote was only partly reverted, retrying on the next fork");

    return false;
  }

  g_zygote_reverted = true;

  return true;
}

bool zygote_mounts_reverted(void) {
  return g_zygote_reverted;
}
