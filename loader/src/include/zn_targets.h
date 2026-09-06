#ifndef ZN_TARGETS_H
#define ZN_TARGETS_H

/* INFO: The zygote-class target names of zn_modules.txt, shared by the daemon
         (which resolves the per-process set) and the loader (whose fallback
         matcher must reach the same answer when the daemon is unreachable).
         Both sides used to carry their own copy of this logic; the two halves
         of the protocol drifting apart here would silently change which
         modules load depending on daemon availability. */

#include <string.h>

static inline bool zn_target_is_zygote_class(const char *target) {
  return strcmp(target, "zygote") == 0 ||
         strcmp(target, "zygote64") == 0 ||
         strcmp(target, "zygote32") == 0 ||
         strcmp(target, "hyos_spawner") == 0;
}

static inline bool zn_process_is_zygote_class(const char *process_name) {
  return strstr(process_name, "zygote") != NULL ||
         strstr(process_name, "app_process") != NULL ||
         strstr(process_name, "hyos_spawner") != NULL;
}

#endif /* ZN_TARGETS_H */
