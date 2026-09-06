#include <stdlib.h>
#include <string.h>

#include <stdio.h>

#include "root_impl/common.h"
#include "companion.h"
#include "zn_companion.h"
#include "zygiskd.h"

#include "utils.h"

int main(int argc, char *argv[]) {
  /* INFO: stdout is the module script's pipe, drained into the root
            manager's log. The daemon is long-lived and logs to logd, so the
            pipe side channel is cut before anything logs: in debug builds
            every printf becomes a null write, and release ones compile away
            entirely. Companions are execed from here and inherit it. */
  if (freopen("/dev/null", "w", stdout) == NULL) {
    /* INFO: Keep the inherited stdout; logd output is unaffected. */
  }

  LOGI("Welcome to VexZygiskd%s", LP_SELECT("32", "64"));

  if (argc > 1) {
    if (strcmp(argv[1], "companion") == 0) {
      if (argc < 3) {
        LOGI("Usage: zygiskd companion <fd>");

        return 1;
      }

      char *fd_end = NULL;
      long parsed_fd = strtol(argv[2], &fd_end, 10);
      if (fd_end == argv[2] || *fd_end != '\0' || parsed_fd < 0 || parsed_fd > 4095) {
        LOGI("Invalid descriptor number: %s", argv[2]);

        return 1;
      }

      int fd = (int)parsed_fd;
      companion_entry(fd);

      return 0;
    } else if (strcmp(argv[1], "zn-companion") == 0) {
      if (argc < 3) {
        LOGI("Usage: zygiskd zn-companion <fd>");

        return 1;
      }

      char *fd_end = NULL;
      long parsed_fd = strtol(argv[2], &fd_end, 10);
      if (fd_end == argv[2] || *fd_end != '\0' || parsed_fd < 0 || parsed_fd > 4095) {
        LOGI("Invalid descriptor number: %s", argv[2]);

        return 1;
      }

      int fd = (int)parsed_fd;
      zn_companion_entry(fd);

      return 0;
    } else if (strcmp(argv[1], "version") == 0) {
      LOGI("VexZygisk Daemon %s", ZKSU_VERSION);

      return 0;
    } else if (strcmp(argv[1], "root") == 0) {
      root_impls_setup();

      struct root_impl impl;
      get_impl(&impl);

      char impl_name[LONGEST_ROOT_IMPL_NAME];
      stringify_root_impl_name(impl, impl_name);

      LOGI("Root implementation: %s", impl_name);

      return 0;
    } else {
      LOGI("Usage: zygiskd [companion|zn-companion|version|root]");

      return 0;
    }
  }

  if (switch_mount_namespace(1) == false) {
    LOGE("Failed to switch mount namespace");

    return 1;
  }
  root_impls_setup();
  zygiskd_start(argv);

  return 0;
}
