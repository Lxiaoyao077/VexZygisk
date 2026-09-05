#ifndef ZYGISK_PATHS_H
#define ZYGISK_PATHS_H

/* INFO: Single source of truth for every path and socket name the loader and
         the daemon share. Both sides used to write these literals separately,
         so a one-sided edit only surfaced as a connection failure on a
         device. The expansions are byte-identical to the previous per-binary
         defines.

         ZYGISK_TMP_PATH and ZYGISK_MODULE_ID are upgrade compatibility red
         lines: neither may change, or existing installs break. */

#ifdef __LP64__
  #define ZP_SELECT(lp32, lp64) lp64
#else
  #define ZP_SELECT(lp32, lp64) lp32
#endif

#define ZYGISK_TMP_PATH "/data/adb/rezygisk"
#define ZYGISK_MODULE_ID "rezygisk"
#define ZYGISK_MODULES_DIR "/data/adb/modules"
#define ZYGISK_MODULE_DIR ZYGISK_MODULES_DIR "/" ZYGISK_MODULE_ID

/* INFO: The daemon binary, the controller datagram socket the monitor
         listens on, and the stream socket the loader connects to. */
#define ZYGISKD_BIN ZYGISK_MODULE_DIR "/bin/zygiskd" ZP_SELECT("32", "64")
#define ZYGISK_CONTROLLER_SOCKET ZYGISK_TMP_PATH "/init_monitor"
#define ZYGISK_CP_SOCKET ZYGISK_TMP_PATH "/" ZP_SELECT("cp32", "cp64") ".sock"

/* INFO: Files the monitor owns inside the scratch directory, and the module
         property file it keeps a pristine copy of. */
#define ZYGISK_STATE_JSON ZYGISK_TMP_PATH "/state.json"
#define ZYGISK_MODULE_PROP ZYGISK_MODULE_DIR "/module.prop"

#endif /* ZYGISK_PATHS_H */
