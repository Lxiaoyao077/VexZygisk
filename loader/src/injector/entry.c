#include <stdbool.h>

#include "daemon.h"
#include "logging.h"
#include "misc.h"

#include "hook.h"
#include "ptrace_clear.h"
#include "zn_api.h"
#include "zn_loader.h"

__attribute__((visibility("default")))
void entry(void *addr, size_t size, int tango_flag) {
  LOGD("VexZygisk%s library injected, version %s", tango_flag ? " [TANGO]" : "", ZKSU_VERSION);

  start_addr = addr;
  block_size = size;

  /* INFO: HyperOS forks applications from /system_ext/bin/hyos_spawner instead
           of a zygote, and there is no ART specialize path in it to hook —
           hooking the JNI there is what crashed the spawner and left every
           app unable to start (the second-screen loop). The spawner only
           carries the runtime: the modules load, register through
           getRuntime(), and are notified from the fork and SELinux hooks the
           runtime installs. The JNI and PLT hooks belong to the zygote. */
  bool is_spawner = zn_is_hyos_spawner();

  if (is_spawner) {
    LOGD("Running inside hyos_spawner, initializing the HyperOS runtime");
  } else {
    LOGD("start plt hooking");

    hook_functions();
  }

  zn_load_all_modules();

  struct kernel_version version = parse_kversion();
  if (version.major > 3 || (version.major == 3 && version.minor >= 8)) {
    LOGD("Supported kernel version %d.%d.%d, sending seccomp event", version.major, version.minor, version.patch);

    perform_ptrace_message_clear();
  }

  /* INFO: The daemon's zygote bookkeeping is about the zygote: the spawner
           has no specialize to track and no companions of its own. */
  if (is_spawner) return;

  if (!rezygiskd_zygote_injected()) {
    LOGE("VexZygiskd is not running");

    return;
  }

  LOGD("Zygisk library execution done, addr: %p, size: %zu", addr, size);
}
