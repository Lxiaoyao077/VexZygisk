#ifndef ZN_API_H
#define ZN_API_H

#include "zygisk_next_api.h"

/* INFO: The API table handed to every Zygisk Next module. PLT hooking is
         served by PLTI, inline hooking by Dobby and the symbol resolver by the
         ELF reader already linked into this library.

         The table is picked from the version the module was built against,
         mirroring the upstream tiering: modules older than API 2 predate the
         symbol resolver and are refused it, API v2/v3 predate the runtime
         entry, and API v4 receives the full table. */
const struct ZygiskNextAPI *zn_get_api_for_version(int target_api_version);

/* INFO: Fires every HyperOS runtime module's onAppSpecialized with the
         specialization strings; called from the app specialize post hook.
         No-op until a module registered through getRuntime().registerModule
         in this process (or the spawner it was forked from). */
void zn_runtime_notify_app_specialized(const char *process_name, const char *package_name, const char *se_info);

/* INFO: Whether this process is the HyperOS app spawner (or one of the apps
         it forked, which share its /proc/self/exe). The injector uses it to
         skip the zygote-only hooks. */
bool zn_is_hyos_spawner(void);

/* INFO: Whether any HyperOS runtime module registered in this process —
         the specialize post hook checks it before doing the JNI work of
         collecting the callback arguments. */
bool zn_hyos_modules_registered(void);

#endif /* ZN_API_H */
