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

#endif /* ZN_API_H */
