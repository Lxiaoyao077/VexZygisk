#ifndef ZN_API_H
#define ZN_API_H

#include "zygisk_next_api.h"

/* INFO: The API table handed to every Zygisk Next module. Inline hooking is not
         implemented, pltHook and the symbol resolver are served by PLTI and the
         ELF reader already linked into this library. */
const struct ZygiskNextAPI *zn_get_api(void);

void zn_api_deinit(void);

#endif /* ZN_API_H */
