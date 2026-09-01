#ifndef ZN_LOADER_H
#define ZN_LOADER_H

/* INFO: Scans the modules for a zn_modules.txt and loads the Zygisk Next
         libraries whose target matches the current process. */
void zn_load_all_modules(void);

/* INFO: Opens a fresh connection to the companion of the module behind
         `handle`, which is the self handle it received in onModuleLoaded.
         Returns the socket, or -1 when there is no reachable companion. */
int zn_companion_connect(void *handle);

#endif /* ZN_LOADER_H */
