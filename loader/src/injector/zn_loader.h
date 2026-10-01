#ifndef ZN_LOADER_H
#define ZN_LOADER_H

#include <stddef.h>
#include <stdint.h>

/* INFO: Scans the modules for a zn_modules.txt and loads the Zygisk Next
         libraries whose target matches the current process. Meant for the
         zygote itself, where the process name can be read off /proc/self/exe.

         `connect_retry` is the number of extra daemon connection attempts
         after the first, spaced 0.1s apart. The HyperOS spawner passes more
         than one because it can exec in the same breath as the daemon's own
         fork, and a single attempt would lose that race and leave the spawner
         with no runtime modules at all. Even at five that is 0.6s at worst,
         and it only ever costs anything while the daemon is unreachable. */
void zn_load_all_modules(uint8_t connect_retry);

/* INFO: Same scan, but for a forked child that is about to specialize:
         process_name is the nice_name the zygote was given, and only the
         modules targeting it are loaded. Libraries already inherited from the
         zygote are skipped. The daemon is long up by the time a process
         specializes, so one connection attempt is enough. */
void zn_load_modules_for_process(const char *process_name);

/* INFO: Opens a fresh connection to the companion of the module behind
         `handle`, which is the self handle it received in onModuleLoaded.
         Returns the socket, or -1 when there is no reachable companion. */
int zn_companion_connect(void *handle);

/* INFO: How many Zygisk Next libraries this process holds. Zero means its maps
         carry none of ours, so there is nothing there to stop naming - and a
         count inherited from the zygote is inherited along with the libraries
         it was raised for. */
size_t zn_loaded_library_count(void);

#endif /* ZN_LOADER_H */
