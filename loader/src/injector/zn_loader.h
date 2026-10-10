#ifndef ZN_LOADER_H
#define ZN_LOADER_H

#include <stddef.h>
#include <stdint.h>

/* INFO: The extra connection attempts `entry` gives the daemon before it gives
         up on the module plan, and what that window is for.
 
         `entry` runs once per injected target, and both targets are one-shot
         for a whole process tree: whatever is loaded there is what the processes
         forked afterwards start with. The two are not equally one-shot, though,
         and the attempts are not the same either:
 
           - the HyperOS spawner's plan is the only one its apps ever see. An
             app it forks is not injected again and does not ask for itself, so
             five attempts a second apart is what NyaZygisk waits out for the
             same contract, and the failure it covers is a daemon forked in the
             same breath as the spawner's own exec.
           - a zygote's apps do ask again - each specialization asks the daemon
             for the modules naming that process - so what a zygote can lose is
             the modules that name the zygote itself, which nothing else loads.
             Three attempts at the short spacing rides out a daemon whose socket
             is still coming up without holding a boot on a daemon that is never
             going to answer: a zygote blocked in here delays every app launch
             behind it.
 
         Both windows are measured against a delay that only elapses while the
         daemon is unreachable, which is why they are attempts and not a fixed
         sleep. */
#define ZN_PLAN_ATTEMPTS_SPAWNER 5
#define ZN_PLAN_ATTEMPTS_TREE 3

/* INFO: Asks the daemon for the Zygisk Next libraries targeting this process
         and loads them. Meant for the zygote itself, where the process name
         can be read off /proc/self/exe.

         The daemon is the only source of the module plan. There is no fallback
         that reads /data/adb/modules directly: the HyperOS spawner and the apps
         it forks sit outside the zygote's domain and cannot read that tree
         anyway, so such a fallback could only ever have worked for targets the
         daemon already serves - and a loader that reads the tree on its own can
         disagree with the daemon about what is installed.

         `connect_retry` is the number of extra daemon connection attempts
         after the first, spaced `connect_delay_us` apart; the two constants
         above are the windows this is called with, and the reasoning behind
         each. The wait only ever costs anything while the daemon is
         unreachable. */
void zn_load_all_modules(uint8_t connect_retry, uint32_t connect_delay_us);

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
