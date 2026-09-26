#ifndef HIDING_H
#define HIDING_H

#include <stdbool.h>

/* INFO: A trace the mount revert cannot reach. Reverting the mount tree of a
         hidden process leaves the module libraries still mapped into it, and
         a mapped library names its own file in /proc/self/maps - which is all
         a process needs to tell that Zygisk put something inside it. Hiding
         that is per process, and only final once the modules have run, so it
         lives here rather than in unmount.c. */

bool hide_module_maps(void);

#endif /* HIDING_H */
