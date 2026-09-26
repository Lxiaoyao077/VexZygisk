#ifndef HIDING_H
#define HIDING_H

#include <stdbool.h>

/* INFO: Traces the mount revert cannot reach, both of them per process and
         both only final once the modules have run:

         - module libraries still mapped into a hidden process, each naming
           its own file in /proc/self/maps;
         - the mount line bionic parses into one static buffer, which the
           zygote hands down to every application it forks.

         Neither is a mount, so neither is reachable from unmount.c. */

bool hide_module_maps(void);

bool refresh_mount_line(void);

#endif /* HIDING_H */
