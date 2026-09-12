#ifndef UNMOUNT_H
#define UNMOUNT_H

#include <stdbool.h>
#include <stdint.h>

/* INFO: "Revert only" is the mount mode a denylisted process is hidden with by
         default: instead of switching it into a shared clean namespace, the
         process is given a private copy of the mount tree and the root traces
         are stripped from that copy.

         Doing it in place is what keeps the mode non-destructive. The zygote
         and every process that is not on the denylist keep their mounts, so a
         metamodule's themes and overlays stay visible to the apps that rely on
         them, and each app ends up holding a namespace object of its own - the
         same shape a normal app has, rather than one shared with every other
         app the way a namespace switch leaves it.

         A metamodule's mounts are indistinguishable from a root trace to the
         selection, which is exactly why this is only ever applied to the
         processes being hidden.

         Switching into the shared clean namespace stays as the fallback for
         when the revert is refused (see the /product guard in unmount.c) or
         turned off with a disable-revert marker. */

/* Whether revert-only is the active mount mode. True unless a disable-revert
   marker next to the module opts the device out. */
bool revert_mode_enabled(void);

/* Strips the root traces from the mount namespace this process is in right
   now, and returns true when nothing is left to hide.

   Meant to run on a denylisted process immediately after it unshared its own
   copy of the mount tree: the mounts then disappear for that process alone.

   Returns false when an exact /product mount is among the traces, or when some
   of them could not be taken down, in which case the caller should hide the
   process the namespace way instead. */
bool revert_root_traces_here(void);

#endif /* UNMOUNT_H */
