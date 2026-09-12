#ifndef UNMOUNT_H
#define UNMOUNT_H

#include <stdbool.h>
#include <stdint.h>

/* INFO: Reverting the zygote is the "revert only" mount mode, and it takes two
         halves. The module and root mounts are unmounted from zygote itself,
         once, so every process forked afterwards starts out unable to see
         them; and a process that is NOT on the denylist switches back into the
         root namespace captured before that revert, so it keeps seeing what
         the mounts carry - a metamodule's themes and overlays among them.

         Leaving the second half out is what makes the mode look broken: every
         app would then run in a view that never had the mounts, breaking
         exactly the modules those mounts exist for.

         Switching denylisted processes into a clean namespace stays as the
         fallback for the cases where reverting is refused (see the /product
         guard in unmount.c). */

/* Whether revert-only is the active mount mode. True unless a disable-revert
   marker next to the module opts the device out, in which case the zygote
   keeps its mounts and the namespace fallback does the isolating.

   The caller asks this before the first revert so the root namespace can be
   captured while the mounts are still there. */
bool zygote_revert_enabled(void);

/* Attempts to unmount the root and module traces from zygote.

   Returns true when zygote is known to be clean, either because this call
   reverted it or because an earlier call already did. Returns false when
   nothing could be done, in which case the caller keeps hiding mounts the
   namespace way.

   Only ever performs work once: a successful revert is remembered, and a
   refused or partial one is retried on the next fork. */
bool zygote_mounts_revert(void);

/* Whether an earlier zygote_mounts_revert() left zygote clean. */
bool zygote_mounts_reverted(void);

#endif /* UNMOUNT_H */
