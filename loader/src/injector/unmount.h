#ifndef UNMOUNT_H
#define UNMOUNT_H

#include <stdbool.h>
#include <stdint.h>

/* INFO: Reverting the zygote is the "revert only" mount mode: the module and
         root mounts are unmounted from zygote itself, once, instead of moving
         every denylisted app into a namespace where they are hidden.

         Once zygote is clean every process forked from it inherits that state,
         which is why the per-process namespace switch can then be skipped. It
         is also the mode that needs the least from the daemon: no namespace
         has to be cached and held for the lifetime of the boot.

         The alternative, switching denylisted processes into a clean
         namespace, is kept as the fallback for the cases where reverting is
         refused (see the /product guard in unmount.c). */

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
