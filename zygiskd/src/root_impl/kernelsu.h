#ifndef KERNELSU_H
#define KERNELSU_H

#include "common.h"

void ksu_get_existence(struct root_impl_state *state);

void ksu_uid_query_root(uid_t uid, bool *granted_root, bool *should_umount);

bool ksu_uid_is_manager(uid_t uid);

void ksu_cleanup(void);

#endif
