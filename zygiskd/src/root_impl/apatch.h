#ifndef APATCH_H
#define APATCH_H

#include "common.h"

void ap_get_existence(struct root_impl_state *state);

void ap_uid_query_root(uid_t uid, bool *granted_root, bool *should_umount);

bool ap_uid_is_manager(uid_t uid);

#endif /* APATCH_H */
