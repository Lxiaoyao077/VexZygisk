#ifndef APATCH_H
#define APATCH_H

#include "common.h"

void ap_get_existence(struct root_impl_state *state);

bool ap_uid_granted_root(uid_t uid);

bool ap_uid_should_umount(uid_t uid);

bool ap_uid_is_manager(uid_t uid);

#endif /* APATCH_H */
