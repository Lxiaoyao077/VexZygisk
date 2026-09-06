#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>

#include <sys/types.h>

#include "../constants.h"

/* INFO: The backend the daemon was built for. Only the matching member is
         compiled in, so the switches and the name table cannot carry the
         other root solution at all. */
#ifdef ROOT_IMPL_APATCH
enum root_impls {
  RootAPatch
};
#else
enum root_impls {
  RootKernelSU
};
#endif

struct root_impl_state {
  enum RootImplState state;
};

struct root_impl {
  enum root_impls impl;
};

/* INFO: The display name and the kind live next to the enum so the length
         can be derived from the one string that is actually compiled in —
         a fixed sizeof("KernelSU") would silently overflow once a root
         with a longer name shows up. */
#ifdef ROOT_IMPL_APATCH
  #define ROOT_IMPL_KIND RootAPatch
  #define ROOT_IMPL_NAME "APatch"
#else
  #define ROOT_IMPL_KIND RootKernelSU
  #define ROOT_IMPL_NAME "KernelSU"
#endif

#define LONGEST_ROOT_IMPL_NAME sizeof(ROOT_IMPL_NAME)

void root_impls_setup(void);

void get_impl(struct root_impl *uimpl);

void uid_query_root(uid_t uid, bool *granted_root, bool *should_umount);

bool uid_is_manager(uid_t uid);

void root_impl_cleanup(void);

#endif /* COMMON_H */
