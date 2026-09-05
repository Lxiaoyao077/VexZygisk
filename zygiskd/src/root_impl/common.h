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
  APatch
};
#else
enum root_impls {
  KernelSU
};
#endif

struct root_impl_state {
  enum RootImplState state;
};

struct root_impl {
  enum root_impls impl;
};

#define LONGEST_ROOT_IMPL_NAME sizeof("KernelSU")

void root_impls_setup(void);

void get_impl(struct root_impl *uimpl);

bool uid_granted_root(uid_t uid);

bool uid_should_umount(uid_t uid);

bool uid_is_manager(uid_t uid);

void root_impl_cleanup(void);

#endif /* COMMON_H */
