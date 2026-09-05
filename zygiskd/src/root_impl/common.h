#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>

#include <sys/types.h>

#include "../constants.h"

/* INFO: Which backend the daemon was built for. Only one is compiled in, but
         both stay in the enum so the impl-name switch and the string table
         are shared. */
enum root_impls {
  KernelSU,
  APatch
};

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
