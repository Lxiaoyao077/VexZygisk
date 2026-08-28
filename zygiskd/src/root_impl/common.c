#include "common.h"

#include "../utils.h"
#include "kernelsu.h"

static struct root_impl impl;

void root_impls_setup(void) {
  struct root_impl_state state_ksu;
  ksu_get_existence(&state_ksu);

  if (state_ksu.state == Supported) {
    impl.impl = KernelSU;
    impl.variant = state_ksu.variant;
  }

  switch (impl.impl) {
    case KernelSU: {
      LOGI("KernelSU root implementation found.\n");

      break;
    }
  }
}

void get_impl(struct root_impl *uimpl) {
  *uimpl = impl;
}

bool uid_granted_root(uid_t uid) {
  switch (impl.impl) {
    case KernelSU: {
      return ksu_uid_granted_root(uid);
    }
  }

  return false;
}

bool uid_should_umount(uid_t uid) {
  switch (impl.impl) {
    case KernelSU: {
      return ksu_uid_should_umount(uid);
    }
  }

  return false;
}

bool uid_is_manager(uid_t uid) {
  switch (impl.impl) {
    case KernelSU: {
      return ksu_uid_is_manager(uid);
    }
  }

  return false;
}

void root_impl_cleanup(void) {
  if (impl.impl == KernelSU) ksu_cleanup();
}
