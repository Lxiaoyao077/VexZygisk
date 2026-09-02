#include "common.h"

#include "../utils.h"
#include "kernelsu.h"

static struct root_impl impl;
static bool impl_supported = false;

void root_impls_setup(void) {
  struct root_impl_state state_ksu;
  ksu_get_existence(&state_ksu);

  /* INFO: The daemon is a KernelSU module, so a missing interface only means
            it is running somewhere it cannot serve; keep serving requests that
            do not need root instead of failing to start. */
  if (state_ksu.state != Supported) {
    LOGW("No supported root implementation found.");

    return;
  }

  impl.impl = KernelSU;
  impl_supported = true;

  LOGI("KernelSU root implementation found.");
}

void get_impl(struct root_impl *uimpl) {
  *uimpl = impl;
}

bool uid_granted_root(uid_t uid) {
  if (!impl_supported) return false;

  return ksu_uid_granted_root(uid);
}

bool uid_should_umount(uid_t uid) {
  if (!impl_supported) return false;

  return ksu_uid_should_umount(uid);
}

bool uid_is_manager(uid_t uid) {
  if (!impl_supported) return false;

  return ksu_uid_is_manager(uid);
}

void root_impl_cleanup(void) {
  if (impl_supported) ksu_cleanup();
}
