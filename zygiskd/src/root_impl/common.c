#include "common.h"

#include "../utils.h"

/* INFO: One backend is compiled in per build; the macros keep the dispatch
         code below identical for both. The daemon is built for a specific
         root solution, so a missing interface only means it is running
         somewhere it cannot serve; keep serving requests that do not need
         root instead of failing to start. */
#ifdef ROOT_IMPL_APATCH
  #include "apatch.h"
  #define ROOT_GET_EXISTENCE ap_get_existence
  #define ROOT_UID_GRANTED_ROOT ap_uid_granted_root
  #define ROOT_UID_SHOULD_UMOUNT ap_uid_should_umount
  #define ROOT_UID_IS_MANAGER ap_uid_is_manager
  #define ROOT_IMPL_KIND APatch
  #define ROOT_IMPL_NAME "APatch"
#else
  #include "kernelsu.h"
  #define ROOT_GET_EXISTENCE ksu_get_existence
  #define ROOT_UID_GRANTED_ROOT ksu_uid_granted_root
  #define ROOT_UID_SHOULD_UMOUNT ksu_uid_should_umount
  #define ROOT_UID_IS_MANAGER ksu_uid_is_manager
  #define ROOT_IMPL_KIND KernelSU
  #define ROOT_IMPL_NAME "KernelSU"
#endif

static struct root_impl impl;
static bool impl_supported = false;

void root_impls_setup(void) {
  struct root_impl_state state;
  ROOT_GET_EXISTENCE(&state);

  if (state.state != Supported) {
    LOGW("No supported root implementation found.");

    return;
  }

  impl.impl = ROOT_IMPL_KIND;
  impl_supported = true;

  LOGI("%s root implementation found.", ROOT_IMPL_NAME);
}

void get_impl(struct root_impl *uimpl) {
  *uimpl = impl;
}

bool uid_granted_root(uid_t uid) {
  if (!impl_supported) return false;

  return ROOT_UID_GRANTED_ROOT(uid);
}

bool uid_should_umount(uid_t uid) {
  if (!impl_supported) return false;

  return ROOT_UID_SHOULD_UMOUNT(uid);
}

bool uid_is_manager(uid_t uid) {
  if (!impl_supported) return false;

  return ROOT_UID_IS_MANAGER(uid);
}

void root_impl_cleanup(void) {
  if (!impl_supported) return;

#ifndef ROOT_IMPL_APATCH
  /* INFO: APatch holds nothing on this side; its apd daemon is external. */
  ksu_cleanup();
#endif
}
