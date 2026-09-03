/* INFO: The Zygisk Next pltHook is served by LSPlt, the hooking engine the
         LSPosed ecosystem builds its modules against, exactly as NyaZygisk
         does. The injector itself is C, so the C++ island is confined to this
         bridge and the static library behind it. */
#include <lsplt.hpp>

extern "C" int zn_lsplt_register_hook(dev_t dev, ino_t inode, const char *symbol, void *hook, void **backup) {
  return lsplt::RegisterHook(dev, inode, symbol, hook, backup) ? 0 : -1;
}

extern "C" int zn_lsplt_commit_hook(void) {
  return lsplt::CommitHook() ? 0 : -1;
}
