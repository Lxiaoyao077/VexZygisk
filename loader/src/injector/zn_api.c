#include <stdlib.h>
#include <string.h>

#include <plti.h>

#include "elf_util.h"
#include "logging.h"
#include "misc.h"

#include "zn_api.h"
#include "zn_loader.h"

static struct plti plt_ctx;
static bool plt_ctx_ready = false;

/* INFO: PLTI identifies libraries by path, while the ZN API hands us a base
         address, so the owning library is looked up in the process maps. */
static char *get_lib_path_by_base(uintptr_t base_addr) {
  struct maps_info *maps = parse_maps_safe("self");
  if (maps == NULL) {
    LOGE("Failed to scan maps for the library at %p", (void *)base_addr);

    return NULL;
  }

  char *lib_path = NULL;
  for (size_t i = 0; i < maps->length; i++) {
    struct map_entry *entry = &maps->maps[i];
    if (entry->start != base_addr || entry->path == NULL) continue;

    lib_path = strdup(entry->path);

    break;
  }

  free_maps(maps);

  if (lib_path == NULL) LOGE("No library mapped at %p", (void *)base_addr);

  return lib_path;
}

static bool ensure_plt_ctx(void) {
  if (plt_ctx_ready) return true;

  if (!plti_init(&plt_ctx)) {
    LOGE("Failed initializing the PLT hook context");

    return false;
  }

  plt_ctx_ready = true;

  return true;
}

static int zn_plt_hook(void *base_addr, const char *symbol, void *hook_handler, void **original) {
  if (base_addr == NULL || symbol == NULL || hook_handler == NULL) return ZN_FAILED;

  if (!ensure_plt_ctx()) return ZN_FAILED;

  char *lib_path = get_lib_path_by_base((uintptr_t)base_addr);
  if (lib_path == NULL) return ZN_FAILED;

  /* INFO: Unhooking is requested by passing the original back as the handler */
  bool is_unhook = original != NULL && *original == hook_handler;

  bool result;
  if (is_unhook) {
    result = plti_remove_hook(&plt_ctx, lib_path, symbol, hook_handler);
  } else {
    if (!plti_add_manual_lib(&plt_ctx, lib_path, (uintptr_t)base_addr)) {
      LOGE("Failed adding %s to the PLT hook context", lib_path);

      free(lib_path);

      return ZN_FAILED;
    }

    result = plti_add_hook(&plt_ctx, lib_path, symbol, hook_handler, original);
  }

  free(lib_path);

  return result ? ZN_SUCCESS : ZN_FAILED;
}

static int zn_inline_hook(void *target, void *addr, void **original) {
  (void)target;
  (void)addr;
  (void)original;

  LOGE("Inline hooking is not supported, rejecting the request");

  return ZN_FAILED;
}

static int zn_inline_unhook(void *target) {
  (void)target;

  return ZN_FAILED;
}

static void *symbol_to_address(ElfImg *img, ElfW(Sym) *sym) {
  if (sym->st_value == 0) return NULL;

  return (void *)((uintptr_t)img->base + sym->st_value);
}

static void *zn_symbol_lookup(struct ZnSymbolResolver *resolver, const char *name, bool prefix, size_t *size) {
  if (resolver == NULL || name == NULL) return NULL;

  ElfImg *img = (ElfImg *)resolver;
  if (!ElfImg_load_symbols(img)) return NULL;

  size_t name_len = strlen(name);
  if (name_len == 0) return NULL;

  for (size_t i = 0; i < img->symtabs_count_; i++) {
    ElfW(Sym) *sym = img->symtabs_[i];

    const char *sym_name = getSymbName(img, sym);
    if (sym_name == NULL) continue;

    if (prefix ? (strncmp(sym_name, name, name_len) != 0) : (strcmp(sym_name, name) != 0)) continue;

    if (size != NULL) *size = sym->st_size;

    return symbol_to_address(img, sym);
  }

  return NULL;
}

static void zn_for_each_symbols(struct ZnSymbolResolver *resolver, bool (*callback)(const char *name, void *addr, size_t size, void *data), void *data) {
  if (resolver == NULL || callback == NULL) return;

  ElfImg *img = (ElfImg *)resolver;
  if (!ElfImg_load_symbols(img)) return;

  for (size_t i = 0; i < img->symtabs_count_; i++) {
    ElfW(Sym) *sym = img->symtabs_[i];

    const char *name = getSymbName(img, sym);
    if (name == NULL || name[0] == '\0') continue;

    if (!callback(name, symbol_to_address(img, sym), sym->st_size, data)) break;
  }
}

static struct ZnSymbolResolver *zn_new_symbol_resolver(const char *path, void *base_addr) {
  if (path == NULL) return NULL;

  return (struct ZnSymbolResolver *)ElfImg_create(path, base_addr);
}

static void zn_free_symbol_resolver(struct ZnSymbolResolver *resolver) {
  if (resolver == NULL) return;

  ElfImg_destroy((ElfImg *)resolver);
}

static void *zn_get_base_address(struct ZnSymbolResolver *resolver) {
  if (resolver == NULL) return NULL;

  return ((ElfImg *)resolver)->base;
}

/* INFO: The self handle is the loader's module entry, which carries the
         companion control socket when the module declared one. */
static int zn_connect_companion(void *handle) {
  int fd = zn_companion_connect(handle);
  if (fd < 0) LOGE("The module has no reachable companion process");

  return fd;
}

static const struct ZygiskNextRuntime *zn_get_runtime(void) {
  return NULL;
}

static const struct ZygiskNextAPI zn_api = {
  .pltHook = zn_plt_hook,
  .inlineHook = zn_inline_hook,
  .inlineUnhook = zn_inline_unhook,

  .newSymbolResolver = zn_new_symbol_resolver,
  .freeSymbolResolver = zn_free_symbol_resolver,
  .getBaseAddress = zn_get_base_address,
  .symbolLookup = zn_symbol_lookup,
  .forEachSymbols = zn_for_each_symbols,

  .connectCompanion = zn_connect_companion,
  .getRuntime = zn_get_runtime
};

const struct ZygiskNextAPI *zn_get_api(void) {
  return &zn_api;
}
