#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <dlfcn.h>
#include <dobby.h>
#include <sys/types.h>

#include "elf_util.h"
#include "logging.h"
#include "misc.h"

#include "zn_api.h"
#include "zn_loader.h"

/* INFO: The Zygisk Next pltHook is served by LSPlt, the hooking engine the
         LSPosed ecosystem builds its modules against, exactly as NyaZygisk
         does. The injector is C, so the C++ island is confined to the
         zn_lsplt_shim.cpp bridge and the static library behind it. */
int zn_lsplt_register_hook(dev_t dev, ino_t inode, const char *symbol, void *hook, void **backup);
int zn_lsplt_commit_hook(void);

/* INFO: LSPlt identifies libraries by file identity (device + inode), while
         the ZN API hands us a base address, so the owning mapping is looked
         up in the process maps. */
static bool get_lib_location_by_base(uintptr_t base_addr, dev_t *dev, ino_t *inode) {
  struct maps_info *maps = parse_maps_safe("self");
  if (maps == NULL) {
    LOGE("Failed to scan maps for the library at %p", (void *)base_addr);

    return false;
  }

  bool found = false;
  for (size_t i = 0; i < maps->length; i++) {
    struct map_entry *entry = &maps->maps[i];
    if (entry->start != base_addr || entry->offset != 0 || entry->path == NULL) continue;

    *dev = entry->dev;
    *inode = entry->inode;
    found = true;

    break;
  }

  free_maps(maps);

  if (!found) LOGE("No library mapped at %p", (void *)base_addr);

  return found;
}

static int zn_plt_hook(void *base_addr, const char *symbol, void *hook_handler, void **original) {
  if (base_addr == NULL || symbol == NULL || hook_handler == NULL) return ZN_FAILED;

  dev_t dev = 0;
  ino_t inode = 0;
  if (!get_lib_location_by_base((uintptr_t)base_addr, &dev, &inode)) return ZN_FAILED;

  /* INFO: LSPlt implements the ZN unhook contract natively: registering the
             backup of a previous call back as the handler restores the GOT
             entries and cleans up. */
  void *backup = NULL;
  if (zn_lsplt_register_hook(dev, inode, symbol, hook_handler, &backup) != 0) {
    LOGE("Failed registering the PLT hook for %s", symbol);

    return ZN_FAILED;
  }

  if (zn_lsplt_commit_hook() != 0) {
    LOGE("Failed committing the PLT hook for %s", symbol);

    return ZN_FAILED;
  }

  if (original != NULL) *original = backup;

  return backup ? ZN_SUCCESS : ZN_FAILED;
}

/* INFO: The Zygisk Next contract allows a single inline hook per address, so
         the hooked addresses are remembered: a second request for one of them
         is rejected instead of piling a second trampoline on top. */
#define ZN_MAX_INLINE_HOOKS 64

static pthread_mutex_t zn_hooked_lock = PTHREAD_MUTEX_INITIALIZER;
static uintptr_t zn_hooked[ZN_MAX_INLINE_HOOKS];
static size_t zn_hooked_count = 0;

static bool zn_is_hooked(uintptr_t address) {
  for (size_t i = 0; i < zn_hooked_count; i++)
    if (zn_hooked[i] == address) return true;

  return false;
}

static void zn_forget_hooked(uintptr_t address) {
  for (size_t i = 0; i < zn_hooked_count; i++) {
    if (zn_hooked[i] != address) continue;

    zn_hooked[i] = zn_hooked[zn_hooked_count - 1];
    zn_hooked_count--;

    return;
  }
}

/* INFO: The slot is claimed before hooking so two threads racing for the same
         address cannot both get past the check. */
static int zn_claim_address(uintptr_t address) {
  pthread_mutex_lock(&zn_hooked_lock);

  if (zn_is_hooked(address)) {
    pthread_mutex_unlock(&zn_hooked_lock);

    LOGW("The address %p already carries an inline hook, rejecting the new one", (void *)address);

    return ZN_FAILED;
  }

  if (zn_hooked_count >= ZN_MAX_INLINE_HOOKS) {
    pthread_mutex_unlock(&zn_hooked_lock);

    LOGE("Reached the limit of %d inline hooks, rejecting %p", ZN_MAX_INLINE_HOOKS, (void *)address);

    return ZN_FAILED;
  }

  zn_hooked[zn_hooked_count++] = address;

  pthread_mutex_unlock(&zn_hooked_lock);

  return ZN_SUCCESS;
}

static int zn_inline_hook(void *target, void *addr, void **original) {
  if (target == NULL || addr == NULL) return ZN_FAILED;

  if (zn_claim_address((uintptr_t)target) != ZN_SUCCESS) return ZN_FAILED;

  dobby_dummy_func_t backup = NULL;
  if (DobbyHook(target, (dobby_dummy_func_t)(uintptr_t)addr, &backup) != RS_SUCCESS) {
    LOGE("Failed placing the inline hook on %p", target);

    pthread_mutex_lock(&zn_hooked_lock);
    zn_forget_hooked((uintptr_t)target);
    pthread_mutex_unlock(&zn_hooked_lock);

    return ZN_FAILED;
  }

  if (original != NULL) *original = (void *)backup;

  return ZN_SUCCESS;
}

static int zn_inline_unhook(void *target) {
  if (target == NULL) return ZN_FAILED;

  if (DobbyDestroy(target) != 0) {
    LOGE("Failed removing the inline hook on %p", target);

    return ZN_FAILED;
  }

  pthread_mutex_lock(&zn_hooked_lock);
  zn_forget_hooked((uintptr_t)target);
  pthread_mutex_unlock(&zn_hooked_lock);

  return ZN_SUCCESS;
}

static void *symbol_to_address(ElfImg *img, ElfW(Sym) *sym) {
  if (sym->st_value == 0) return NULL;

  return (void *)((uintptr_t)img->base + sym->st_value);
}

/* INFO: Lookup order mirrors Zygisk Next: an exact lookup prefers the dynamic
           linker, which always yields the true runtime address of a loaded
           exported symbol, then falls back to the parsed symbol tables (file
           .symtab and the .gnu_debugdata mini-debug symbols) and finally to the
           dynamic symbol tables of the file itself. Prefix lookups can only be
           served from the parsed tables. */
static void *zn_symbol_lookup(struct ZnSymbolResolver *resolver, const char *name, bool prefix, size_t *size) {
  if (resolver == NULL || name == NULL) return NULL;

  ElfImg *img = (ElfImg *)resolver;

  if (!prefix) {
    void *exported = dlsym(RTLD_DEFAULT, name);
    if (exported != NULL) return exported;
  }

  size_t name_len = strlen(name);
  if (name_len == 0) return NULL;

  if (ElfImg_load_symbols(img)) {
    for (size_t i = 0; i < img->symtabs_count_; i++) {
      ElfW(Sym) *sym = img->symtabs_[i];

      const char *sym_name = getSymbName(img, sym);
      if (sym_name == NULL) continue;

      if (prefix ? (strncmp(sym_name, name, name_len) != 0) : (strcmp(sym_name, name) != 0)) continue;

      if (size != NULL) *size = sym->st_size;

      return symbol_to_address(img, sym);
    }
  }

  /* INFO: Last resort for an exact lookup: the hash tables of the dynamic
             symbol section, resolved against the image base. */
  if (!prefix) {
    void *dynamic = (void *)getSymbAddress(img, name);
    if (dynamic != NULL) return dynamic;
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

/* INFO: The contract lets a resolver be requested by bare file name ("libc.so"
         instead of "/apex/.../libc.so"). The ELF reader opens the file itself,
         so a name without a directory is resolved against the libraries
         actually mapped in this process first. */
static char *get_lib_path_by_name(const char *name) {
  struct maps_info *maps = parse_maps_safe("self");
  if (maps == NULL) return NULL;

  char *lib_path = NULL;
  for (size_t i = 0; i < maps->length; i++) {
    struct map_entry *entry = &maps->maps[i];
    if (entry->path == NULL || entry->offset != 0) continue;

    const char *base = strrchr(entry->path, '/');
    base = base == NULL ? entry->path : base + 1;

    if (strcmp(base, name) != 0) continue;

    lib_path = strdup(entry->path);

    break;
  }

  free_maps(maps);

  return lib_path;
}

static struct ZnSymbolResolver *zn_new_symbol_resolver(const char *path, void *base_addr) {
  if (path == NULL) return NULL;

  char *resolved = NULL;

  if (strchr(path, '/') == NULL) {
    resolved = get_lib_path_by_name(path);
    if (resolved != NULL) path = resolved;
  }

  struct ZnSymbolResolver *resolver = (struct ZnSymbolResolver *)ElfImg_create(path, base_addr);

  free(resolved);

  return resolver;
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

/* INFO: Nothing registers a runtime yet. Kept returning null rather than
         failing the call: a module is expected to probe it and carry on. */
static const struct ZygiskNextRuntime *zn_get_runtime(void) {
  return NULL;
}

/* INFO: The Runtime API only exists from ZN API v4 onwards, so modules built
           against an older version are told about it instead of being served
           a table they would never have reached. */
static const struct ZygiskNextRuntime *zn_get_runtime_unavailable(void) {
  LOGE("The runtime API needs a module built for API 4 or newer");

  return NULL;
}

/* INFO: Modules built against an API older than 2 predate the symbol resolver.
         They would call it through a structure that never had those slots, so
         they are told about it instead of being served. */
static struct ZnSymbolResolver *zn_symbol_resolver_unavailable(const char *path, void *base_addr) {
  (void)path;
  (void)base_addr;

  LOGE("The symbol resolver needs a module built for API 2 or newer");

  return NULL;
}

static void zn_free_symbol_resolver_unavailable(struct ZnSymbolResolver *resolver) {
  (void)resolver;
}

static void *zn_get_base_address_unavailable(struct ZnSymbolResolver *resolver) {
  (void)resolver;

  return NULL;
}

static void *zn_symbol_lookup_unavailable(struct ZnSymbolResolver *resolver, const char *name, bool prefix, size_t *size) {
  (void)resolver;
  (void)name;
  (void)prefix;
  (void)size;

  return NULL;
}

static void zn_for_each_symbols_unavailable(struct ZnSymbolResolver *resolver, bool (*callback)(const char *name, void *addr, size_t size, void *data), void *data) {
  (void)resolver;
  (void)callback;
  (void)data;
}

/* INFO: Full API, including the runtime entry: served to modules targeting
           API v4 and newer. */
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

/* INFO: API v2 and v3 predate the runtime entry, so their table carries the
           failing stub instead of a callable one. */
static const struct ZygiskNextAPI zn_api_without_runtime = {
  .pltHook = zn_plt_hook,
  .inlineHook = zn_inline_hook,
  .inlineUnhook = zn_inline_unhook,

  .newSymbolResolver = zn_new_symbol_resolver,
  .freeSymbolResolver = zn_free_symbol_resolver,
  .getBaseAddress = zn_get_base_address,
  .symbolLookup = zn_symbol_lookup,
  .forEachSymbols = zn_for_each_symbols,

  .connectCompanion = zn_connect_companion,
  .getRuntime = zn_get_runtime_unavailable
};

static const struct ZygiskNextAPI zn_api_without_symbol_resolver = {
  .pltHook = zn_plt_hook,
  .inlineHook = zn_inline_hook,
  .inlineUnhook = zn_inline_unhook,

  .newSymbolResolver = zn_symbol_resolver_unavailable,
  .freeSymbolResolver = zn_free_symbol_resolver_unavailable,
  .getBaseAddress = zn_get_base_address_unavailable,
  .symbolLookup = zn_symbol_lookup_unavailable,
  .forEachSymbols = zn_for_each_symbols_unavailable,

  .connectCompanion = zn_connect_companion,
  .getRuntime = zn_get_runtime_unavailable
};

const struct ZygiskNextAPI *zn_get_api_for_version(int target_api_version) {
  if (target_api_version < 2) return &zn_api_without_symbol_resolver;
  if (target_api_version < 4) return &zn_api_without_runtime;

  return &zn_api;
}
