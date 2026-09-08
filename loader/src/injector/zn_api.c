#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <dlfcn.h>
#include <unistd.h>
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
         up in the process maps.

         A module hooks several symbols per library, and every call used to
         re-scan /proc/self/maps in full. The base of a library that is still
         loaded resolves to the same file identity every time, so the lookups
         are cached. The table only needs to hold the libraries a module is
         hooking right now; a base that gets reused for a different file after
         a dlclose is rare and simply evicts itself once the table is full. */
#define ZN_PLT_LOCATION_CACHE 16

struct zn_plt_location {
  uintptr_t base;
  dev_t dev;
  ino_t inode;
};

static struct zn_plt_location zn_plt_locations[ZN_PLT_LOCATION_CACHE];
static size_t zn_plt_locations_len = 0;

static bool get_lib_location_by_base(uintptr_t base_addr, dev_t *dev, ino_t *inode) {
  for (size_t i = 0; i < zn_plt_locations_len; i++) {
    if (zn_plt_locations[i].base != base_addr) continue;

    *dev = zn_plt_locations[i].dev;
    *inode = zn_plt_locations[i].inode;

    return true;
  }

  struct maps_info *maps = parse_maps_safe("self");
  if (maps == NULL) {
    LOGE("Failed to scan maps for the library at %p", (void *)base_addr);

    return false;
  }

  /* INFO: The module may pass the load base, the load bias or any address
            inside the library, so the owning mapping is found first and its
            file identity is then resolved to the mapping at offset zero,
            which is what LSPlt keys on. */
  bool found = false;
  for (size_t i = 0; i < maps->length; i++) {
    struct map_entry *entry = &maps->maps[i];

    if (entry->inode == 0 || entry->path == NULL) continue;

    uintptr_t load_base = entry->start - entry->offset;
    bool inside = (base_addr >= entry->start && base_addr < entry->end) ||
                  base_addr == entry->start || base_addr == load_base;
    if (!inside) continue;

    for (size_t j = 0; j < maps->length; j++) {
      struct map_entry *head = &maps->maps[j];

      if (head->dev == entry->dev && head->inode == entry->inode && head->offset == 0) {
        *dev = head->dev;
        *inode = head->inode;
        found = true;

        break;
      }
    }

    if (!found) {
      *dev = entry->dev;
      *inode = entry->inode;
      found = true;
    }

    break;
  }

  free_maps(maps);

  if (!found) {
    LOGE("No library mapped at %p", (void *)base_addr);

    return false;
  }

  /* INFO: Evict the oldest entry when the table is full, so a module that
            hooks many libraries keeps the most recently touched ones. */
  if (zn_plt_locations_len == ZN_PLT_LOCATION_CACHE) {
    memmove(&zn_plt_locations[0], &zn_plt_locations[1],
            (ZN_PLT_LOCATION_CACHE - 1) * sizeof(struct zn_plt_location));
    zn_plt_locations_len--;
  }

  zn_plt_locations[zn_plt_locations_len].base = base_addr;
  zn_plt_locations[zn_plt_locations_len].dev = *dev;
  zn_plt_locations[zn_plt_locations_len].inode = *inode;
  zn_plt_locations_len++;

  return true;
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

  /* INFO: A NULL backup means LSPlt never replaced an entry for this symbol.
           The previous code still reported success and handed the module a
           NULL original, which a module that trusts the return value would
           then call. Fail instead, before *original is touched. */
  if (backup == NULL) {
    LOGE("No PLT entry was replaced for %s", symbol);

    return ZN_FAILED;
  }

  if (original != NULL) *original = backup;

  return ZN_SUCCESS;
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

/* INFO: st_value is a link-time vaddr; the runtime address is the mapped ELF
         header (img->base) shifted by the difference to the first PT_LOAD's
         vaddr (img->bias), the same conversion getSymbAddress performs. */
static void *symbol_to_address(ElfImg *img, ElfW(Sym) *sym) {
  if (sym->st_value == 0) return NULL;

  return (void *)((uintptr_t)img->base + sym->st_value - img->bias);
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

/* INFO: The HyperOS runtime. On HyperOS, applications are forked by
         /system_ext/bin/hyos_spawner rather than the classic zygote, and
         modules that care speak the runtime contract: getRuntime() hands out
         the table, registerModule() copies the callbacks in, and
         zn_runtime_notify_app_specialized() (called from the specialize
         post hook) fires every registered onAppSpecialized with the
         specialization strings. The registry lives in this process's memory,
         so children forked from the spawner inherit it. */
#define ZN_HYOS_MODULE_MAX 16

static struct ZygiskNextHyosModule zn_hyos_modules[ZN_HYOS_MODULE_MAX];
static size_t zn_hyos_module_count = 0;

/* INFO: The spawner forks applications itself, so the ART hooks that announce
         a specialization in a zygote simply are not there: nothing calls
         forkAndSpecialize in this process tree. What every forked app does go
         through is our own pthread_atfork and, on the system's side,
         selinux_android_setcontext — and that call carries the uid, the seinfo
         and the package name, which is exactly what onAppSpecialized promises.
         pthread_setname_np adds the process name Android sets right after.

         Without these the runtime table is handed out but nothing ever fires,
         and a module waiting on onAppSpecialized just never runs. */
static bool zn_hyos_in_child = false;
static bool zn_hyos_fired = false;
static bool zn_hyos_has_process_name = false;
static bool zn_hyos_atfork_installed = false;
static char zn_hyos_process_name[256];

typedef pid_t (*zn_hyos_fork_fn)(void);
typedef int (*zn_hyos_setcontext_fn)(uid_t uid, int is_system_server, const char *se_info, const char *pkg_name);
typedef int (*zn_hyos_setname_fn)(pthread_t thread, const char *name);

static zn_hyos_fork_fn zn_hyos_original_fork = NULL;
static zn_hyos_setcontext_fn zn_hyos_original_setcontext = NULL;
static zn_hyos_setname_fn zn_hyos_original_setname = NULL;
static bool zn_hyos_hooks_warned = false;

/* INFO: File identity of the spawner's own executable, so its PLT entries
         can be hooked (YukiSU style). Rewriting spawner code in place for an
         inline hook can fail where the image is not writable, while a GOT
         entry always is. */
static dev_t zn_hyos_spawner_dev = 0;
static ino_t zn_hyos_spawner_inode = 0;

static bool zn_hyos_spawner_file_identity(dev_t *dev, ino_t *inode) {
  if (zn_hyos_spawner_inode != 0) {
    *dev = zn_hyos_spawner_dev;
    *inode = zn_hyos_spawner_inode;

    return true;
  }

  struct maps_info *maps = parse_maps_safe("self");
  if (maps == NULL) return false;

  bool found = false;
  for (size_t i = 0; i < maps->length; i++) {
    struct map_entry *entry = &maps->maps[i];

    if (entry->offset != 0 || entry->inode == 0 || entry->path == NULL) continue;
    if (strstr(entry->path, "hyos_spawner") == NULL) continue;

    zn_hyos_spawner_dev = entry->dev;
    zn_hyos_spawner_inode = entry->inode;
    *dev = zn_hyos_spawner_dev;
    *inode = zn_hyos_spawner_inode;
    found = true;

    LOGD("HyperOS runtime: spawner image at %s (dev %lu, inode %lu)",
         entry->path, (unsigned long)entry->dev, (unsigned long)entry->inode);

    break;
  }

  free_maps(maps);

  return found;
}

/* INFO: Marking the child at the fork return point is what actually fires:
         the spawner forks through its own PLT, and inline-hooking fork in a
         writable image is not always possible. */
static pid_t zn_hyos_fork_hook(void) {
  pid_t result = zn_hyos_original_fork != NULL ? zn_hyos_original_fork() : -1;

  if (result == 0) zn_hyos_atfork_child();

  return result;
}

/* INFO: Fires once per child: the callback contract promises exactly one
         onAppSpecialized per app process. */
static void zn_hyos_deliver(const char *pkg_name, const char *se_info) {
  if (!zn_hyos_in_child || zn_hyos_fired || zn_hyos_module_count == 0) return;

  zn_hyos_fired = true;

  const char *process_name = zn_hyos_has_process_name ? zn_hyos_process_name : "hyos_app";

  LOGD("HyperOS runtime: app specialized, process=%s package=%s", process_name, pkg_name);

  /* INFO: The contract hands the modules strings, never NULL: a package the
            platform did not resolve is an empty one. */
  zn_runtime_notify_app_specialized(process_name,
                                    pkg_name != NULL ? pkg_name : "",
                                    se_info != NULL ? se_info : "");
}

static int zn_hyos_setcontext_hook(uid_t uid, int is_system_server, const char *se_info, const char *pkg_name) {
  int result = zn_hyos_original_setcontext != NULL
    ? zn_hyos_original_setcontext(uid, is_system_server, se_info, pkg_name)
    : -1;

  if (result == 0) {
    zn_hyos_deliver(pkg_name, se_info);
  } else if (zn_hyos_in_child && !zn_hyos_fired) {
    LOGW("HyperOS runtime: selinux_android_setcontext failed (%d)", result);
  }

  return result;
}

static int zn_hyos_setname_hook(pthread_t thread, const char *name) {
  int result = zn_hyos_original_setname != NULL ? zn_hyos_original_setname(thread, name) : -1;

  if (result == 0 && !zn_hyos_has_process_name && zn_hyos_in_child && !zn_hyos_fired && name != NULL) {
    snprintf(zn_hyos_process_name, sizeof(zn_hyos_process_name), "%s", name);
    zn_hyos_has_process_name = true;

    LOGD("HyperOS runtime: captured process name %s", zn_hyos_process_name);
  }

  return result;
}

static void zn_hyos_atfork_child(void) {
  zn_hyos_in_child = true;
  zn_hyos_fired = false;
  zn_hyos_has_process_name = false;
  zn_hyos_process_name[0] = '\0';
}

/* INFO: Installed from the fork prepare handler as well as at registration:
         the hooks have to be in place before the child runs, and a library
         loaded later may have brought the symbols with it. */
static void zn_hyos_install_hooks(void) {
  /* INFO: YukiSU-style PLT hooks on the spawner's own image are tried first:
           they only rewrite GOT entries, which always works, whereas an
           inline hook rewrites code and can be refused. The spawner calls
           fork and selinux_android_setcontext through its own PLT. */
  dev_t spawner_dev = 0;
  ino_t spawner_inode = 0;

  if (zn_hyos_spawner_file_identity(&spawner_dev, &spawner_inode)) {
    if (zn_hyos_original_fork == NULL) {
      void *backup = NULL;

      if (zn_lsplt_register_hook(spawner_dev, spawner_inode, "fork",
                                 (void *)(uintptr_t)zn_hyos_fork_hook, &backup) == 0 &&
          zn_lsplt_commit_hook() == 0 && backup != NULL) {
        zn_hyos_original_fork = (zn_hyos_fork_fn)(uintptr_t)backup;

        LOGD("HyperOS runtime: PLT hooked fork in the spawner");
      }
    }

    if (zn_hyos_original_setcontext == NULL) {
      void *backup = NULL;

      if (zn_lsplt_register_hook(spawner_dev, spawner_inode, "selinux_android_setcontext",
                                 (void *)(uintptr_t)zn_hyos_setcontext_hook, &backup) == 0 &&
          zn_lsplt_commit_hook() == 0 && backup != NULL) {
        zn_hyos_original_setcontext = (zn_hyos_setcontext_fn)(uintptr_t)backup;

        LOGD("HyperOS runtime: PLT hooked selinux_android_setcontext in the spawner");
      }
    }
  }

  if (zn_hyos_original_setcontext == NULL) {
    void *target = dlsym(RTLD_DEFAULT, "selinux_android_setcontext");

    if (target == NULL) {
      void *handle = dlopen("libselinux.so", RTLD_NOW);
      if (handle != NULL) target = dlsym(handle, "selinux_android_setcontext");
    }

    if (target != NULL) {
      void *backup = NULL;

      if (zn_inline_hook(target, (void *)(uintptr_t)zn_hyos_setcontext_hook, &backup) == ZN_SUCCESS) {
        zn_hyos_original_setcontext = (zn_hyos_setcontext_fn)(uintptr_t)backup;

        LOGD("HyperOS runtime: inline hooked selinux_android_setcontext at %p", target);
      }
    }
  }

  if (zn_hyos_original_setname == NULL) {
    void *target = dlsym(RTLD_DEFAULT, "pthread_setname_np");

    if (target == NULL) {
      void *handle = dlopen("libc.so", RTLD_NOW);
      if (handle != NULL) target = dlsym(handle, "pthread_setname_np");
    }

    if (target != NULL) {
      void *backup = NULL;

      if (zn_inline_hook(target, (void *)(uintptr_t)zn_hyos_setname_hook, &backup) == ZN_SUCCESS) {
        zn_hyos_original_setname = (zn_hyos_setname_fn)(uintptr_t)backup;

        LOGD("HyperOS runtime: hooked pthread_setname_np at %p", target);
      }
    }
  }

  if (zn_hyos_original_setcontext == NULL && !zn_hyos_hooks_warned) {
    zn_hyos_hooks_warned = true;

    LOGW("HyperOS runtime: selinux_android_setcontext is unreachable, onAppSpecialized will not fire");
  }
}

static void zn_hyos_atfork_prepare(void) {
  if (zn_hyos_module_count > 0) zn_hyos_install_hooks();
}

static int zn_hyos_register_module(const void *module_ptr) {
  const struct ZygiskNextHyosModule *module = (const struct ZygiskNextHyosModule *)module_ptr;

  if (module == NULL || module->onAppSpecialized == NULL) return ZN_FAILED;

  if (module->target_api_version <= 0 || module->target_api_version > ZYGISK_NEXT_HYOS_API_VERSION) {
    LOGE("HyperOS runtime module targets API %d, supported is 1..%d",
         module->target_api_version, ZYGISK_NEXT_HYOS_API_VERSION);

    return ZN_FAILED;
  }

  if (zn_hyos_module_count >= ZN_HYOS_MODULE_MAX) {
    LOGE("Reached the limit of %d HyperOS runtime modules", ZN_HYOS_MODULE_MAX);

    return ZN_FAILED;
  }

  /* INFO: The contract is that the runtime copies the structure before
            returning, so a module may reuse its storage. */
  zn_hyos_modules[zn_hyos_module_count++] = *module;

  /* INFO: Only the spawner itself registers. The children it forks inherit
            the table through fork, and re-arming the fork handlers in each of
            them would stack up one pair per registration. */
  if (!zn_hyos_in_child && !zn_hyos_atfork_installed) {
    zn_hyos_atfork_installed = true;

    pthread_atfork(zn_hyos_atfork_prepare, NULL, zn_hyos_atfork_child);
  }

  zn_hyos_install_hooks();

  LOGD("HyperOS runtime: module registered (%zu total)", zn_hyos_module_count);

  return ZN_SUCCESS;
}

static const struct ZygiskNextRuntime zn_hyos_runtime = {
  .type = ZN_RUNTIME_HYOS,
  .api_version = ZYGISK_NEXT_HYOS_API_VERSION,
  .registerModule = zn_hyos_register_module
};

/* INFO: The runtime is exposed in the hyos_spawner process tree only: the
         spawner and the apps it forks all carry the same /proc/self/exe,
         and a registration made there is inherited by every child. */
/* INFO: The spawner and every app it forks carry the same /proc/self/exe, so
         this identifies the whole tree. An upgraded binary leaves a
         " (deleted)" suffix on the link target. */
static bool zn_hyos_process_is_spawner(void) {
  static int is_spawner = -1;

  if (is_spawner == -1) {
    is_spawner = 0;

    char exe[PATH_MAX];
    ssize_t length = readlink("/proc/self/exe", exe, sizeof(exe) - 1);

    if (length > 0) {
      exe[length] = '\0';

      size_t len = (size_t)length;
      if (len > 10 && strcmp(exe + len - 10, " (deleted)") == 0) {
        len -= 10;
        exe[len] = '\0';
      }

      const char *base = strrchr(exe, '/');

      is_spawner = strcmp(base == NULL ? exe : base + 1, "hyos_spawner") == 0;
    }
  }

  return is_spawner == 1;
}

bool zn_is_hyos_spawner(void) {
  return zn_hyos_process_is_spawner();
}

static const struct ZygiskNextRuntime *zn_get_runtime(void) {
  return zn_hyos_process_is_spawner() ? &zn_hyos_runtime : NULL;
}

bool zn_hyos_modules_registered(void) {
  return zn_hyos_module_count > 0;
}

void zn_runtime_notify_app_specialized(const char *process_name, const char *package_name, const char *se_info) {
  if (zn_hyos_module_count == 0) return;
  /* INFO: The strings are read-only and only valid for the duration of the
            callback, exactly as the contract promises. */
  struct ZnHyosAppSpecializeArgs args = {
    .process_name = process_name,
    .package_name = package_name,
    .se_info = se_info
  };

  for (size_t i = 0; i < zn_hyos_module_count; i++) {
    zn_hyos_modules[i].onAppSpecialized(&args);
  }
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
