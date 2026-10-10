#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <dlfcn.h>
#include <unistd.h>
#include <dobby.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/types.h>

#include "elf_util.h"
#include "logging.h"
#include "misc.h"
#include "zn_spawner.h"

#include "zn_api.h"
#include "zn_loader.h"

/* INFO: The Zygisk Next pltHook is served by LSPlt, the hooking engine the
         LSPosed ecosystem builds its modules against, exactly as NyaZygisk
         does. The injector is C, so the C++ island is confined to the
         zn_lsplt_shim.cpp bridge and the static library behind it. */
int zn_lsplt_register_hook(dev_t dev, ino_t inode, const char *symbol, void *hook, void **backup);
int zn_lsplt_commit_hook(void);

/* INFO: LSPlt identifies libraries by file identity (device + inode) while the ZN
          API hands us a base address, so the owning mapping is looked up in the
          process maps.

          The scan is redone per call, which is what the reference does and what
          keeps the answer honest: a cached identity goes stale the moment a
          library is unloaded and another one is mapped where it was, and a
          pltHook then lands on the wrong file. Nothing here is shared between
          threads either, so no lock is needed. */
static bool get_lib_location_by_base(uintptr_t base_addr, dev_t *dev, ino_t *inode) {
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
         is rejected instead of piling a second trampoline on top. The table
         itself is unbounded, exactly as NyaZygisk's is - a module that hooks
         many addresses is not refused at an arbitrary cap; it only fails when
         memory does. */
static pthread_mutex_t zn_hooked_lock = PTHREAD_MUTEX_INITIALIZER;
static uintptr_t *zn_hooked = NULL;
static size_t zn_hooked_count = 0;
static size_t zn_hooked_capacity = 0;

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

  if (zn_hooked_count == zn_hooked_capacity) {
    size_t capacity = zn_hooked_capacity == 0 ? 16 : zn_hooked_capacity * 2;

    uintptr_t *grown = (uintptr_t *)realloc(zn_hooked, capacity * sizeof(uintptr_t));

    if (grown == NULL) {
      pthread_mutex_unlock(&zn_hooked_lock);

      LOGE("Failed growing the inline hook table for %p", (void *)address);

      return ZN_FAILED;
    }

    zn_hooked = grown;
    zn_hooked_capacity = capacity;
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

/* INFO: Lookup order mirrors Zygisk Next: the parsed symbol tables are walked
           first - the file .symtab, then .dynsym, then the .gnu_debugdata
           mini-debug symbols - and an exact lookup that finds nothing there
           falls back to the hash tables of the dynamic symbol section. A prefix
           request is only ever served from those tables, which is why .dynsym
           has to be among them. */
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

      /* INFO: A match whose value converts to no address is not a hit the
                module can use, so it does not end the search - and *size is
                left alone rather than describing a symbol nobody can call. */
      void *addr = symbol_to_address(img, sym);
      if (addr == NULL) continue;

      if (size != NULL) *size = sym->st_size;

      return addr;
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

  /* INFO: The seen-set is keyed on the symbol name, which is what identifies a
            symbol across tables. Now that the walk covers .symtab, .dynsym and
            the mini-debug table, one function is routinely described by all
            three; reporting it twice hands the module a second entry for an
            address it was already asked to hook, which its own duplicate check
            then refuses - so the repeat reads as a failure instead of as the
            same symbol. The name stays valid for the walk: it points into the
            mapped image or the decompressed mini-debug buffer. */
  char **seen = NULL;
  size_t seen_count = 0;
  size_t seen_capacity = 0;

  for (size_t i = 0; i < img->symtabs_count_; i++) {
    ElfW(Sym) *sym = img->symtabs_[i];

    const char *name = getSymbName(img, sym);
    if (name == NULL || name[0] == '\0') continue;

    void *addr = symbol_to_address(img, sym);
    if (addr == NULL) continue;

    bool duplicate = false;
    for (size_t j = 0; j < seen_count; j++) {
      if (strcmp(seen[j], name) == 0) {
        duplicate = true;

        break;
      }
    }

    if (duplicate) continue;

    if (seen_count == seen_capacity) {
      size_t capacity = seen_capacity == 0 ? 64 : seen_capacity * 2;

      char **grown = (char **)realloc(seen, capacity * sizeof(char *));
      if (grown == NULL) {
        LOGE("Failed growing the duplicate filter, reporting %s anyway", name);
      } else {
        seen = grown;
        seen_capacity = capacity;
      }
    }

    if (seen_count < seen_capacity) seen[seen_count++] = (char *)name;

    if (!callback(name, addr, sym->st_size, data)) break;
  }

  free(seen);
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

    /* INFO: [heap], [stack] and the anon mappings are not files. Handing one
              back as a path would only produce an open() that fails. */
    if (entry->path[0] == '[') continue;

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

  /* INFO: The path is tried as given first, exactly as the reference does. A
            bare soname is only resolved against the loaded mappings when it
            does not open - a caller that passes a real path that happens to
            resolve should get that file, not whatever the maps hold under the
            same name. */
  struct ZnSymbolResolver *resolver = (struct ZnSymbolResolver *)ElfImg_create(path, base_addr);
  if (resolver != NULL) return resolver;

  if (strchr(path, '/') != NULL) return NULL;

  char *resolved = get_lib_path_by_name(path);
  if (resolved == NULL) return NULL;

  resolver = (struct ZnSymbolResolver *)ElfImg_create(resolved, base_addr);

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

/* INFO: On HyperOS the spawner forks applications itself, so the ART hooks that
          announce a specialization in a zygote are absent. What every forked app
          does go through is, system-side, selinux_android_setcontext - which
          carries uid, seinfo and package name, exactly what onAppSpecialized
          promises; pthread_setname_np adds the process name. Without these the
          runtime table is handed out but nothing ever fires.

          Which process is a child is decided from the pid, not from a fork
          hook: the spawner is not guaranteed to fork through libc (a raw
          clone() runs no pthread_atfork handler), and bionic caches getpid(),
          so the syscall is what has to be read. */
static bool zn_hyos_fired = false;
static bool zn_hyos_has_process_name = false;
static bool zn_hyos_atfork_installed = false;
static char zn_hyos_process_name[256];

/* INFO: Whether zn_init_hyos_runtime() ran in this process, which is what
          getRuntime() answers from. This is how the implementation the runtime
          was ported from answers it, and it is the stable answer: decided once
          in entry() by a check that has already succeeded, instead of being
          re-derived from the process on every call - which gave the scan its
          own ways to say no, and left getRuntime() returning nullptr in a
          process that had been identified as the spawner. */
static bool zn_hyos_runtime_enabled = false;

/* INFO: The pid the runtime was initialized in, which is the spawner itself.
          Every app it forks has the same executable and a different pid, so
          that difference is what tells a child apart. Zero until
          zn_init_hyos_runtime() ran, so nothing is a child before then. */
static pid_t zn_hyos_spawner_pid = 0;

static bool zn_hyos_in_child(void) {
  return zn_hyos_spawner_pid != 0 && (pid_t)syscall(__NR_getpid) != zn_hyos_spawner_pid;
}

typedef int (*zn_hyos_setcontext_fn)(uid_t uid, int is_system_server, const char *se_info, const char *pkg_name);
typedef int (*zn_hyos_setname_fn)(pthread_t thread, const char *name);

static zn_hyos_setcontext_fn zn_hyos_original_setcontext = NULL;
static zn_hyos_setname_fn zn_hyos_original_setname = NULL;
static bool zn_hyos_hooks_warned = false;

/* INFO: The file name HyperOS gives the Rust runtime image, and the reason it is
         not the only thing that identifies the spawner, now live in
         zn_spawner.h - this file only decides which of them to ask.

         The history is worth keeping, because the two answers have each been
         the wrong one on a device at some point. An exe-only check is why
         getRuntime() answered "no runtime" on a HyperOS 4 build while everything
         else looked correct: the process hosting the runtime was an app_process
         binary with the spawner image mapped into it, so its executable name
         read app_process64. A maps-only check then read as a match in processes
         that merely had the image inherited, which is why the exe came back.
         Neither alone is the answer; see zn_spawner.h for why asking both is
         safe and what each one survives. */

/* INFO: File identity of the spawner's own executable, so its PLT entries
         can be hooked (YukiSU style). Rewriting spawner code in place for an
         inline hook can fail where the image is not writable, while a GOT
         entry always is.

         The name alone is not enough to accept a mapping: it is what the
         sibling implementation in YukiZygisk checks, and for the same reason -
         a path can be spelled the spawner's way while the bytes behind it are
         something else. */
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
    if (!zn_spawner_path_is_image(entry->path, strlen(entry->path))) continue;

    /* INFO: The listing carries mappings this process may not read, and the
              header below is what decides the question - so the permissions
              are read first. Dereferencing a PROT_NONE mapping is a segfault
              in the injected process, which is the one failure mode worse than
              answering "not the spawner". */
    if ((entry->perms & PROT_READ) == 0) continue;
    if (!zn_spawner_elf_is_image((const unsigned char *)entry->start, (size_t)(entry->end - entry->start))) continue;

    zn_hyos_spawner_dev = entry->dev;
    zn_hyos_spawner_inode = entry->inode;
    *dev = zn_hyos_spawner_dev;
    *inode = zn_hyos_spawner_inode;
    found = true;

    LOGI("HyperOS runtime: spawner image at %s (dev %lu, inode %lu)",
         entry->path, (unsigned long)entry->dev, (unsigned long)entry->inode);

    break;
  }

  free_maps(maps);

  return found;
}

/* INFO: The process name of last resort, read the way NyaZygisk reads it:
         /proc/self/cmdline, one byte at a time, counting a lone NUL as "the
         kernel has nothing" rather than as a name. */
static bool zn_hyos_read_cmdline(char *out, size_t max_len) {
  if (out == NULL || max_len == 0) return false;

  int fd;
  do {
    fd = open("/proc/self/cmdline", O_RDONLY | O_CLOEXEC);
  } while (fd == -1 && errno == EINTR);

  if (fd == -1) return false;

  size_t length = 0;
  bool complete = false;

  while (length + 1 < max_len) {
    char value = '\0';
    ssize_t got;

    do {
      got = read(fd, &value, sizeof(value));
    } while (got == -1 && errno == EINTR);

    if (got != (ssize_t)sizeof(value)) break;

    if (value == '\0') {
      complete = length != 0;

      break;
    }

    out[length++] = value;
  }

  close(fd);

  out[length] = '\0';

  return complete;
}

/* INFO: Fires once per child: the callback contract promises exactly one
          onAppSpecialized per app process. */
static void zn_hyos_deliver(const char *pkg_name, const char *se_info) {
  if (!zn_hyos_in_child() || zn_hyos_fired || zn_hyos_module_count == 0) return;

  zn_hyos_fired = true;

  char process_name[256];
  char package_name[256];
  char se_info_buf[64];

  if (zn_hyos_has_process_name && zn_hyos_process_name[0] != '\0') {
    snprintf(process_name, sizeof(process_name), "%s", zn_hyos_process_name);
  } else if (!zn_hyos_read_cmdline(process_name, sizeof(process_name)) || process_name[0] == '\0') {
    /* INFO: prctl leaves the buffer untouched when it fails, and the condition
              below reads the first byte regardless. Clearing it first keeps a
              failed PR_GET_NAME from being taken for the length of whatever
              the stack happened to hold, which snprintf would then read as a
              string. */
    process_name[0] = '\0';

    if (prctl(PR_GET_NAME, process_name, 0, 0, 0) != 0 || process_name[0] == '\0') {
      snprintf(process_name, sizeof(process_name), "%s", "hyos_app");
    }
  }

  snprintf(package_name, sizeof(package_name), "%s", pkg_name != NULL ? pkg_name : "");
  snprintf(se_info_buf, sizeof(se_info_buf), "%s", se_info != NULL ? se_info : "");

  LOGI("HyperOS runtime: app specialized, process=%s package=%s se_info=%s",
       process_name, package_name, se_info_buf);

  /* INFO: The contract hands the modules strings, never NULL: a package the
            platform did not resolve is an empty one. */
  zn_runtime_notify_app_specialized(process_name, package_name, se_info_buf);
}

static int zn_hyos_setcontext_hook(uid_t uid, int is_system_server, const char *se_info, const char *pkg_name) {
  int result = zn_hyos_original_setcontext != NULL
    ? zn_hyos_original_setcontext(uid, is_system_server, se_info, pkg_name)
    : -1;

  if (result == 0) {
    zn_hyos_deliver(pkg_name, se_info);
  } else if (zn_hyos_in_child() && !zn_hyos_fired) {
    LOGW("HyperOS runtime: selinux_android_setcontext failed (%d)", result);
  }

  return result;
}

static int zn_hyos_setname_hook(pthread_t thread, const char *name) {
  int result = zn_hyos_original_setname != NULL ? zn_hyos_original_setname(thread, name) : -1;

  /* INFO: Only thread's own name counts as this process's name; the spawner
            names its helpers too, and the child check is what keeps the
            spawner's own threads from being captured. */
  if (result == 0 && !zn_hyos_has_process_name && !zn_hyos_fired && name != NULL && name[0] != '\0' &&
      pthread_equal(thread, pthread_self()) && zn_hyos_in_child()) {
    snprintf(zn_hyos_process_name, sizeof(zn_hyos_process_name), "%s", name);
    zn_hyos_has_process_name = true;

    LOGI("HyperOS runtime: captured process name %s", zn_hyos_process_name);
  }

  return result;
}

/* INFO: One PLT hook on the spawner's own image. A symbol the image does not
         import has no GOT entry to rewrite, which is not a failure: the inline
         hook below covers that case, so NULL is returned and the caller falls
         back. */
static void *zn_hyos_plt_hook_spawner(dev_t dev, ino_t inode, const char *symbol, void *hook) {
  void *backup = NULL;

  if (zn_lsplt_register_hook(dev, inode, symbol, hook, &backup) == 0 &&
      zn_lsplt_commit_hook() == 0 && backup != NULL) {
    LOGI("HyperOS runtime: PLT hooked %s in the spawner", symbol);

    return backup;
  }

  LOGW("HyperOS runtime: PLT hook of %s failed, falling back to an inline hook", symbol);

  return NULL;
}

/* INFO: Installed from the fork prepare handler as well as at registration:
         the hooks have to be in place before the child runs, and a library
         loaded later may have brought the symbols with it. */
static void zn_hyos_install_hooks(void) {
  /* INFO: YukiSU-style PLT hooks on the spawner's own image are tried first:
           they only rewrite GOT entries, which always works, whereas an
           inline hook rewrites code and can be refused. The spawner reaches
           selinux_android_setcontext and pthread_setname_np through its own
           PLT. fork is not hooked any more: the child state is read from the
           pid instead. */
  dev_t spawner_dev = 0;
  ino_t spawner_inode = 0;

  if (zn_hyos_spawner_file_identity(&spawner_dev, &spawner_inode)) {
    if (zn_hyos_original_setcontext == NULL) {
      zn_hyos_original_setcontext = (zn_hyos_setcontext_fn)(uintptr_t)zn_hyos_plt_hook_spawner(
        spawner_dev, spawner_inode, "selinux_android_setcontext", (void *)(uintptr_t)zn_hyos_setcontext_hook);
    }

    if (zn_hyos_original_setname == NULL) {
      zn_hyos_original_setname = (zn_hyos_setname_fn)(uintptr_t)zn_hyos_plt_hook_spawner(
        spawner_dev, spawner_inode, "pthread_setname_np", (void *)(uintptr_t)zn_hyos_setname_hook);
    }
  }

  if (zn_hyos_original_setcontext == NULL) {
    void *target = dlsym(RTLD_DEFAULT, "selinux_android_setcontext");

    if (target == NULL) {
      /* INFO: The handle is deliberately not closed. Closing it would drop the
                reference this dlopen took, and a process where nothing else
                holds libselinux.so would have it unloaded - leaving the address
                just resolved, and the inline hook written through it, pointing
                into an unmapped library. One handle per spawner is the cheaper
                side of that trade. */
      void *handle = dlopen("libselinux.so", RTLD_NOW);
      if (handle != NULL) target = dlsym(handle, "selinux_android_setcontext");
    }

    if (target != NULL) {
      void *backup = NULL;

      if (zn_inline_hook(target, (void *)(uintptr_t)zn_hyos_setcontext_hook, &backup) == ZN_SUCCESS) {
        zn_hyos_original_setcontext = (zn_hyos_setcontext_fn)(uintptr_t)backup;

        LOGI("HyperOS runtime: inline hooked selinux_android_setcontext at %p", target);
      }
    }
  }

  if (zn_hyos_original_setname == NULL) {
    void *target = dlsym(RTLD_DEFAULT, "pthread_setname_np");

    if (target == NULL) {
      /* INFO: Not closed, for the reason given for libselinux.so above. */
      void *handle = dlopen("libc.so", RTLD_NOW);
      if (handle != NULL) target = dlsym(handle, "pthread_setname_np");
    }

    if (target != NULL) {
      void *backup = NULL;

      if (zn_inline_hook(target, (void *)(uintptr_t)zn_hyos_setname_hook, &backup) == ZN_SUCCESS) {
        zn_hyos_original_setname = (zn_hyos_setname_fn)(uintptr_t)backup;

        LOGI("HyperOS runtime: inline hooked pthread_setname_np at %p", target);
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

  if (module->target_api_version > ZYGISK_NEXT_HYOS_API_VERSION) {
    LOGE("HyperOS runtime module targets API %d, only up to %d is supported",
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
  if (!zn_hyos_in_child()) {
    if (!zn_hyos_atfork_installed) {
      zn_hyos_atfork_installed = true;

      /* INFO: The prepare hook re-installs late-arrived symbols before a
                fork; the child needs no hook of its own now that its state
                is read from the pid. */
      pthread_atfork(zn_hyos_atfork_prepare, NULL, NULL);
    }

    zn_hyos_install_hooks();
  }

  LOGI("HyperOS runtime: module registered (%zu total)", zn_hyos_module_count);

  return ZN_SUCCESS;
}

static const struct ZygiskNextRuntime zn_hyos_runtime = {
  .type = ZN_RUNTIME_HYOS,
  .api_version = ZYGISK_NEXT_HYOS_API_VERSION,
  .registerModule = zn_hyos_register_module
};

/* INFO: Whether the HyperOS Rust runtime is reachable from this process. This
         is the question the ZN runtime API answers, and the one the injector
         needs before it picks its hook set, so both read it from here.

         The runtime is exposed in the hyos_spawner process tree only, and a
         registration made in the spawner is inherited by every child, which is
         exactly what the runtime contract wants. Which process *is* the spawner
         is answered from two independent places and either one is enough - the
         executable's own name, and the image it is mapped from. zn_spawner.h
         has the reasoning; what this adds is that both are asked, so neither a
         rename nor an unreadable /proc/self/exe turns the spawner into the
         branch that installs the JNI hooks. */
static bool zn_hyos_process_is_spawner(void) {
  static int is_spawner = -1;

  if (is_spawner != -1) return is_spawner == 1;

  char path[PATH_MAX];
  ssize_t len = read_exe_path((int)getpid(), path, sizeof(path));

  if (len > 0 && zn_spawner_path_is_image(path, (size_t)len)) {
    is_spawner = 1;

    LOGI("HyperOS runtime: the executable is the spawner (%s)", path);

    return true;
  }

  /* INFO: The name did not say so, which is not the same as "no": it is also
           what an unreadable /proc/self/exe and a build that runs the spawner
           under another name look like. The image underneath does say so, and
           it is the answer the sibling implementations take. */
  dev_t dev = 0;
  ino_t inode = 0;

  if (zn_hyos_spawner_file_identity(&dev, &inode)) {
    is_spawner = 1;

    LOGI("HyperOS runtime: the spawner image is mapped here (exe %s), taking this process for the spawner",
         len > 0 ? path : "(unreadable)");

    return true;
  }

  is_spawner = 0;

  LOGD("HyperOS runtime: not the spawner (exe %s)", len > 0 ? path : "(unreadable)");

  return false;
}

/* INFO: Remembers which process the runtime belongs to. Called once, in the
         spawner, before any module can register: every later "is this a
         child?" answer is that pid against the current one.

         Idempotent on purpose. A process forked from the spawner inherits the
         recorded pid, so a second call there would answer "this is the
         spawner" with the child's own pid and make zn_hyos_in_child() false
         for the rest of its life - onAppSpecialized would then never fire for
         that app, silently. Only the first call in a fresh process counts. */
void zn_init_hyos_runtime(void) {
  /* INFO: Idempotent, because the flag is inherited by every app the spawner
            forks: a second call in one of them would otherwise pin the runtime
            to the child and leave it answering "not a child" about itself. */
  if (zn_hyos_runtime_enabled) return;

  zn_hyos_runtime_enabled = true;
  zn_hyos_spawner_pid = (pid_t)syscall(__NR_getpid);

  LOGI("HyperOS runtime enabled in pid %d", zn_hyos_spawner_pid);
}

bool zn_is_hyos_spawner(void) {
  return zn_hyos_process_is_spawner();
}

static const struct ZygiskNextRuntime *zn_get_runtime(void) {
  /* INFO: Answered from the flag zn_init_hyos_runtime() set rather than from a
            fresh look at the process. entry() has already decided what this
            process is, and a module asking for the runtime has to be given the
            answer entry() reached - a second, independent check can only
            disagree with it, and disagreeing means handing out nullptr to a
            module loaded into a process that does have a runtime. */
  if (!zn_hyos_runtime_enabled) {
    LOGD("HyperOS runtime: getRuntime() in a process that has no runtime");

    return NULL;
  }

  return &zn_hyos_runtime;
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
