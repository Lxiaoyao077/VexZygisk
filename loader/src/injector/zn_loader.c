#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <dlfcn.h>

#include <android/dlext.h>
#include <dirent.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <linux/memfd.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include "daemon.h"
#include "logging.h"

#include "zn_api.h"
#include "zn_loader.h"

#define ZN_MODULES_DIR "/data/adb/modules"
#define ZN_MAX_MODULES 32

/* INFO: Command byte a module sends through the companion control socket to
         request a new connection. Mirrors K_CMD_CONNECT on the daemon side. */
#define ZN_COMPANION_CMD_CONNECT 1

/* INFO: The kernel may copy a cmsghdr into the control buffer, so it has to be
         aligned as one instead of being a plain byte array. */
union zn_cmsg_buffer {
  struct cmsghdr header;
  char control[CMSG_SPACE(sizeof(int))];
};

struct zn_entry {
  bool is_name;
  bool companion;
  char *target;
  char *lib_path;
  int companion_fd;
};

/* INFO: Loaded libraries are kept for the whole life of the process, a module
         is never unloaded once its callbacks are installed. The entries are
         handed to the modules as their self handle, so they must outlive the
         scan that produced them. */
static void *loaded_libs[ZN_MAX_MODULES];
static struct zn_entry loaded_entries[ZN_MAX_MODULES];
static size_t loaded_libs_count = 0;

/* INFO: The ZN modules are loaded by the system linker, exactly as Zygisk Next
         does it. dlopen() of a path under /data/adb fails for most targets
         because the linker's namespace "permitted path" check rejects
         non-system paths, and loading through a plain fd (a memfd handed over
         by the daemon) is also rejected: bionic re-checks namespace
         accessibility for every fd that does not live on tmpfs. Copying the
         bytes into a memfd owned by this process sidesteps both checks.

         The memfd is deliberately left open: bionic does not take ownership of
         ANDROID_DLEXT_USE_LIBRARY_FD descriptors and may keep reading from
         them for the whole life of the loaded library. */
static void *dlopen_via_fd(const char *path, int flags) {
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    LOGE("dlopen %s: cannot open: %s", path, strerror(errno));

    return NULL;
  }

  int mem_fd = (int)syscall(SYS_memfd_create, "zn-module", MFD_CLOEXEC);
  if (mem_fd < 0) {
    LOGE("dlopen %s: memfd_create failed: %s", path, strerror(errno));

    close(fd);

    return NULL;
  }

  char buffer[65536];
  ssize_t got;
  bool copied = true;

  while ((got = TEMP_FAILURE_RETRY(read(fd, buffer, sizeof(buffer)))) > 0) {
    size_t left = (size_t)got;
    const char *cursor = buffer;

    while (left > 0) {
      ssize_t written = TEMP_FAILURE_RETRY(write(mem_fd, cursor, left));
      if (written <= 0) {
        copied = false;

        break;
      }

      cursor += written;
      left -= (size_t)written;
    }

    if (!copied) break;
  }

  close(fd);

  if (!copied || got < 0) {
    LOGE("dlopen %s: copy to memfd failed: %s", path, strerror(errno));

    close(mem_fd);

    return NULL;
  }

  android_dlextinfo info = { 0 };
  info.flags = ANDROID_DLEXT_USE_LIBRARY_FD;
  info.library_fd = mem_fd;

  void *lib = android_dlopen_ext(path, flags, &info);
  if (lib == NULL) LOGE("dlopen %s via memfd failed: %s", path, dlerror());

  /* INFO: The memfd stays open either way, see above. */
  return lib;
}

/* INFO: Same contract as dlopen_via_fd, but the memfd already exists: the
         daemon created it on our behalf, which is the only mode that works for
         a target that cannot read /data/adb itself. */
static void *dlopen_from_fd(int fd, const char *name, int flags) {
  android_dlextinfo info = { 0 };
  info.flags = ANDROID_DLEXT_USE_LIBRARY_FD;
  info.library_fd = fd;

  void *lib = android_dlopen_ext(name, flags, &info);
  if (lib == NULL) LOGE("dlopen %s from fd %d failed: %s", name, fd, dlerror());

  return lib;
}

static char *read_process_path(void) {
  char buf[PATH_MAX];
  ssize_t len = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
  if (len <= 0) return NULL;

  buf[len] = '\0';

  return strdup(buf);
}

static char *get_process_name(const char *process_path) {
  if (process_path == NULL) return NULL;

  const char *last_slash = strrchr(process_path, '/');

  return (char *)(last_slash == NULL ? process_path : last_slash + 1);
}

/* INFO: A line is "<name=|path=><target> [companion] <library>" */
static bool parse_line(const char *module_dir, const char *line, struct zn_entry *entry) {
  const char *cursor = line;
  char *tokens[8];
  size_t token_count = 0;

  while (*cursor != '\0' && token_count < 8) {
    while (*cursor != '\0' && isspace((unsigned char)*cursor)) cursor++;
    if (*cursor == '\0') break;

    const char *start = cursor;
    while (*cursor != '\0' && !isspace((unsigned char)*cursor)) cursor++;

    size_t length = (size_t)(cursor - start);
    tokens[token_count] = strndup(start, length);
    if (tokens[token_count] == NULL) break;

    token_count++;
  }

  if (token_count < 2) goto parse_line_cleanup;

  if (strncmp(tokens[0], "name=", 5) == 0) {
    entry->is_name = true;
  } else if (strncmp(tokens[0], "path=", 5) == 0) {
    entry->is_name = false;
  } else {
    goto parse_line_cleanup;
  }

  entry->target = strdup(tokens[0] + 5);
  if (entry->target == NULL) goto parse_line_cleanup;

  /* INFO: The library is always the last token, "companion" may sit anywhere
           between the target and it. Scanning only that range keeps a module
           named "companion" from being mistaken for the flag. */
  for (size_t i = 1; i + 1 < token_count; i++) {
    if (strcmp(tokens[i], "companion") == 0) entry->companion = true;
  }

  const char *library = tokens[token_count - 1];
  if (library[0] == '/') {
    entry->lib_path = strdup(library);
  } else {
    size_t size = strlen(module_dir) + strlen(library) + 2;
    entry->lib_path = malloc(size);
    if (entry->lib_path != NULL) snprintf(entry->lib_path, size, "%s/%s", module_dir, library);
  }

  parse_line_cleanup:
    for (size_t i = 0; i < token_count; i++) {
      free(tokens[i]);
    }

  return entry->target != NULL && entry->lib_path != NULL;
}

static bool matches_process(const struct zn_entry *entry, const char *process_path, const char *process_name) {
  if (entry->is_name) {
    if (strcmp(entry->target, "zygote") == 0 || strcmp(entry->target, "zygote64") == 0 || strcmp(entry->target, "zygote32") == 0)
      return strstr(process_name, "zygote") != NULL || strstr(process_name, "app_process") != NULL;

    return strcmp(process_name, entry->target) == 0;
  }

  return strcmp(process_path, entry->target) == 0;
}

/* INFO: Runs in the forked companion: loads the library again, announces itself
         with onCompanionLoaded and then serves every connectCompanion() the
         module performs. Each request carries one command byte plus the socket
         to hand over through SCM_RIGHTS. */
static void companion_main(const char *lib_path, int socket_fd) {
  void *lib = dlopen_via_fd(lib_path, RTLD_NOW);
  if (lib == NULL) {
    LOGE("Failed loading the Zygisk Next companion library [%s]", lib_path);

    return;
  }

  struct ZygiskNextCompanionModule *companion = (struct ZygiskNextCompanionModule *)dlsym(lib, "zn_companion_module");
  if (companion == NULL || companion->onCompanionLoaded == NULL || companion->onModuleConnected == NULL) {
    LOGE("The library [%s] does not export a usable zn_companion_module", lib_path);

    return;
  }

  LOGD("Companion of [%s] is ready", lib_path);

  companion->onCompanionLoaded();

  while (true) {
    uint8_t command = 0;
    union zn_cmsg_buffer buffer;

    struct iovec io;
    io.iov_base = &command;
    io.iov_len = sizeof(command);

    struct msghdr message;
    memset(&message, 0, sizeof(message));
    message.msg_iov = &io;
    message.msg_iovlen = 1;
    message.msg_control = buffer.control;
    message.msg_controllen = sizeof(buffer.control);

    if (recvmsg(socket_fd, &message, 0) <= 0) break;

    /* INFO: The descriptor is taken out of the message before the command is
             looked at: an unserved request still owns the fd it carried, and
             dropping it here would leak one descriptor per request. */
    int connection_fd = -1;
    for (struct cmsghdr *header = CMSG_FIRSTHDR(&message); header != NULL; header = CMSG_NXTHDR(&message, header)) {
      if (header->cmsg_level != SOL_SOCKET || header->cmsg_type != SCM_RIGHTS) continue;

      memcpy(&connection_fd, CMSG_DATA(header), sizeof(connection_fd));

      break;
    }

    if (command != ZN_COMPANION_CMD_CONNECT) {
      if (connection_fd >= 0) close(connection_fd);

      continue;
    }

    if (connection_fd < 0) continue;

    companion->onModuleConnected(connection_fd);
  }
}

/* INFO: Forks a companion for the module. The daemon is asked first because the
         child then keeps its privileged SELinux domain; forking here is only a
         fallback, and the child inherits this process's (possibly restricted)
         domain. */
static int spawn_companion(const char *lib_path) {
  int daemon_fd = rezygiskd_spawn_zn_companion(lib_path);
  if (daemon_fd >= 0) return daemon_fd;

  LOGW("VexZygiskd is unavailable, forking the companion of [%s] locally", lib_path);

  int sockets[2];
  if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) != 0) {
    LOGE("Failed creating the companion socket pair: %s", strerror(errno));

    return -1;
  }

  pid_t pid = fork();
  if (pid < 0) {
    LOGE("Failed forking the companion process: %s", strerror(errno));

    close(sockets[0]);
    close(sockets[1]);

    return -1;
  }

  if (pid == 0) {
    close(sockets[0]);

    companion_main(lib_path, sockets[1]);

    close(sockets[1]);
    _exit(0);
  }

  close(sockets[1]);

  LOGD("Companion of [%s] running as pid %d", lib_path, pid);

  return sockets[0];
}

static bool load_entry(struct zn_entry *entry, void **lib_handle, int module_fd) {
  void *lib = NULL;

  if (module_fd >= 0) {
    /* INFO: The daemon opened the file for us because this process cannot read
             /data/adb/modules, so it is loaded through its memfd descriptor.
             The descriptor stays open for the life of the library, bionic does
             not take ownership of it. */
    lib = dlopen_from_fd(module_fd, entry->lib_path, RTLD_NOW);
    if (lib == NULL) {
      LOGE("Failed loading the Zygisk Next library [%s] from its fd", entry->lib_path);

      close(module_fd);

      return false;
    }
  } else {
    lib = dlopen_via_fd(entry->lib_path, RTLD_NOW);
    if (lib == NULL) {
      LOGE("Failed loading the Zygisk Next library [%s]", entry->lib_path);

      return false;
    }
  }

  struct ZygiskNextModule *module = (struct ZygiskNextModule *)dlsym(lib, "zn_module");
  if (module == NULL) {
    /* INFO: Not worth an error: a module may ship a zn_modules.txt and still
             only speak the standard Zygisk contract, LSPosed being the common
             case. It is then loaded by the standard path, which runs its
             zygisk_module_entry. */
    LOGW("The library [%s] does not export zn_module, it is not a Zygisk Next module", entry->lib_path);

    dlclose(lib);
    if (module_fd >= 0) close(module_fd);

    return false;
  }

  if (module->target_api_version < 1 || module->target_api_version > ZYGISK_NEXT_API_VERSION) {
    LOGE("Unsupported Zygisk Next API version %d in [%s]", module->target_api_version, entry->lib_path);

    dlclose(lib);
    if (module_fd >= 0) close(module_fd);

    return false;
  }

  if (module->onModuleLoaded == NULL) {
    LOGE("The library [%s] exports zn_module without an onModuleLoaded callback", entry->lib_path);

    dlclose(lib);
    if (module_fd >= 0) close(module_fd);

    return false;
  }

  /* INFO: Companions only exist from API v3 onwards. */
  if (entry->companion) {
    if (module->target_api_version >= 3) {
      entry->companion_fd = spawn_companion(entry->lib_path);
    } else {
      LOGW("The module [%s] declares a companion but targets API %d (< 3), skipping it", entry->lib_path, module->target_api_version);
    }
  }

  LOGD("Loading the Zygisk Next module [%s] targeting %s", entry->lib_path, entry->target);

  /* INFO: From here on the library stays loaded for the life of the process:
             its callbacks and hooks outlive this call, unloading is not an
             option. */
  *lib_handle = lib;

  module->onModuleLoaded((void *)entry, zn_get_api_for_version(module->target_api_version));

  return true;
}

/* INFO: Asks the companion behind `handle` for a fresh connection and returns
         its socket, or -1 when the module has no reachable companion. */
int zn_companion_connect(void *handle) {
  if (handle == NULL) return -1;

  struct zn_entry *entry = (struct zn_entry *)handle;
  if (entry->companion_fd < 0) return -1;

  int sockets[2];
  if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) != 0) {
    LOGE("Failed creating the companion connection: %s", strerror(errno));

    return -1;
  }

  uint8_t command = ZN_COMPANION_CMD_CONNECT;
  union zn_cmsg_buffer buffer;

  struct iovec io;
  io.iov_base = &command;
  io.iov_len = sizeof(command);

  struct msghdr message;
  memset(&message, 0, sizeof(message));
  message.msg_iov = &io;
  message.msg_iovlen = 1;
  message.msg_control = buffer.control;
  message.msg_controllen = sizeof(buffer.control);

  struct cmsghdr *header = CMSG_FIRSTHDR(&message);
  header->cmsg_level = SOL_SOCKET;
  header->cmsg_type = SCM_RIGHTS;
  header->cmsg_len = CMSG_LEN(sizeof(int));
  memcpy(CMSG_DATA(header), &sockets[1], sizeof(sockets[1]));

  if (sendmsg(entry->companion_fd, &message, 0) < 0) {
    LOGE("Failed requesting a companion connection: %s", strerror(errno));

    close(sockets[0]);
    close(sockets[1]);

    return -1;
  }

  close(sockets[1]);

  return sockets[0];
}

static void load_module_file(const char *module_dir, const char *file, const char *process_path, const char *process_name) {
  FILE *fp = fopen(file, "re");
  if (fp == NULL) return;

  char *line = NULL;
  size_t capacity = 0;
  ssize_t length;

  while ((length = getline(&line, &capacity, fp)) > 0) {
    while (length > 0 && isspace((unsigned char)line[length - 1])) line[--length] = '\0';
    if (length == 0) continue;

    struct zn_entry entry = { .is_name = false, .companion = false, .target = NULL, .lib_path = NULL, .companion_fd = -1 };

    if (!parse_line(module_dir, line, &entry)) {
      free(entry.target);
      free(entry.lib_path);

      continue;
    }

    bool matched = matches_process(&entry, process_path, process_name);

    LOGD("Zygisk Next module [%s] targeting %s: %s", entry.lib_path, entry.target, matched ? "loaded" : "skipped");

    if (!matched) {
      free(entry.target);
      free(entry.lib_path);

      continue;
    }

    if (loaded_libs_count >= ZN_MAX_MODULES) {
      LOGW("Reached the limit of %d Zygisk Next modules, skipping [%s]", ZN_MAX_MODULES, entry.lib_path);

      free(entry.target);
      free(entry.lib_path);

      continue;
    }

    /* INFO: The module receives this entry as its self handle, so it is moved
             into the permanent array instead of being freed here. */
    loaded_entries[loaded_libs_count] = entry;

    if (load_entry(&loaded_entries[loaded_libs_count], &loaded_libs[loaded_libs_count], -1)) {
      loaded_libs_count++;

      continue;
    }

    /* INFO: The slot stays free for the next module, drop the copy so the
             released strings are not left dangling in it. */
    if (loaded_entries[loaded_libs_count].companion_fd >= 0) close(loaded_entries[loaded_libs_count].companion_fd);

    memset(&loaded_entries[loaded_libs_count], 0, sizeof(loaded_entries[0]));

    free(entry.target);
    free(entry.lib_path);
  }

  free(line);
  fclose(fp);
}

/* INFO: Loads the libraries the daemon resolved for this process. It is the
         only path that works for a target which cannot read /data/adb/modules,
         since the daemon opens every file on its behalf.

         Returns false only when the daemon itself could not be reached, which
         is the one case where scanning the modules directly is worth trying.
         An empty answer is a valid answer and must not trigger the fallback. */
static bool load_modules_from_daemon(const char *process_name, const char *process_path) {
  struct zn_module_file *files = NULL;
  size_t files_len = 0;

  if (!rezygiskd_read_zn_modules(process_name, process_path, &files, &files_len)) return false;

  LOGD("Got %zu Zygisk Next module(s) from VexZygiskd", files_len);

  for (size_t i = 0; i < files_len; i++) {
    if (loaded_libs_count >= ZN_MAX_MODULES) {
      LOGW("Reached the limit of %d Zygisk Next modules, skipping \"%s\"", ZN_MAX_MODULES, files[i].lib_path);

      break;
    }

    struct zn_entry *entry = &loaded_entries[loaded_libs_count];
    entry->is_name = false;
    entry->companion = files[i].companion;
    entry->target = strdup(process_name);
    entry->lib_path = strdup(files[i].lib_path);
    entry->companion_fd = -1;

    if (entry->target == NULL || entry->lib_path == NULL) {
      LOGE("Failed copying the Zygisk Next module \"%s\"", files[i].lib_path);

      free(entry->target);
      free(entry->lib_path);

      entry->target = NULL;
      entry->lib_path = NULL;
      entry->companion_fd = -1;

      break;
    }

    /* INFO: load_entry takes over the descriptor: a loaded library keeps it
             for its whole life (bionic does not own USE_LIBRARY_FD fds), and a
             failed one closes it on the spot. Handing it over here, instead of
             letting free_zn_module_files close everything, keeps a loaded
             library's descriptor alive and avoids a double close on failure. */
    int module_fd = files[i].fd;
    files[i].fd = -1;

    if (load_entry(entry, &loaded_libs[loaded_libs_count], module_fd)) {
      loaded_libs_count++;

      continue;
    }

    if (entry->companion_fd >= 0) close(entry->companion_fd);

    free(entry->target);
    free(entry->lib_path);

    /* INFO: The slot is free again, so leave it as "no companion" rather than
             a zeroed struct whose fd would read as a valid descriptor. */
    entry->target = NULL;
    entry->lib_path = NULL;
    entry->companion_fd = -1;
  }

  free_zn_module_files(files, files_len);

  return true;
}

void zn_load_all_modules(void) {
  char *process_path = read_process_path();
  const char *process_name = get_process_name(process_path);

  if (process_path == NULL) {
    LOGE("Failed resolving the current process path");

    return;
  }

  if (load_modules_from_daemon(process_name, process_path)) {
    free(process_path);

    return;
  }

  LOGW("VexZygiskd is unavailable, reading the Zygisk Next modules directly");

  DIR *dir = opendir(ZN_MODULES_DIR);
  if (dir == NULL) {
    LOGE("Failed opening %s", ZN_MODULES_DIR);

    free(process_path);

    return;
  }

  struct dirent *entry;
  while ((entry = readdir(dir)) != NULL) {
    if (entry->d_type != DT_DIR && entry->d_type != DT_UNKNOWN) continue;
    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0 || strcmp(entry->d_name, "rezygisk") == 0) continue;

    char module_dir[PATH_MAX];
    snprintf(module_dir, PATH_MAX, "%s/%s", ZN_MODULES_DIR, entry->d_name);

    char disabled[PATH_MAX];
    snprintf(disabled, PATH_MAX, "%s/disable", module_dir);
    if (access(disabled, F_OK) == 0) continue;

    char zn_file[PATH_MAX];
    snprintf(zn_file, PATH_MAX, "%s/zn_modules.txt", module_dir);
    if (access(zn_file, F_OK) != 0) continue;

    load_module_file(module_dir, zn_file, process_path, process_name);
  }

  closedir(dir);
  free(process_path);
}
