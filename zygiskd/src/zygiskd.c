#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <linux/limits.h>
#include <unistd.h>

#include "constants.h"
#include "root_impl/common.h"
#include "utils.h"

struct Module {
  char *name;
  int lib_fd;
  int companion;
};

/* INFO: Zygisk Next modules ship zn_modules.txt instead of a Zygisk library,
         they are kept apart so the loader indexes stay those of the modules it
         can actually load. The targets and companion flag are read from the
         file so the controller can surface them in the UI. */
struct ZnModule {
  char *name;
  bool companion;
  char **targets;
  size_t targets_len;
};

struct Context {
  struct Module *modules;
  size_t len;

  struct ZnModule *zn_modules;
  size_t zn_len;
};

/* INFO: A Zygisk Next library resolved for one target: its path, whether the
         module asked for a companion, and the fd of the opened file. */
struct ZnModuleFile {
  char *lib_path;
  bool companion;
  int fd;
};

#define PATH_MODULES_DIR "/data/adb/modules"
#define TMP_PATH "/data/adb/rezygisk"
#define CONTROLLER_SOCKET TMP_PATH "/init_monitor"
#define PATH_CP_NAME TMP_PATH "/" LP_SELECT("cp32.sock", "cp64.sock")
#define ZYGISKD_PATH "/data/adb/modules/rezygisk/bin/zygiskd" LP_SELECT("32", "64")

#ifdef __aarch64__
  #define ARCH_STR "arm64-v8a"
#elif __arm__
  #define ARCH_STR "armeabi-v7a"
#else
  #error "Unsupported architecture"
#endif

/* INFO: A trailing byte tells the monitor whether the module targets Zygisk Next */
static void send_module_info(const char *name, bool is_zn) {
  uint32_t module_name_len = (uint32_t)strlen(name);
  uint8_t module_type = is_zn ? 1 : 0;

  unix_datagram_sendto(CONTROLLER_SOCKET, &module_name_len, sizeof(module_name_len));
  unix_datagram_sendto(CONTROLLER_SOCKET, name, module_name_len);
  unix_datagram_sendto(CONTROLLER_SOCKET, &module_type, sizeof(module_type));
}

/* INFO: Zygisk Next modules also carry the companion flag and every target of
         their zn_modules.txt, so the monitor can show them. */
static void send_zn_module_info(const struct ZnModule *module) {
  uint32_t module_name_len = (uint32_t)strlen(module->name);
  uint8_t module_type = 1;
  uint8_t companion = module->companion ? 1 : 0;
  uint32_t targets_len = (uint32_t)module->targets_len;

  unix_datagram_sendto(CONTROLLER_SOCKET, &module_name_len, sizeof(module_name_len));
  unix_datagram_sendto(CONTROLLER_SOCKET, module->name, module_name_len);
  unix_datagram_sendto(CONTROLLER_SOCKET, &module_type, sizeof(module_type));
  unix_datagram_sendto(CONTROLLER_SOCKET, &companion, sizeof(companion));
  unix_datagram_sendto(CONTROLLER_SOCKET, &targets_len, sizeof(targets_len));

  for (size_t i = 0; i < module->targets_len; i++) {
    uint32_t target_len = (uint32_t)strlen(module->targets[i]);
    unix_datagram_sendto(CONTROLLER_SOCKET, &target_len, sizeof(target_len));
    unix_datagram_sendto(CONTROLLER_SOCKET, module->targets[i], target_len);
  }
}

/* INFO: Reads zn_modules.txt and collects the targets, one per line ("name="
         or "path=" as the first token), plus whether any line asks for a
         companion. Mirrors the loader's parse_line, "companion" is only
         matched between the target and the library. */
static void parse_zn_module_file(const char *module_dir, struct ZnModule *module) {
  char zn_path[PATH_MAX];
  snprintf(zn_path, PATH_MAX, "%s/zn_modules.txt", module_dir);

  FILE *fp = fopen(zn_path, "re");
  if (fp == NULL) return;

  char *line = NULL;
  size_t line_capacity = 0;
  ssize_t length;

  while ((length = getline(&line, &line_capacity, fp)) > 0) {
    char *tokens[8];
    size_t token_count = 0;

    const char *cursor = line;
    while (*cursor != '\0' && token_count < 8) {
      while (*cursor != '\0' && isspace((unsigned char)*cursor)) cursor++;
      if (*cursor == '\0') break;

      const char *start = cursor;
      while (*cursor != '\0' && !isspace((unsigned char)*cursor)) cursor++;

      size_t token_len = (size_t)(cursor - start);
      tokens[token_count] = malloc(token_len + 1);
      if (tokens[token_count] == NULL) break;
      memcpy(tokens[token_count], start, token_len);
      tokens[token_count][token_len] = '\0';

      token_count++;
    }

    if (token_count >= 2) {
      for (size_t i = 1; i + 1 < token_count; i++) {
        if (strcmp(tokens[i], "companion") == 0) module->companion = true;
      }

      char **tmp = realloc(module->targets, (module->targets_len + 1) * sizeof(char *));
      if (tmp != NULL) {
        module->targets = tmp;
        module->targets[module->targets_len++] = tokens[0];
        tokens[0] = NULL; /* INFO: Ownership moves into the array */
      }
    }

    for (size_t i = 0; i < token_count; i++) free(tokens[i]);
  }

  free(line);
  fclose(fp);
}

/* WARNING: Dynamic memory based */
static bool add_zn_module(struct Context *restrict context, const char *name) {
  struct ZnModule *tmp = realloc(context->zn_modules, (context->zn_len + 1) * sizeof(struct ZnModule));
  if (tmp == NULL) {
    LOGE("Failed reallocating memory for Zygisk Next modules.");

    return false;
  }
  context->zn_modules = tmp;

  struct ZnModule *module = &context->zn_modules[context->zn_len];
  module->name = strdup(name);
  if (module->name == NULL) {
    LOGE("Failed to strdup for the Zygisk Next module \"%s\": %s", name, strerror(errno));

    return false;
  }

  module->companion = false;
  module->targets = NULL;
  module->targets_len = 0;

  char module_dir[PATH_MAX];
  snprintf(module_dir, PATH_MAX, "%s/%s", PATH_MODULES_DIR, name);

  parse_zn_module_file(module_dir, module);

  context->zn_len++;

  return true;
}

/* INFO: Declared here because load_modules bails out through it, and it is
         defined further down where the rest of the context handling lives. */
static void free_modules(struct Context *restrict context);

/* WARNING: Dynamic memory based */
static void load_modules(struct Context *restrict context) {
  context->len = 0;
  context->modules = NULL;
  context->zn_len = 0;
  context->zn_modules = NULL;

  DIR *dir = opendir(PATH_MODULES_DIR);
  if (dir == NULL) {
    LOGE("Failed opening modules directory: %s.", PATH_MODULES_DIR);

    return;
  }

  LOGI("Loading modules for architecture: " ARCH_STR);

  struct dirent *entry;
  while ((entry = readdir(dir)) != NULL) {
    /* INFO: Some filesystems (fuse, certain overlays) report DT_UNKNOWN, and
             skipping those would silently drop every module, so the type is
             only used to rule out what is definitely not a directory. */
    if (entry->d_type != DT_DIR && entry->d_type != DT_UNKNOWN) continue;
    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0 || strcmp(entry->d_name, "rezygisk") == 0) continue;

    char *name = entry->d_name;

    char disabled[PATH_MAX];
    snprintf(disabled, PATH_MAX, "/data/adb/modules/%s/disable", name);

    if (access(disabled, F_OK) == 0) continue;

    char zn_modules[PATH_MAX];
    snprintf(zn_modules, PATH_MAX, "/data/adb/modules/%s/zn_modules.txt", name);

    /* INFO: The two mechanisms are served side by side rather than picked
             between, which is what NyaZygisk does and what LSPosed depends on.

             LSPosed ships a zn_modules.txt because it wants a ZN-aware
             provider underneath (mount-free injection, HyperOS Runtime,
             dex2oat on A17+, ...), yet its library only exports the standard
             zygisk_module_entry, never zn_module. Treating the two as
             exclusive sends it down the ZN path, where it cannot load, and
             drops it from the standard path, where it would have.

             Entering it in both lists costs nothing: the ZN load finds no
             zn_module and gives up quietly, while the standard load runs the
             entry point that is there. */
    if (access(zn_modules, F_OK) == 0) {
      LOGI("Found Zygisk Next module \"%s\"", name);

      add_zn_module(context, name);
    }

    char so_path[PATH_MAX];
    snprintf(so_path, PATH_MAX, "/data/adb/modules/%s/zygisk/" ARCH_STR ".so", name);

    if (access(so_path, R_OK) == -1) continue;

    int lib_fd = open(so_path, O_RDONLY | O_CLOEXEC);
    if (lib_fd == -1) {
      LOGE("Failed loading module \"%s\"", name);

      continue;
    }

    struct Module *tmp_modules = realloc(context->modules, (context->len + 1) * sizeof(struct Module));
    if (tmp_modules == NULL) {
      LOGE("Failed reallocating memory for modules.");

      close(lib_fd);

      goto load_modules_fail;
    }
    context->modules = tmp_modules;

    context->modules[context->len].name = strdup(name);
    if (context->modules[context->len].name == NULL) {
      LOGE("Failed to strdup for the module \"%s\": %s", name, strerror(errno));

      close(lib_fd);

      goto load_modules_fail;
    }

    context->modules[context->len].lib_fd = lib_fd;
    context->modules[context->len].companion = -1;
    context->len++;
  }

  closedir(dir);

  return;

  load_modules_fail:
    free_modules(context);
    closedir(dir);
}

static void free_modules(struct Context *restrict context) {
  for (size_t i = 0; i < context->len; i++) {
    free(context->modules[i].name);
    if (context->modules[i].companion >= 0) close(context->modules[i].companion);
    if (context->modules[i].lib_fd >= 0) close(context->modules[i].lib_fd);
  }

  free(context->modules);
  context->modules = NULL;
  context->len = 0;

  for (size_t i = 0; i < context->zn_len; i++) {
    free(context->zn_modules[i].name);

    for (size_t j = 0; j < context->zn_modules[i].targets_len; j++) {
      free(context->zn_modules[i].targets[j]);
    }

    free(context->zn_modules[i].targets);
  }

  free(context->zn_modules);
  context->zn_modules = NULL;
  context->zn_len = 0;
}

static void free_zn_module_files(struct ZnModuleFile *files, size_t len) {
  for (size_t i = 0; i < len; i++) {
    free(files[i].lib_path);
    if (files[i].fd >= 0) close(files[i].fd);
  }

  free(files);
}

/* INFO: Splits one zn_modules.txt line, which reads
         "<name=|path=><target> [companion] <library>". The library is always
         the last token and "companion" may sit anywhere between the target and
         it, so only that range is scanned for the flag. */
static bool parse_zn_line(const char *module_dir, const char *line, bool *is_name, char **target, bool *companion, char **lib_path) {
  const char *tokens[8];
  size_t lengths[8];
  size_t token_count = 0;

  const char *cursor = line;
  while (*cursor != '\0' && token_count < 8) {
    while (*cursor != '\0' && isspace((unsigned char)*cursor)) cursor++;
    if (*cursor == '\0') break;

    const char *start = cursor;
    while (*cursor != '\0' && !isspace((unsigned char)*cursor)) cursor++;

    tokens[token_count] = start;
    lengths[token_count] = (size_t)(cursor - start);

    token_count++;
  }

  if (token_count < 2) return false;

  if (lengths[0] > 5 && strncmp(tokens[0], "name=", 5) == 0) {
    *is_name = true;
  } else if (lengths[0] > 5 && strncmp(tokens[0], "path=", 5) == 0) {
    *is_name = false;
  } else {
    return false;
  }

  size_t target_len = lengths[0] - 5;

  char *parsed_target = malloc(target_len + 1);
  if (parsed_target == NULL) return false;

  memcpy(parsed_target, tokens[0] + 5, target_len);
  parsed_target[target_len] = '\0';

  *companion = false;
  for (size_t i = 1; i + 1 < token_count; i++) {
    if (lengths[i] == 9 && strncmp(tokens[i], "companion", 9) == 0) *companion = true;
  }

  const char *library = tokens[token_count - 1];
  size_t library_len = lengths[token_count - 1];

  char *resolved;
  if (library[0] == '/') {
    resolved = strndup(library, library_len);
  } else {
    size_t dir_len = strlen(module_dir);

    resolved = malloc(dir_len + library_len + 2);
    if (resolved != NULL) snprintf(resolved, dir_len + library_len + 2, "%s/%.*s", module_dir, (int)library_len, library);
  }

  if (resolved == NULL) {
    free(parsed_target);

    return false;
  }

  *target = parsed_target;
  *lib_path = resolved;

  return true;
}

static bool zn_matches_target(const char *target, bool is_name, const char *process_name, const char *process_path) {
  if (is_name) {
    if (strcmp(target, "zygote") == 0 || strcmp(target, "zygote64") == 0 || strcmp(target, "zygote32") == 0)
      return strstr(process_name, "zygote") != NULL || strstr(process_name, "app_process") != NULL;

    return strcmp(process_name, target) == 0;
  }

  return strcmp(process_path, target) == 0;
}

/* INFO: Forks a process running "zygiskd zn-companion", which keeps the
         daemon's SELinux domain instead of the restricted one of the target
         that asked for it. Returns the control socket, or -1 on failure.

         Unlike the Zygisk companion this one takes a path rather than a module
         name: Zygisk Next modules are not tracked by index in the context. */
static int spawn_zn_companion(char *restrict argv[], const char *restrict lib_path) {
  int sockets[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == -1) {
    LOGE("Failed creating the Zygisk Next companion socket pair.");

    return -1;
  }

  int daemon_fd = sockets[0];
  int companion_fd = sockets[1];

  pid_t pid = fork();
  if (pid < 0) {
    LOGE("Failed forking the Zygisk Next companion: %s", strerror(errno));

    close(companion_fd);
    close(daemon_fd);

    return -1;
  }

  if (pid > 0) {
    close(companion_fd);

    int status = 0;
    waitpid(pid, &status, 0);

    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
      LOGE("Exited with status %d", status);

      close(daemon_fd);

      return -1;
    }

    if (write_string(daemon_fd, lib_path) == -1) {
      LOGE("Failed writing the Zygisk Next library path.");

      close(daemon_fd);

      return -1;
    }

    int lib_fd = create_library_fd(lib_path);
    if (lib_fd == -1) {
      LOGE("Failed handing over \"%s\"", lib_path);

      close(daemon_fd);

      return -1;
    }

    if (write_fd(daemon_fd, lib_fd) == -1) {
      LOGE("Failed sending the Zygisk Next library fd.");

      close(lib_fd);
      close(daemon_fd);

      return -1;
    }

    close(lib_fd);

    uint8_t response = 0;
    ssize_t ret = read_uint8_t(daemon_fd, &response);
    if (ret <= 0) {
      LOGE("Failed reading the Zygisk Next companion response.");

      close(daemon_fd);

      return -1;
    }

    if (response != 1) {
      LOGE("The Zygisk Next companion rejected \"%s\"", lib_path);

      close(daemon_fd);

      return -1;
    }

    return daemon_fd;
  }

  close(daemon_fd);

  /* INFO: Remove FD_CLOEXEC flag to avoid closing upon exec */
  if (fcntl(companion_fd, F_SETFD, 0) == -1) {
    LOGE("Failed removing FD_CLOEXEC flag: %s", strerror(errno));

    close(companion_fd);

    exit(1);
  }

  char *process = argv[0];
  char nice_name[256];
  char *last = strrchr(process, '/');
  if (last == NULL) {
    snprintf(nice_name, sizeof(nice_name), "%s", process);
  } else {
    snprintf(nice_name, sizeof(nice_name), "%s", last + 1);
  }

  char process_name[256];
  snprintf(process_name, sizeof(process_name), "%s-zn-companion", nice_name);

  char companion_fd_str[32];
  snprintf(companion_fd_str, sizeof(companion_fd_str), "%d", companion_fd);

  char mode[] = "zn-companion";
  char *eargv[] = { process_name, mode, companion_fd_str, NULL };
  if (non_blocking_execv(ZYGISKD_PATH, eargv) == -1) {
    LOGE("Failed executing the Zygisk Next companion: %s", strerror(errno));

    close(companion_fd);

    exit(1);
  }

  exit(0);
}

/* INFO: Walks every Zygisk Next module and resolves the libraries targeting
         this process. The daemon opens the files itself because a non-root
         target cannot read /data/adb/modules, which is the whole point of
         handing them over as file descriptors.

   WARNING: Dynamic memory based */
static bool collect_zn_modules(const char *process_name, const char *process_path, struct ZnModuleFile **out, size_t *out_len) {
  *out = NULL;
  *out_len = 0;

  size_t capacity = 0;

  DIR *dir = opendir(PATH_MODULES_DIR);
  if (dir == NULL) {
    LOGE("Failed opening %s: %s", PATH_MODULES_DIR, strerror(errno));

    return false;
  }

  struct dirent *entry;
  while ((entry = readdir(dir)) != NULL) {
    if (entry->d_type != DT_DIR) continue;
    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0 || strcmp(entry->d_name, "rezygisk") == 0) continue;

    char module_dir[PATH_MAX];
    snprintf(module_dir, PATH_MAX, "%s/%s", PATH_MODULES_DIR, entry->d_name);

    char disabled[PATH_MAX];
    snprintf(disabled, PATH_MAX, "%s/disable", module_dir);

    if (access(disabled, F_OK) == 0) continue;

    char zn_file[PATH_MAX];
    snprintf(zn_file, PATH_MAX, "%s/zn_modules.txt", module_dir);

    if (access(zn_file, R_OK) != 0) continue;

    FILE *fp = fopen(zn_file, "re");
    if (fp == NULL) continue;

    char *line = NULL;
    size_t line_capacity = 0;
    ssize_t length;

    while ((length = getline(&line, &line_capacity, fp)) > 0) {
      while (length > 0 && isspace((unsigned char)line[length - 1])) line[--length] = '\0';
      if (length == 0) continue;

      bool is_name = false;
      bool companion = false;
      char *target = NULL;
      char *lib_path = NULL;

      if (!parse_zn_line(module_dir, line, &is_name, &target, &companion, &lib_path)) continue;

      bool matched = zn_matches_target(target, is_name, process_name, process_path);

      free(target);

      if (!matched) {
        free(lib_path);

        continue;
      }

      int fd = create_library_fd(lib_path);
      if (fd == -1) {
        LOGE("Failed handing over the Zygisk Next library \"%s\"", lib_path);

        free(lib_path);

        continue;
      }

      if (*out_len == capacity) {
        size_t new_capacity = capacity == 0 ? 8 : capacity * 2;

        struct ZnModuleFile *tmp = realloc(*out, new_capacity * sizeof(struct ZnModuleFile));
        if (tmp == NULL) {
          LOGE("Failed growing the Zygisk Next module list");

          close(fd);
          free(lib_path);

          break;
        }

        *out = tmp;
        capacity = new_capacity;
      }

      (*out)[*out_len].lib_path = lib_path;
      (*out)[*out_len].companion = companion;
      (*out)[*out_len].fd = fd;
      (*out_len)++;
    }

    free(line);
    fclose(fp);
  }

  closedir(dir);

  return true;
}

static int create_daemon_socket(void) {
  set_socket_create_context("u:r:zygote:s0");

  return unix_listener_from_path(PATH_CP_NAME);
}

static int spawn_companion(char *restrict argv[], char *restrict name, int lib_fd) {
  int sockets[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == -1) {
    LOGE("Failed creating socket pair.");

    return -1;
  }

  int daemon_fd = sockets[0];
  int companion_fd = sockets[1];

  pid_t pid = fork();
  if (pid < 0) {
    LOGE("Failed forking companion: %s", strerror(errno));

    close(companion_fd);
    close(daemon_fd);

    return -1;
  }

  if (pid > 0) {
    close(companion_fd);

    int status = 0;
    waitpid(pid, &status, 0);

    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
      LOGE("Exited with status %d", status);

      close(daemon_fd);

      return -1;
    }

    if (write_string(daemon_fd, name) == -1) {
      LOGE("Failed writing module name.");

      close(daemon_fd);

      return -1;
    }

    if (write_fd(daemon_fd, lib_fd) == -1) {
      LOGE("Failed sending library fd.");

      close(daemon_fd);

      return -1;
    }

    uint8_t response = 0;
    ssize_t ret = read_uint8_t(daemon_fd, &response);
    if (ret <= 0) {
      LOGE("Failed reading companion response.");

      close(daemon_fd);

      return -1;
    }

    switch (response) {
      /* INFO: Even without any entry, we should still just deal with it */
      case 0: {
        close(daemon_fd);

        return -2;
      }
      case 1: { return daemon_fd; }
      /* TODO: Should we be closing daemon socket here? (in non-0-and-1 case) */
      default: {
        close(daemon_fd);

        return -1;
      }
    }
  /* INFO: if pid == 0: */
  }

  close(daemon_fd);

  /* INFO: There is no case where this will fail with a valid fd. */
  /* INFO: Remove FD_CLOEXEC flag to avoid closing upon exec */
  if (fcntl(companion_fd, F_SETFD, 0) == -1) {
    LOGE("Failed removing FD_CLOEXEC flag: %s", strerror(errno));

    close(companion_fd);

    exit(1);
  }

  char *process = argv[0];
  char nice_name[256];
  char *last = strrchr(process, '/');
  if (last == NULL) {
    snprintf(nice_name, sizeof(nice_name), "%s", process);
  } else {
    snprintf(nice_name, sizeof(nice_name), "%s", last + 1);
  }

  char process_name[256];
  snprintf(process_name, sizeof(process_name), "%s-%s", nice_name, name);

  char companion_fd_str[32];
  snprintf(companion_fd_str, sizeof(companion_fd_str), "%d", companion_fd);

  char companion[] = "companion";
  char *eargv[] = { process_name, companion, companion_fd_str, NULL };
  if (non_blocking_execv(ZYGISKD_PATH, eargv) == -1) {
    LOGE("Failed executing companion: %s", strerror(errno));

    close(companion_fd);

    exit(1);
  }

  exit(0);
}

/* WARNING: Dynamic memory based */
void zygiskd_start(char *restrict argv[]) {
  /* INFO: When no root implementation is found, it won't set the values
            for the context, causing it to have garbage values. In response
            to that, "= { 0 }" is used to ensure that the values are clean. */
  struct Context context = { 0 };

  struct root_impl impl;
  get_impl(&impl);

  load_modules(&context);

  unix_datagram_sendto(CONTROLLER_SOCKET, &(uint8_t){ DAEMON_SET_INFO }, sizeof(uint8_t));

  char impl_name[LONGEST_ROOT_IMPL_NAME];
  stringify_root_impl_name(impl, impl_name);

  uint32_t root_impl_len = (uint32_t)strlen(impl_name);
  unix_datagram_sendto(CONTROLLER_SOCKET, &root_impl_len, sizeof(root_impl_len));
  unix_datagram_sendto(CONTROLLER_SOCKET, impl_name, root_impl_len);

  uint32_t modules_len = (uint32_t)(context.len + context.zn_len);
  unix_datagram_sendto(CONTROLLER_SOCKET, &modules_len, sizeof(modules_len));

  for (size_t i = 0; i < context.len; i++) {
    send_module_info(context.modules[i].name, false);
  }

  for (size_t i = 0; i < context.zn_len; i++) {
    send_zn_module_info(&context.zn_modules[i]);
  }

  LOGI("Sent root implementation and modules information to controller socket");

  int socket_fd = create_daemon_socket();
  if (socket_fd == -1) {
    LOGE("Failed creating daemon socket");

    free_modules(&context);

    root_impl_cleanup();

    return;
  }

  struct sigaction sa = { .sa_handler = SIG_IGN };
  sigaction(SIGPIPE, &sa, NULL);

  bool first_process = true;
  while (1) {
    int client_fd = accept(socket_fd, NULL, NULL);
    if (client_fd == -1) {
      LOGE("accept: %s", strerror(errno));

      break;
    }

    uint8_t action8 = 0;
    ssize_t len = read_uint8_t(client_fd, &action8);
    if (len == -1) {
      LOGE("read: %s", strerror(errno));

      close(client_fd);

      break;
    } else if (len == 0) {
      LOGI("Client disconnected");

      close(client_fd);

      break;
    }

    enum DaemonSocketAction action = (enum DaemonSocketAction)action8;

    switch (action) {
      case ZygoteInjected: {
        unix_datagram_sendto(CONTROLLER_SOCKET, &(uint8_t){ ZYGOTE_INJECTED }, sizeof(uint8_t));

        break;
      }
      case ZygoteRestart: {
        for (size_t i = 0; i < context.len; i++) {
          if (context.modules[i].companion <= -1) continue;

          close(context.modules[i].companion);
          context.modules[i].companion = -1;
        }

        break;
      }
      case GetProcessFlags: {
        uint32_t uid = 0;
        ssize_t ret = read_uint32_t(client_fd, &uid);
        ASSURE_SIZE_READ("GetProcessFlags", "uid", ret, sizeof(uid), break);

        /* INFO: Sent by the loader, unused here since only UIDs are queried. */
        char process[PROCESS_NAME_MAX_LEN];
        ret = read_string(client_fd, process, sizeof(process));
        if (ret == -1) {
          LOGE("Failed reading process name.");

          break;
        }

        uint32_t flags = 0;
        if (first_process) {
          flags |= PROCESS_IS_FIRST_STARTED;

          first_process = false;
        }

        if (uid_is_manager(uid)) {
          flags |= PROCESS_IS_MANAGER;
        } else {
          if (uid_granted_root(uid)) {
            flags |= PROCESS_GRANTED_ROOT;
          }
          if (uid_should_umount(uid)) {
            flags |= PROCESS_ON_DENYLIST;
          }
        }

        switch (impl.impl) {
          case KernelSU: {
            flags |= PROCESS_ROOT_IS_KSU;

            break;
          }
        }

        ret = write_uint32_t(client_fd, flags);
        ASSURE_SIZE_WRITE("GetProcessFlags", "flags", ret, sizeof(flags), break);

        break;
      }
      case GetInfo: {
        uint32_t flags = 0;

        switch (impl.impl) {
          case KernelSU: {
            flags |= PROCESS_ROOT_IS_KSU;

            break;
          }
        }

        ssize_t ret = write_uint32_t(client_fd, flags);
        ASSURE_SIZE_WRITE("GetInfo", "flags", ret, sizeof(flags), break);

        pid_t pid = getpid();
        ret = write_uint32_t(client_fd, (uint32_t)pid);
        ASSURE_SIZE_WRITE("GetInfo", "pid", ret, sizeof(pid), break);

        size_t modules_count = context.len;
        ret = write_size_t(client_fd, modules_count);
        ASSURE_SIZE_WRITE("GetInfo", "modules_count", ret, sizeof(modules_count), break);

        for (size_t i = 0; i < modules_count; i++) {
          ret = write_string(client_fd, context.modules[i].name);
          if (ret == -1) {
            LOGE("Failed writing module name.");

            break;
          }
        }

        break;
      }
      case ReadModules: {
        size_t clen = context.len;
        ssize_t ret = write_size_t(client_fd, clen);
        ASSURE_SIZE_WRITE("ReadModules", "len", ret, sizeof(clen), break);

        for (size_t i = 0; i < clen; i++) {
          char lib_path[PATH_MAX];
          snprintf(lib_path, PATH_MAX, "/data/adb/modules/%s/zygisk/" ARCH_STR ".so", context.modules[i].name);

          if (write_string(client_fd, lib_path) == -1) {
            LOGE("Failed writing module path.");

            break;
          }
        }

        break;
      }
      case SpawnZnCompanion: {
        char lib_path[PATH_MAX];
        ssize_t ret = read_string(client_fd, lib_path, sizeof(lib_path));
        if (ret <= 0) {
          LOGE("Failed reading the Zygisk Next library path.");

          break;
        }

        int companion_fd = spawn_zn_companion(argv, lib_path);
        if (companion_fd < 0) {
          LOGE("Failed spawning the Zygisk Next companion of \"%s\"", lib_path);

          ret = write_uint8_t(client_fd, (uint8_t)0);
          ASSURE_SIZE_WRITE("SpawnZnCompanion", "response", ret, sizeof(uint8_t), break);

          break;
        }

        LOGI("Spawned the Zygisk Next companion of \"%s\"", lib_path);

        ret = write_uint8_t(client_fd, (uint8_t)1);
        if (ret != (ssize_t)sizeof(uint8_t)) {
          LOGE("Failed confirming the Zygisk Next companion.");

          close(companion_fd);

          break;
        }

        if (write_fd(client_fd, companion_fd) == -1) LOGE("Failed sending the Zygisk Next companion fd.");

        close(companion_fd);

        break;
      }
      case ReadZnModules: {
        char process_name[PROCESS_NAME_MAX_LEN];
        ssize_t ret = read_string(client_fd, process_name, sizeof(process_name));
        if (ret <= 0) {
          LOGE("Failed reading the process name for ReadZnModules.");

          break;
        }

        char process_path[PATH_MAX];
        ret = read_string(client_fd, process_path, sizeof(process_path));
        if (ret <= 0) {
          LOGE("Failed reading the process path for ReadZnModules.");

          break;
        }

        struct ZnModuleFile *files = NULL;
        size_t files_len = 0;

        if (!collect_zn_modules(process_name, process_path, &files, &files_len)) {
          ret = write_size_t(client_fd, 0);
          ASSURE_SIZE_WRITE("ReadZnModules", "len", ret, sizeof(size_t), break);

          break;
        }

        ret = write_size_t(client_fd, files_len);
        if (ret != (ssize_t)sizeof(size_t)) {
          LOGE("Failed writing the Zygisk Next module count.");

          free_zn_module_files(files, files_len);

          break;
        }

        LOGI("Serving %zu Zygisk Next module(s) to \"%s\"", files_len, process_name);

        for (size_t i = 0; i < files_len; i++) {
          if (write_string(client_fd, files[i].lib_path) == -1) {
            LOGE("Failed writing a Zygisk Next module path.");

            break;
          }

          ret = write_uint8_t(client_fd, (uint8_t)(files[i].companion ? 1 : 0));
          if (ret != (ssize_t)sizeof(uint8_t)) {
            LOGE("Failed writing a Zygisk Next companion flag.");

            break;
          }

          if (write_fd(client_fd, files[i].fd) == -1) {
            LOGE("Failed sending a Zygisk Next module fd.");

            break;
          }
        }

        free_zn_module_files(files, files_len);

        break;
      }
      case RequestCompanionSocket: {
        size_t index = 0;
        ssize_t ret = read_size_t(client_fd, &index);
        ASSURE_SIZE_READ("RequestCompanionSocket", "index", ret, sizeof(index), break);

        if (index >= context.len) {
          LOGE("Invalid module index: %zu", index);

          ret = write_uint8_t(client_fd, 0);
          ASSURE_SIZE_WRITE("RequestCompanionSocket", "response", ret, sizeof(uint8_t), break);

          break;
        }

        struct Module *module = &context.modules[index];
        if (module->companion >= 0) {
          if (!check_unix_socket(module->companion, false)) {
            LOGE(" - Companion for module \"%s\" crashed", module->name);

            close(module->companion);
            module->companion = -1;
          }
        }

        if (module->companion <= -1) {
          module->companion = spawn_companion(argv, module->name, module->lib_fd);

          if (module->companion >= 0) {
            LOGI(" - Spawned companion for \"%s\": %d", module->name, module->companion);
          } else if (module->companion == -2) {
            LOGE(" - No companion spawned for \"%s\" because it has no entry.", module->name);
          } else {
            LOGE(" - Failed to spawn companion for \"%s\": %s", module->name, strerror(errno));
          }
        }

        /*
          INFO: Companion already exists or was created. In any way,
                 it should be in the while loop to receive fds now,
                 so just sending the file descriptor of the client is
                 safe.
        */
        if (module->companion >= 0) {
          LOGI(" - Sending companion fd socket of module \"%s\"", module->name);

          if (write_fd(module->companion, client_fd) == -1) {
            LOGE(" - Failed to send companion fd socket of module \"%s\"", module->name);

            ret = write_uint8_t(client_fd, 0);
            ASSURE_SIZE_WRITE("RequestCompanionSocket", "response", ret, sizeof(uint8_t), break);

            close(module->companion);
            module->companion = -1;
          }
        } else {
          LOGE(" - Failed to spawn companion for module \"%s\"", module->name);

          ret = write_uint8_t(client_fd, 0);
          ASSURE_SIZE_WRITE("RequestCompanionSocket", "response", ret, sizeof(uint8_t), break);
        }

        break;
      }
      case GetModuleDir: {
        size_t index = 0;
        ssize_t ret = read_size_t(client_fd, &index);
        ASSURE_SIZE_READ("GetModuleDir", "index", ret, sizeof(index), break);

        if (index >= context.len) {
          LOGE("Invalid module index: %zu", index);

          ret = write_uint8_t(client_fd, 0);
          ASSURE_SIZE_WRITE("GetModuleDir", "response", ret, sizeof(uint8_t), break);

          break;
        }

        char module_dir[PATH_MAX];
        snprintf(module_dir, PATH_MAX, "%s/%s", PATH_MODULES_DIR, context.modules[index].name);

        int fd = open(module_dir, O_RDONLY);
        if (fd == -1) {
          LOGE("Failed opening module directory \"%s\": %s", module_dir, strerror(errno));

          break;
        }

        if (write_fd(client_fd, fd) == -1) {
          LOGE("Failed sending module directory \"%s\" fd: %s", module_dir, strerror(errno));

          close(fd);

          break;
        }

        close(fd);

        break;
      }
      case UpdateMountNamespace: {
        pid_t pid = 0;
        ssize_t ret = read_uint32_t(client_fd, (uint32_t *)&pid);
        ASSURE_SIZE_READ("UpdateMountNamespace", "pid", ret, sizeof(pid), break);

        uint8_t mns_state = 0;
        ret = read_uint8_t(client_fd, &mns_state);
        ASSURE_SIZE_READ("UpdateMountNamespace", "mns_state", ret, sizeof(mns_state), break);

        uint32_t our_pid = (uint32_t)getpid();
        ret = write_uint32_t(client_fd, our_pid);
        ASSURE_SIZE_WRITE("UpdateMountNamespace", "our_pid", ret, sizeof(our_pid), break);

        if ((enum MountNamespaceState)mns_state == Clean)
          save_mns_fd(pid, Mounted);

        int ns_fd = save_mns_fd(pid, (enum MountNamespaceState)mns_state);
        if (ns_fd == -1) {
          LOGE("Failed to save mount namespace fd for pid %d: %s", pid, strerror(errno));

          ret = write_uint32_t(client_fd, (uint32_t)0);
          ASSURE_SIZE_WRITE("UpdateMountNamespace", "ns_fd", ret, sizeof(ns_fd), break);

          break;
        }

        ret = write_uint32_t(client_fd, (uint32_t)ns_fd);
        ASSURE_SIZE_WRITE("UpdateMountNamespace", "ns_fd", ret, sizeof(ns_fd), break);

        break;
      }
      case RemoveModule: {
        size_t index = 0;
        ssize_t ret = read_size_t(client_fd, &index);
        ASSURE_SIZE_READ("RemoveModule", "index", ret, sizeof(index), break);

        if (index >= context.len) {
          LOGE("Invalid module index: %zu", index);

          ret = write_uint8_t(client_fd, 0);
          ASSURE_SIZE_WRITE("RemoveModule", "response", ret, sizeof(uint8_t), break);

          break;
        }

        struct Module *module = &context.modules[index];
        if (module->companion >= 0) {
          close(module->companion);
          module->companion = -1;
        }

        free(module->name);
        module->name = NULL;

        if (module->lib_fd >= 0) {
          close(module->lib_fd);
          module->lib_fd = -1;
        }

        memmove(&context.modules[index], &context.modules[index + 1], (context.len - index - 1) * sizeof(struct Module));
        context.len--;

        ret = write_uint8_t(client_fd, 1);
        ASSURE_SIZE_WRITE("RemoveModule", "response", ret, sizeof(uint8_t), break);

        break;
      }
    }

    close(client_fd);
  }

  close(socket_fd);
  free_modules(&context);
  root_impl_cleanup();
}
