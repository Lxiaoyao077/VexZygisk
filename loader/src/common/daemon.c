#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include <limits.h>

#include <linux/un.h>
#include <sys/socket.h>

#include "logging.h"
#include "misc.h"
#include "socket_utils.h"

#include "daemon.h"

#define SOCKET_FILE_NAME LP_SELECT("cp32", "cp64") ".sock"

/* INFO: The socket either accepts at once or is refused outright, so a full
         second only stalls the injection of every process while the daemon is
         down. This is still long enough to ride out a daemon restart. */
#define REZYGISKD_RETRY_DELAY_US 100000

static int rezygiskd_connect(uint8_t retry) {
  struct sockaddr_un addr = {
    .sun_family = AF_UNIX,
    .sun_path = { 0 }
  };
  /*
    INFO: Application must assume that sun_path can hold _POSIX_PATH_MAX characters.

    Sources:
     - https://pubs.opengroup.org/onlinepubs/009696699/basedefs/sys/un.h.html
  */
  strcpy(addr.sun_path, TMP_PATH "/" SOCKET_FILE_NAME);

  for (uint8_t attempt = 0; attempt <= retry; attempt++) {
    int fd = socket(PF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd == -1) {
      PLOGE("socket");

      return -1;
    }

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != -1) return fd;

    PLOGE("connect (attempt %d of %d)", attempt + 1, retry + 1);

    close(fd);

    /* INFO: Waiting is pointless once there is no attempt left to make. */
    if (attempt == retry) break;

    usleep(REZYGISKD_RETRY_DELAY_US);
  }

  return -1;
}

/* INFO: Logs the failed exchange, closes the daemon socket and bails out. */
#define safe_check(fn, what, ret_type)              \
  if (fn == -1) {                                   \
    LOGE("Failed to " what " with VexZygiskd");     \
                                                    \
    close(fd);                                      \
                                                    \
    ret_type;                                       \
  }

#define safe_write(fn, name, ret_type) safe_check(fn, "write " name, ret_type)
#define safe_read(fn, name, ret_type)  safe_check(fn, "read " name, ret_type)

bool rezygiskd_zygote_injected(void) {
  int fd = rezygiskd_connect(5);
  if (fd == -1) return false;

  safe_write(write_uint8_t(fd, (uint8_t)ZygoteInjected), "ZygoteInjected action", return false);

  close(fd);

  return true;
}

uint32_t rezygiskd_get_process_flags(uid_t uid, const char *const process) {
  int fd = rezygiskd_connect(1);
  if (fd == -1) return 0;

  safe_write(write_uint8_t(fd, (uint8_t)GetProcessFlags), "GetProcessFlags action", return 0);
  safe_write(write_uint32_t(fd, (uint32_t)uid), "uid", return 0);
  safe_write(write_string(fd, process), "process name", return 0);

  uint32_t res = 0;
  safe_read(read_uint32_t(fd, &res), "process flags", return 0);

  close(fd);

  return res;
}

void rezygiskd_get_info(struct rezygisk_info *info) {
  int fd = rezygiskd_connect(1);
  if (fd == -1) {
    info->running = false;

    return;
  }

  info->running = true;

  safe_write(write_uint8_t(fd, (uint8_t)GetInfo), "GetInfo action", return);

  /* INFO: The flags word is consumed to stay in step with the protocol; the
            daemon always sets the bit of the root solution it was built for,
            which this flavour is built to match. */
  uint32_t flags = 0;
  safe_read(read_uint32_t(fd, &flags), "info flags", return);

#ifdef ROOT_IMPL_APATCH
  info->root_impl = ROOT_IMPL_APATCH;
#else
  info->root_impl = ROOT_IMPL_KERNELSU;
#endif

  uint32_t daemon_pid = 0;
  safe_read(read_uint32_t(fd, &daemon_pid), "pid", return);

  info->pid = (pid_t)daemon_pid;

  safe_read(read_size_t(fd, &info->modules.modules_count), "modules count", return);
  if (info->modules.modules_count == 0) {
    info->modules.modules = NULL;

    close(fd);

    return;
  }

  info->modules.modules = (char **)malloc(sizeof(char *) * info->modules.modules_count);
  if (!info->modules.modules) {
    PLOGE("allocating modules name memory");

    info->modules.modules_count = 0;

    close(fd);

    return;
  }

  for (size_t i = 0; i < info->modules.modules_count; i++) {
    char *module_name = read_string(fd);
    if (module_name == NULL) {
      PLOGE("reading module name");

      goto info_cleanup;
    }

    char module_path[PATH_MAX];
    snprintf(module_path, sizeof(module_path), "/data/adb/modules/%s/module.prop", module_name);

    free(module_name);

    FILE *module_prop = fopen(module_path, "r");
    if (!module_prop) {
      PLOGE("failed to open module prop file %s", module_path);

      goto info_cleanup;
    }

    info->modules.modules[i] = NULL;

    char line[1024];
    while (fgets(line, sizeof(line), module_prop) != NULL) {
      if (strncmp(line, "name=", strlen("name=")) != 0) continue;

      size_t name_len = strlen(line + strlen("name="));
      if (name_len == 0 || line[name_len + strlen("name=") - 1] != '\n') {
        LOGE("Invalid module name in %s", module_path);

        fclose(module_prop);

        goto info_cleanup;
      }

      info->modules.modules[i] = strndup(line + strlen("name="), name_len - 1);
      if (info->modules.modules[i] == NULL) {
        PLOGE("allocate memory for module name from %s", module_path);

        fclose(module_prop);

        goto info_cleanup;
      }

      break;
    }

    if (info->modules.modules[i] == NULL) {
      PLOGE("failed to read module name from %s", module_path);

      fclose(module_prop);

      goto info_cleanup;
    }

    fclose(module_prop);

    continue;

    info_cleanup:
      info->modules.modules_count = i;
      free_rezygisk_info(info);

      break;
  }

  close(fd);
}

void free_rezygisk_info(struct rezygisk_info *info) {
  for (size_t i = 0; i < info->modules.modules_count; i++) {
    free(info->modules.modules[i]);
  }

  free(info->modules.modules);
  info->modules.modules = NULL;
  info->modules.modules_count = 0;
}

bool rezygiskd_read_modules(struct zygisk_modules *modules) {
  int fd = rezygiskd_connect(1);
  if (fd == -1) return false;

  safe_write(write_uint8_t(fd, (uint8_t)ReadModules), "ReadModules action", return false);

  size_t len = 0;
  safe_read(read_size_t(fd, &len), "modules count", return false);

  /* INFO: calloc also validates the multiplication, so a corrupt count from
            the socket cannot overflow into an undersized allocation. */
  modules->modules = calloc(len, sizeof(char *));
  if (!modules->modules) {
    PLOGE("allocating modules name memory");

    close(fd);

    return false;
  }
  modules->modules_count = len;

  for (size_t i = 0; i < len; i++) {
    char *lib_path = read_string(fd);
    if (!lib_path) {
      PLOGE("reading module lib_path");

      modules->modules_count = i;
      free_modules(modules);

      close(fd);

      return false;
    }

    modules->modules[i] = lib_path;
  }

  close(fd);

  return true;
}

void free_modules(struct zygisk_modules *modules) {
  for (size_t i = 0; i < modules->modules_count; i++) {
    free(modules->modules[i]);
  }

  free(modules->modules);
  modules->modules = NULL;
  modules->modules_count = 0;
}

bool rezygiskd_read_zn_modules(const char *process_name, const char *process_path, struct zn_module_file **out, size_t *out_len) {
  *out = NULL;
  *out_len = 0;

  size_t filled = 0;

  int fd = rezygiskd_connect(1);
  if (fd == -1) return false;

  safe_write(write_uint8_t(fd, (uint8_t)ReadZnModules), "ReadZnModules action", return false);
  safe_write(write_string(fd, process_name), "process name", return false);
  safe_write(write_string(fd, process_path), "process path", return false);

  size_t len = 0;
  safe_read(read_size_t(fd, &len), "Zygisk Next modules count", return false);

  if (len == 0) {
    close(fd);

    *out = NULL;
    *out_len = 0;

    return true;
  }

  struct zn_module_file *files = calloc(len, sizeof(struct zn_module_file));
  if (!files) {
    PLOGE("allocating the Zygisk Next module list");

    close(fd);

    return false;
  }

  /* INFO: calloc leaves every descriptor at 0, which is a perfectly valid fd,
           so they have to read as "not open" until one is really stored. */
  for (size_t i = 0; i < len; i++) files[i].fd = -1;

  for (size_t i = 0; i < len; i++) {
    char *lib_path = read_string(fd);
    if (!lib_path) {
      PLOGE("reading a Zygisk Next module path");

      goto cleanup;
    }

    uint8_t companion = 0;
    if (read_uint8_t(fd, &companion) == -1) {
      PLOGE("reading a Zygisk Next companion flag");

      free(lib_path);

      goto cleanup;
    }

    int module_fd = read_fd(fd);
    if (module_fd == -1) {
      PLOGE("reading a Zygisk Next module fd");

      free(lib_path);

      goto cleanup;
    }

    files[i].lib_path = lib_path;
    files[i].companion = companion != 0;
    files[i].fd = module_fd;

    filled = i + 1;
  }

  close(fd);

  *out = files;
  *out_len = len;

  return true;

  cleanup:
    /* INFO: Hand back nothing rather than a list that has already been freed. */
    free_zn_module_files(files, filled);

    close(fd);

    return false;
}

void free_zn_module_files(struct zn_module_file *files, size_t len) {
  for (size_t i = 0; i < len; i++) {
    free(files[i].lib_path);
    if (files[i].fd >= 0) close(files[i].fd);
  }

  free(files);
}

int rezygiskd_spawn_zn_companion(const char *lib_path) {
  int fd = rezygiskd_connect(1);
  if (fd == -1) return -1;

  safe_write(write_uint8_t(fd, (uint8_t)SpawnZnCompanion), "SpawnZnCompanion action", return -1);
  safe_write(write_string(fd, lib_path), "Zygisk Next library path", return -1);

  uint8_t res = 0;
  safe_read(read_uint8_t(fd, &res), "Zygisk Next companion result", return -1);

  if (res != 1) {
    close(fd);

    return -1;
  }

  int companion_fd = read_fd(fd);

  close(fd);

  return companion_fd;
}

int rezygiskd_connect_companion(size_t index) {
  int fd = rezygiskd_connect(1);
  if (fd == -1) return -1;

  safe_write(write_uint8_t(fd, (uint8_t)RequestCompanionSocket), "RequestCompanionSocket action", return -1);
  safe_write(write_size_t(fd, index), "companion index", return -1);

  uint8_t res = 0;
  safe_read(read_uint8_t(fd, &res), "companion socket result", return -1);

  if (res == 1) return fd;
  else {
    close(fd);

    return -1;
  }
}

int rezygiskd_get_module_dir(size_t index) {
  int fd = rezygiskd_connect(1);
  if (fd == -1) return -1;

  safe_write(write_uint8_t(fd, (uint8_t)GetModuleDir), "GetModuleDir action", return -1);
  safe_write(write_size_t(fd, index), "module index", return -1);

  int dirfd = read_fd(fd);

  close(fd);

  return dirfd;
}

void rezygiskd_zygote_restart(void) {
  int fd = rezygiskd_connect(1);
  if (fd == -1) return;

  safe_write(write_uint8_t(fd, (uint8_t)ZygoteRestart), "ZygoteRestart action", return);

  close(fd);
}

bool rezygiskd_update_mns(enum mount_namespace_state nms_state, char *buf, size_t buf_size) {
  int fd = rezygiskd_connect(1);
  if (fd == -1) return false;

  safe_write(write_uint8_t(fd, (uint8_t)UpdateMountNamespace), "UpdateMountNamespace action", return false);
  safe_write(write_uint32_t(fd, (uint32_t)getpid()), "pid", return false);
  safe_write(write_uint8_t(fd, (uint8_t)nms_state), "mount namespace state", return false);

  uint32_t target_pid = 0;
  safe_read(read_uint32_t(fd, &target_pid), "target pid", return false);

  uint32_t target_fd = 0;
  safe_read(read_uint32_t(fd, &target_fd), "target fd", return false);

  if (target_fd == 0) {
    LOGE("Failed to get target fd");

    close(fd);

    return false;
  }

  snprintf(buf, buf_size, "/proc/%u/fd/%u", target_pid, target_fd);

  close(fd);

  return true;
}

bool rezygiskd_remove_module(size_t index) {
  int fd = rezygiskd_connect(1);
  if (fd == -1) return false;

  safe_write(write_uint8_t(fd, (uint8_t)RemoveModule), "RemoveModule action", return false);
  safe_write(write_size_t(fd, index), "module index", return false);

  uint8_t res = 0;
  safe_read(read_uint8_t(fd, &res), "remove module result", return false);

  close(fd);

  return res == 1;
}

#undef safe_read
#undef safe_write
