#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include <limits.h>

#include <linux/un.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/uio.h>

#include "logging.h"
#include "misc.h"
#include "socket_utils.h"

#include "daemon.h"

/* INFO: Bounds how long a request may block on the daemon once connected. A
         stalled or overloaded daemon would otherwise leave the caller - the
         spawner collecting its one-shot boot plan, a zygote child mid-
         specialize - hung forever on read(), since a plain blocking socket
         has no deadline of its own. Cleared again wherever the socket stops
         being ours: the companion protocols belong to the modules, and they
         may legitimately block far longer than this budget. */
#define REZYGISKD_IO_TIMEOUT_SEC 3

static void set_socket_timeout(int fd, long seconds) {
  struct timeval tv = {
    .tv_sec = seconds,
    .tv_usec = 0
  };

  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

static int rezygiskd_connect(uint8_t retry, uint32_t retry_delay_us) {
  struct sockaddr_un addr = {
    .sun_family = AF_UNIX,
    .sun_path = { 0 }
  };
  /*
    INFO: Application must assume that sun_path can hold _POSIX_PATH_MAX characters.

    Sources:
     - https://pubs.opengroup.org/onlinepubs/009696699/basedefs/sys/un.h.html
  */
  strcpy(addr.sun_path, ZYGISK_CP_SOCKET);

  for (uint8_t attempt = 0; attempt <= retry; attempt++) {
    int fd = socket(PF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd == -1) {
      PLOGE("socket");

      return -1;
    }

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != -1) {
      set_socket_timeout(fd, REZYGISKD_IO_TIMEOUT_SEC);

      return fd;
    }

    PLOGE("connect (attempt %d of %d)", attempt + 1, retry + 1);

    close(fd);

    /* INFO: Waiting is pointless once there is no attempt left to make. */
    if (attempt == retry) break;

    usleep(retry_delay_us);
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
  int fd = rezygiskd_connect(5, REZYGISKD_RETRY_DELAY_US);
  if (fd == -1) return false;

  safe_write(write_uint8_t(fd, (uint8_t)ZygoteInjected), "ZygoteInjected action", return false);

  close(fd);

  return true;
}

uint32_t rezygiskd_get_process_flags(uid_t uid, const char *const process) {
  int fd = rezygiskd_connect(1, REZYGISKD_RETRY_DELAY_US);
  if (fd == -1) return 0;

  safe_write(write_uint8_t(fd, (uint8_t)GetProcessFlags), "GetProcessFlags action", return 0);
  safe_write(write_uint32_t(fd, (uint32_t)uid), "uid", return 0);
  safe_write(write_string(fd, process), "process name", return 0);

  uint32_t res = 0;
  safe_read(read_uint32_t(fd, &res), "process flags", return 0);

  close(fd);

  return res;
}

/* INFO: The display name of one module, from its own module.prop.

         The path is built here because the name it is built from arrived over a
         socket, so its length is not this process's to assume: a name that does
         not fit is refused rather than truncated, since a truncated path is
         still a valid-looking one and the fopen below would report "no such
         file" for a path nobody ever asked for.

         Returns a strdup'ed name, or NULL with the reason already logged. */
static char *read_module_prop_name(const char *module_name) {
  static const char kNameTag[] = "name=";
  const size_t tag_len = sizeof(kNameTag) - 1;

  char module_path[PATH_MAX];
  int written = snprintf(module_path, sizeof(module_path), "/data/adb/modules/%s/module.prop", module_name);

  if (written < 0 || (size_t)written >= sizeof(module_path)) {
    LOGE("module name is too long for a prop path (%d bytes)", written);

    return NULL;
  }

  FILE *module_prop = fopen(module_path, "r");
  if (module_prop == NULL) {
    PLOGE("failed to open module prop file %s", module_path);

    return NULL;
  }

  char *name = NULL;
  char line[1024];

  while (fgets(line, sizeof(line), module_prop) != NULL) {
    if (strncmp(line, kNameTag, tag_len) != 0) continue;

    size_t value_len = strlen(line + tag_len);

    /* INFO: The newline has to be there: it is what says the line was read in
              full, and the name is the text before it. */
    if (value_len == 0 || line[value_len + tag_len - 1] != '\n') {
      LOGE("Invalid module name in %s", module_path);

      break;
    }

    name = strndup(line + tag_len, value_len - 1);
    if (name == NULL) PLOGE("allocate memory for module name from %s", module_path);

    break;
  }

  if (name == NULL) PLOGE("failed to read module name from %s", module_path);

  fclose(module_prop);

  return name;
}

void rezygiskd_get_info(struct rezygisk_info *info) {
  int fd = rezygiskd_connect(1, REZYGISKD_RETRY_DELAY_US);
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
  info->root_impl = ROOT_APATCH;
#else
  info->root_impl = ROOT_KERNELSU;
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

  /* INFO: calloc validates the multiplication for us. The count arrives over
            the socket, so a corrupted or hostile value could wrap
            count * sizeof(char *) into a small block that the loop below would
            then write straight past; calloc refuses that and returns NULL. */
  info->modules.modules = (char **)calloc(info->modules.modules_count, sizeof(char *));
  if (!info->modules.modules) {
    PLOGE("allocating modules name memory");

    info->modules.modules_count = 0;

    close(fd);

    return;
  }

  /* INFO: The list is handed back as far as it was read on every failure
            below: the count says how many entries exist, and the ones that were
            never reached are still the calloc'ed NULLs, so the caller can free
            the list and report a daemon that answered with less than it said. */
  for (size_t i = 0; i < info->modules.modules_count; i++) {
    char *module_name = read_string(fd);
    if (module_name == NULL) {
      PLOGE("reading module name");

      info->modules.modules_count = i;
      free_rezygisk_info(info);

      break;
    }

    info->modules.modules[i] = read_module_prop_name(module_name);

    free(module_name);

    if (info->modules.modules[i] == NULL) {
      info->modules.modules_count = i;
      free_rezygisk_info(info);

      break;
    }
  }

  close(fd);
}

void free_rezygisk_info(struct rezygisk_info *info) {
  free_modules(&info->modules);
}

bool rezygiskd_read_modules(struct zygisk_modules *modules) {
  int fd = rezygiskd_connect(1, REZYGISKD_RETRY_DELAY_US);
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

bool rezygiskd_read_zn_modules(const char *process_name, const char *process_path, const char *image_path, uint8_t retry, uint32_t retry_delay_us, struct zn_module_file **out, size_t *out_len) {
  *out = NULL;
  *out_len = 0;

  size_t filled = 0;

  int fd = rezygiskd_connect(retry, retry_delay_us);
  if (fd == -1) return false;

  safe_write(write_uint8_t(fd, (uint8_t)ReadZnModules), "ReadZnModules action", return false);
  safe_write(write_string(fd, process_name), "process name", return false);
  safe_write(write_string(fd, process_path), "process path", return false);

  /* INFO: The path the HyperOS runtime image is mapped from, which is the
            executable on the builds where the spawner is its own file and the
            image mapped into an ART host on the ones where it is not. Empty
            everywhere else, and the daemon treats an empty one as "no second
            answer" - so a process that merely inherited the runtime state (an
            application the spawner forked) does not become a match for the
            spawner's own path target. */
  safe_write(write_string(fd, image_path != NULL ? image_path : ""), "runtime image path", return false);

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

    /* INFO: The module id is the module directory the daemon found the library
              in, and it is what a module is named by everywhere else: the
              daemon's own plan, its log, and the runtime's report of a
              specialization. Read right after the path, so the two names of one
              module arrive together. */
    char *module_id = read_string(fd);
    if (!module_id) {
      PLOGE("reading a Zygisk Next module id");

      free(lib_path);

      goto cleanup;
    }

    uint8_t companion = 0;
    if (read_uint8_t(fd, &companion) == -1) {
      PLOGE("reading a Zygisk Next companion flag");

      free(lib_path);
      free(module_id);

      goto cleanup;
    }

    int module_fd = read_fd(fd);
    if (module_fd == -1) {
      PLOGE("reading a Zygisk Next module fd");

      free(lib_path);
      free(module_id);

      goto cleanup;
    }

    files[i].lib_path = lib_path;
    files[i].module_id = module_id;
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
    free(files[i].module_id);
    if (files[i].fd >= 0) close(files[i].fd);
  }

  free(files);
}

/* INFO: Opens the control session the HyperOS runtime reports over.

         The daemon keeps the connection rather than answering it once and
         closing, which is the difference from every request above: what comes
         back is a session, and the descriptor is meant to be inherited by the
         applications the spawner forks - they are the ones that report, and
         they cannot open one of their own once they are specialized. Every
         other exchange in this file is one request and one answer from a
         process that can come back later; this one is the only connection that
         outlives its request.

         The send timeout is short on purpose. A report is written from inside
         an application that is on its way to its first frame, so a daemon that
         has stopped reading must not hold it: a report that cannot be written
         promptly is worth less than the launch it would delay. */
int rezygiskd_open_zn_control_session(void) {
  int fd = rezygiskd_connect(1, REZYGISKD_RETRY_DELAY_US);
  if (fd == -1) return -1;

  if (write_uint8_t(fd, (uint8_t)OpenZnControlSession) == -1) {
    LOGE("Failed asking VexZygiskd for a Zygisk Next control session");

    close(fd);

    return -1;
  }

  uint8_t res = 0;
  if (read_uint8_t(fd, &res) == -1 || res != 1) {
    LOGE("VexZygiskd did not open a Zygisk Next control session");

    close(fd);

    return -1;
  }

  set_socket_timeout(fd, 1);

  return fd;
}

/* INFO: Writes one module report over an already open session.

         The session is handed in rather than opened here: it is the one the
         spawner opened and the fork passed down, and this call runs in the
         application, which has no way to open another once it is specialized.

         The whole record goes out in one sendmsg on purpose. Poll wakes the
         daemon on the first byte, and separate writes would let it read a header
         whose payload has not arrived yet - which it answers by ending the
         session. Under one call the kernel copies the record into the socket
         buffer whole, and what the daemon reads is always a record or nothing.

         MSG_NOSIGNAL is the other half of that. The far end of this socket is
         the daemon, and a daemon that has restarted - a soft reboot, a crash, a
         replacement after a stale socket - is exactly when this write fails:
         with SIGPIPE, whose default action would take down the application this
         runs in, at the moment it is starting up. The flag is asked for per call
         rather than by ignoring the signal for the whole process, because what
         is written here is not worth changing how the target handles it. */
bool rezygiskd_report_zn_runtime(int session_fd, const char *module_id) {
  if (session_fd < 0 || module_id == NULL) return false;

  const size_t id_len = strlen(module_id);
  if (id_len == 0 || id_len >= ZN_CONTROL_MODULE_ID_MAX) {
    LOGE("The Zygisk Next module id \"%s\" does not fit a report", module_id);

    return false;
  }

  /* INFO: The pid is read with a raw syscall: bionic caches getpid(), and the
            process that reports here may have been forked by the spawner
            without going through libc, which would leave that cache describing
            the process this one was forked from. */
  uint8_t action = (uint8_t)ReportZnRuntime;
  struct zn_control_report_header header = {
    .pid = (uint32_t)syscall(__NR_getpid),
    .module_id_len = (uint32_t)id_len
  };

  struct iovec record[3] = {
    { .iov_base = &action, .iov_len = sizeof(action) },
    { .iov_base = &header, .iov_len = sizeof(header) },
    { .iov_base = (void *)module_id, .iov_len = id_len }
  };

  struct msghdr message;
  memset(&message, 0, sizeof(message));
  message.msg_iov = record;
  message.msg_iovlen = 3;

  const size_t total = sizeof(action) + zn_control_report_size(id_len);
  const ssize_t written = sendmsg(session_fd, &message, MSG_NOSIGNAL);

  if (written != (ssize_t)total) {
    PLOGE("writing a Zygisk Next module report");

    return false;
  }

  return true;
}

int rezygiskd_spawn_zn_companion(const char *lib_path) {
  int fd = rezygiskd_connect(1, REZYGISKD_RETRY_DELAY_US);
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
  int fd = rezygiskd_connect(1, REZYGISKD_RETRY_DELAY_US);
  if (fd == -1) return -1;

  safe_write(write_uint8_t(fd, (uint8_t)RequestCompanionSocket), "RequestCompanionSocket action", return -1);
  safe_write(write_size_t(fd, index), "companion index", return -1);

  uint8_t res = 0;
  safe_read(read_uint8_t(fd, &res), "companion socket result", return -1);

  if (res == 1) {
    /* INFO: Past this point the same socket is the module's companion
              channel, and the module's protocol may block far longer than
              our daemon handshake budget - hand it over unconstrained. */
    set_socket_timeout(fd, 0);

    return fd;
  } else {
    close(fd);

    return -1;
  }
}

int rezygiskd_get_module_dir(size_t index) {
  int fd = rezygiskd_connect(1, REZYGISKD_RETRY_DELAY_US);
  if (fd == -1) return -1;

  safe_write(write_uint8_t(fd, (uint8_t)GetModuleDir), "GetModuleDir action", return -1);
  safe_write(write_size_t(fd, index), "module index", return -1);

  int dirfd = read_fd(fd);

  close(fd);

  return dirfd;
}

void rezygiskd_zygote_restart(void) {
  int fd = rezygiskd_connect(1, REZYGISKD_RETRY_DELAY_US);
  if (fd == -1) return;

  safe_write(write_uint8_t(fd, (uint8_t)ZygoteRestart), "ZygoteRestart action", return);

  close(fd);
}

bool rezygiskd_update_mns(enum mount_namespace_state nms_state, char *buf, size_t buf_size) {
  int fd = rezygiskd_connect(1, REZYGISKD_RETRY_DELAY_US);
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
  int fd = rezygiskd_connect(1, REZYGISKD_RETRY_DELAY_US);
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
