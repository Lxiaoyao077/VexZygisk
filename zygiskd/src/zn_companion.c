#define LOG_TAG "zygiskd-zn-companion"

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <dlfcn.h>
#include <pthread.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <linux/limits.h>

#include "zygisk_next_api.h"
#include "utils.h"

/* INFO: The command byte and the control buffer come from the shared protocol
         header, so the loader that serves this socket and the daemon that
         hosts it cannot define them differently. */
#include "zn_companion_protocol.h"

static struct ZygiskNextCompanionModule *load_companion_module(int library_fd) {
  char path[PATH_MAX];
  snprintf(path, sizeof(path), "/proc/self/fd/%d", library_fd);

  void *handle = dlopen(path, RTLD_NOW);
  if (handle == NULL) {
    LOGE("Failed to dlopen the companion library: %s", dlerror());

    return NULL;
  }

  struct ZygiskNextCompanionModule *module = (struct ZygiskNextCompanionModule *)dlsym(handle, "zn_companion_module");
  if (module == NULL) {
    LOGE("Failed to dlsym zn_companion_module: %s", dlerror());

    /* INFO: Nothing keeps this handle, so a failed lookup has to drop it here
              or the library stays mapped for the life of the companion. */
    dlclose(handle);
  }

  return module;
}

/* INFO: Entry point of "zygiskd zn-companion <fd>". Forked from the daemon so the
         companion inherits the daemon's SELinux domain rather than the restricted
         one of the target that loaded the module. One process serves one library
         for the daemon's lifetime; every connector gets a duplicate of the control
         socket. Protocol: path and fd in, one readiness byte back, then
         onCompanionLoaded once, then a command byte plus an fd per
         connectCompanion - each handed to onModuleConnected on its own thread, so
         one blocking connection cannot starve the others. */
struct zn_client_thread_args {
  int fd;
  void (*on_module_connected)(int);
};

static void *zn_client_thread(void *arg) {
  struct zn_client_thread_args *args = (struct zn_client_thread_args *)arg;

  int fd = args->fd;
  void (*on_module_connected)(int) = args->on_module_connected;

  free(args);

  struct stat st0 = { 0 };
  if (fstat(fd, &st0) == -1) {
    LOGE(" - Failed to stat the connection fd: %s", strerror(errno));

    /* INFO: This thread owns the connection fd and closes it at the end of a
              successful run; returning without closing leaks one descriptor per
              failure in a process that outlives every connection. */
    close(fd);

    return NULL;
  }

  on_module_connected(fd);

  /* INFO: Same heuristic as the standard companion: only close the fd if it
             still describes the same file, so a module that already closed
             it does not cause a double close on a recycled descriptor. */
  struct stat st1;
  if (fstat(fd, &st1) != -1 && st0.st_dev == st1.st_dev && st0.st_ino == st1.st_ino &&
      ((st0.st_mode ^ st1.st_mode) & S_IFMT) == 0) {
    LOGI(" - Connection fd unchanged after onModuleConnected, closing it");

    close(fd);
  }

  return NULL;
}

void zn_companion_entry(int fd) {
  /* INFO: Installed before the first write. A peer that has already gone away
            turns a write into SIGPIPE, whose default action kills the process
            instead of letting the error paths below run. */
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = SIG_IGN;
  sigaction(SIGPIPE, &sa, NULL);

  LOGI("New Zygisk Next companion. Control fd: %d", fd);

  char path[PATH_MAX];
  ssize_t ret = read_string(fd, path, sizeof(path));
  if (ret <= 0) {
    LOGE("Failed reading the companion library path");

    goto cleanup;
  }

  int library_fd = read_fd(fd);
  if (library_fd == -1) {
    LOGE("Failed receiving the companion library fd");

    goto cleanup;
  }

  LOGI(" - Library: %s (fd %d)", path, library_fd);

  struct ZygiskNextCompanionModule *module = load_companion_module(library_fd);
  close(library_fd);

  /* INFO: Both callbacks and a companion-capable API version, which is the same
           gate the loader applies before it asks for a companion at all. The
           version is not redundant here: a library that exports the symbol but
           was built against a contract that had no companions would otherwise be
           answered "ready" and then handed connections it cannot make sense of.
           YukiZygisk refuses the same pair of versions at this point. */
  bool usable = module != NULL && module->onCompanionLoaded != NULL && module->onModuleConnected != NULL &&
                (module->target_api_version == 3 || module->target_api_version == ZYGISK_NEXT_API_VERSION);

  if (!usable) {
    LOGE(" - No usable zn_companion_module in \"%s\"", path);

    ret = write_uint8_t(fd, (uint8_t)0);
    ASSURE_SIZE_WRITE("ZnCompanion", "response", ret, sizeof(uint8_t), goto cleanup);

    goto cleanup;
  }

  ret = write_uint8_t(fd, (uint8_t)1);
  if (ret != (ssize_t)sizeof(uint8_t)) {
    LOGE("Failed confirming the companion is ready");

    goto cleanup;
  }

  module->onCompanionLoaded();

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

    ssize_t received;
    do {
      received = recvmsg(fd, &message, 0);
    } while (received == -1 && errno == EINTR);

    if (received <= 0) {
      LOGI(" - Control socket closed, companion of \"%s\" is done", path);

      break;
    }

    /* INFO: Taken out before the command is looked at: an unserved request
             still owns the fd it carried, and dropping it here would leak one
             descriptor per request. */
    int connection_fd = -1;
    for (struct cmsghdr *header = CMSG_FIRSTHDR(&message); header != NULL; header = CMSG_NXTHDR(&message, header)) {
      if (header->cmsg_level != SOL_SOCKET || header->cmsg_type != SCM_RIGHTS) continue;

      /* INFO: Checked before the copy: the length in the header is what says a
                descriptor is actually there, and a request that arrived with the
                rights truncated would otherwise be read past the end of the
                control buffer. */
      if (header->cmsg_len < CMSG_LEN(sizeof(connection_fd))) continue;

      memcpy(&connection_fd, CMSG_DATA(header), sizeof(connection_fd));

      break;
    }

    if (command != ZN_COMPANION_CMD_CONNECT) {
      if (connection_fd >= 0) close(connection_fd);

      continue;
    }

    if (connection_fd < 0) {
      LOGE(" - Connection request without a file descriptor");

      continue;
    }

    /* INFO: Acknowledged before the handling thread exists, so the loader's
              read of this byte is evidence the companion really holds the
              connection. A module that started talking straight away would
              otherwise race a thread this process had not spawned yet. */
    uint8_t ack = ZN_COMPANION_ACK;
    ssize_t ack_written;

    do {
      ack_written = write(connection_fd, &ack, sizeof(ack));
    } while (ack_written == -1 && errno == EINTR);

    if (ack_written != (ssize_t)sizeof(ack)) {
      LOGE(" - Failed acknowledging the module connection: %s", strerror(errno));

      close(connection_fd);

      continue;
    }

    struct zn_client_thread_args *args = malloc(sizeof(struct zn_client_thread_args));
    if (args == NULL) {
      LOGE("Failed allocating the client thread args");

      close(connection_fd);

      continue;
    }

    args->fd = connection_fd;
    args->on_module_connected = module->onModuleConnected;

    pthread_t thread;
    if (pthread_create(&thread, NULL, zn_client_thread, args) != 0) {
      LOGE("Failed creating a thread for the module connection");

      close(connection_fd);
      free(args);

      continue;
    }

    pthread_detach(thread);
  }

  cleanup:
    close(fd);

    exit(0);
}
