#define LOG_TAG "zygiskd-zn-companion" LP_SELECT("32", "64")

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

/* INFO: Command byte the module sends when it calls connectCompanion. */
#define ZN_COMPANION_CMD_CONNECT ((uint8_t)1)

/* INFO: The kernel may copy a cmsghdr into the control buffer, so it has to be
         aligned as one instead of being a plain byte array. */
union zn_cmsg_buffer {
  struct cmsghdr header;
  char control[CMSG_SPACE(sizeof(int))];
};

static struct ZygiskNextCompanionModule *load_companion_module(int library_fd) {
  char path[PATH_MAX];
  snprintf(path, sizeof(path), "/proc/self/fd/%d", library_fd);

  void *handle = dlopen(path, RTLD_NOW);
  if (handle == NULL) {
    LOGE("Failed to dlopen the companion library: %s", dlerror());

    return NULL;
  }

  struct ZygiskNextCompanionModule *module = (struct ZygiskNextCompanionModule *)dlsym(handle, "zn_companion_module");
  if (module == NULL) LOGE("Failed to dlsym zn_companion_module: %s", dlerror());

  return module;
}

/* INFO: Entry point of "zygiskd zn-companion <fd>", a process forked from the
         daemon so the companion keeps the daemon's SELinux domain instead of
         the restricted one of the target that loaded the module. One process
         serves one library for the daemon's whole lifetime; every connecting
         process gets a duplicate of the control socket.

         Protocol, mirroring the Zygisk Next contract:
         1. the library path and its fd arrive on the control socket
         2. one byte goes back: 1 when the companion is ready, 0 otherwise
         3. onCompanionLoaded runs once
         4. every connectCompanion call sends a command byte plus an fd
            through SCM_RIGHTS; each is handed to onModuleConnected on its
            own thread, so one blocking module connection cannot starve the
            others. */
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

  if (module == NULL || module->onCompanionLoaded == NULL || module->onModuleConnected == NULL) {
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

  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = SIG_IGN;
  sigaction(SIGPIPE, &sa, NULL);

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
