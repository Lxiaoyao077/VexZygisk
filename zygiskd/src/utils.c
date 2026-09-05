#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <fcntl.h>
#include <poll.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/xattr.h>

#include <linux/limits.h>
#include <sched.h>
#include <unistd.h>

#include "root_impl/common.h"

#include "utils.h"

bool switch_mount_namespace(pid_t pid) {
  char path[PATH_MAX];
  snprintf(path, sizeof(path), "/proc/%d/ns/mnt", pid);

  int nsfd = open(path, O_RDONLY | O_CLOEXEC);
  if (nsfd == -1) {
    LOGE("Failed to open nsfd: %s", strerror(errno));

    return false;
  }

  if (setns(nsfd, CLONE_NEWNS) == -1) {
    LOGE("Failed to setns: %s", strerror(errno));

    close(nsfd);

    return false;
  }

  close(nsfd);

  return true;
}

static bool write_sockcreate(const char *restrict path, const char *restrict context) {
  FILE *sockcreate = fopen(path, "w");
  if (sockcreate == NULL) {
    LOGE("Failed to open %s with %d: %s", path, errno, strerror(errno));

    return false;
  }

  if (fwrite(context, 1, strlen(context), sockcreate) != strlen(context)) {
    LOGE("Failed to write to %s with %d: %s", path, errno, strerror(errno));

    fclose(sockcreate);

    return false;
  }

  fclose(sockcreate);

  return true;
}

void set_socket_create_context(const char *restrict context) {
  if (write_sockcreate("/proc/thread-self/attr/sockcreate", context)) return;

  /* INFO: thread-self can fail on very old kernels, so fall back to the
            explicit task directory of this thread. */
  char path[PATH_MAX];
  snprintf(path, PATH_MAX, "/proc/self/task/%d/attr/sockcreate", gettid());

  write_sockcreate(path, context);
}

static bool get_current_attr(char *restrict output, size_t size) {
  FILE *current = fopen("/proc/self/attr/current", "r");
  if (current == NULL) {
    LOGE("fopen: %s", strerror(errno));

    return false;
  }

  size_t ret = fread(output, 1, size - 1, current);
  if (ferror(current)) {
    LOGE("fread: %s", strerror(errno));

    fclose(current);

    return false;
  }

  output[ret] = '\0';

  fclose(current);

  return true;
}

void unix_datagram_sendto(const char *restrict path, const void *restrict buf, size_t len) {
  char current_attr[PATH_MAX];
  if (!get_current_attr(current_attr, sizeof(current_attr))) {
    LOGE("Failed to get current attribute");

    return;
  }

  set_socket_create_context(current_attr);

  struct sockaddr_un addr = {
    .sun_family = AF_UNIX
  };
  strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

  int socket_fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (socket_fd == -1) {
    LOGE("socket: %s", strerror(errno));

    goto restore;
  }

  if (connect(socket_fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
    LOGE("connect: %s", strerror(errno));

    close(socket_fd);

    goto restore;
  }

  if (send(socket_fd, buf, len, 0) == -1) {
    LOGE("send: %s", strerror(errno));

    close(socket_fd);

    goto restore;
  }

  close(socket_fd);

  restore:
    set_socket_create_context("u:r:zygote:s0");
}

int chcon(const char *restrict path, const char *context) {
  return lsetxattr(path, "security.selinux", context, strlen(context) + 1, 0);
}

int unix_listener_from_path(const char *restrict path) {
  if (remove(path) == -1 && errno != ENOENT) {
    LOGE("remove: %s", strerror(errno));

    return -1;
  }

  int socket_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (socket_fd == -1) {
    LOGE("socket: %s", strerror(errno));

    return -1;
  }

  struct sockaddr_un addr = {
    .sun_family = AF_UNIX
  };
  strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

  if (bind(socket_fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_un)) == -1) {
    LOGE("bind: %s", strerror(errno));

    close(socket_fd);

    return -1;
  }

  /* INFO: A backlog of 2 dropped connections whenever several zygote forks
             connected at once; the loader retries once at 100 ms, so a drop
             cost a whole inject attempt. */
  if (listen(socket_fd, 16) == -1) {
    LOGE("listen: %s", strerror(errno));

    close(socket_fd);

    return -1;
  }

  if (chcon(path, "u:object_r:zygisk_file:s0") == -1)
    LOGW("chcon (non-fatal): %s", strerror(errno));

  return socket_fd;
}

ssize_t write_fd(int fd, int sendfd) {
  char cmsgbuf[CMSG_SPACE(sizeof(int))];
  char buf[1] = { 0 };

  struct iovec iov = {
    .iov_base = buf,
    .iov_len = sizeof(buf)
  };

  struct msghdr msg = {
    .msg_iov = &iov,
    .msg_iovlen = 1,
    .msg_control = cmsgbuf,
    .msg_controllen = sizeof(cmsgbuf)
  };

  struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
  cmsg->cmsg_len = CMSG_LEN(sizeof(int));
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;

  memcpy(CMSG_DATA(cmsg), &sendfd, sizeof(int));

  ssize_t ret = sendmsg(fd, &msg, 0);
  if (ret == -1) {
    LOGE("sendmsg: %s", strerror(errno));

    return -1;
  }

  return ret;
}

int read_fd(int fd) {
  char cmsgbuf[CMSG_SPACE(sizeof(int))];

  /* INFO: The peer writes a single data byte with every descriptor, so the
            payload sizes match on both ends of the exchange. */
  char buf[1] = { 0 };

  struct iovec iov = {
    .iov_base = buf,
    .iov_len = sizeof(buf)
  };

  struct msghdr msg = {
    .msg_iov = &iov,
    .msg_iovlen = 1,
    .msg_control = cmsgbuf,
    .msg_controllen = sizeof(cmsgbuf)
  };

  ssize_t ret = recvmsg(fd, &msg, MSG_WAITALL);
  if (ret == -1) {
    LOGE("recvmsg: %s", strerror(errno));

    return -1;
  }

  struct cmsghdr *cmsg;
  int sendfd = -1;

  for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
    if (cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS || cmsg->cmsg_len < CMSG_LEN(sizeof(int))) continue;

    memcpy(&sendfd, CMSG_DATA(cmsg), sizeof(int));

    break;
  }

  if (sendfd == -1) {
    LOGE("Failed to receive fd: No valid fd found in ancillary data.");

    return -1;
  }

  return sendfd;
}

/* INFO: memfd_create() only reaches bionic from API 30, while common.mk builds
         against a much older one, so the syscall is issued directly. */
#ifndef MFD_CLOEXEC
  #define MFD_CLOEXEC 0x0001U
#endif

/* INFO: Hands a library over as a memfd instead of a descriptor of the file
         itself, which is what lets an unprivileged target load it at all.

         Reopening /proc/self/fd skips the permissions of every directory
         leading to the file, /data/adb among them, but the file then still
         carries its own mode and its SELinux label, and a target that is not
         root is usually allowed to touch neither. A memfd is created here, so
         it is owned by this daemon and labelled after its domain. */
int create_library_fd(const char *restrict path) {
  int file_fd = open(path, O_RDONLY | O_CLOEXEC);
  if (file_fd == -1) {
    LOGE("Failed opening \"%s\": %s", path, strerror(errno));

    return -1;
  }

  int mem_fd = (int)syscall(__NR_memfd_create, "zn-module", MFD_CLOEXEC);
  if (mem_fd == -1) {
    LOGE("Failed creating a memfd: %s", strerror(errno));

    close(file_fd);

    return -1;
  }

  char buffer[65536];
  bool copied = true;

  for (;;) {
    ssize_t got = read(file_fd, buffer, sizeof(buffer));
    if (got == -1) {
      if (errno == EINTR) continue;

      LOGE("Failed reading \"%s\": %s", path, strerror(errno));

      copied = false;

      break;
    }

    if (got == 0) break;

    if (write_loop(mem_fd, buffer, (size_t)got) != got) {
      LOGE("Failed filling the memfd of \"%s\"", path);

      copied = false;

      break;
    }
  }

  close(file_fd);

  if (!copied) {
    close(mem_fd);

    return -1;
  }

  return mem_fd;
}

/* INFO: A stream socket may transfer less than asked for, so every exchange
         loops until the whole payload moved; a partial one desynchronises the
         protocol and the rest of the conversation is read as garbage. */
ssize_t write_loop(int fd, const void *restrict buf, size_t count) {
  const char *data = (const char *)buf;
  size_t written_bytes = 0;

  while (written_bytes < count) {
    ssize_t ret = write(fd, data + written_bytes, count - written_bytes);
    if (ret == -1) {
      if (errno == EINTR) continue;

      LOGE("write failed with %d: %s", errno, strerror(errno));

      return -1;
    }

    written_bytes += (size_t)ret;
  }

  return (ssize_t)written_bytes;
}

ssize_t read_loop(int fd, void *restrict buf, size_t count) {
  char *data = (char *)buf;
  size_t read_bytes = 0;

  while (read_bytes < count) {
    ssize_t ret = read(fd, data + read_bytes, count - read_bytes);
    if (ret == -1) {
      if (errno == EINTR) continue;

      LOGE("read failed with %d: %s", errno, strerror(errno));

      return -1;
    }

    /* INFO: The peer hung up, a short exchange rather than a failed one. */
    if (ret == 0) return (ssize_t)read_bytes;

    read_bytes += (size_t)ret;
  }

  return (ssize_t)read_bytes;
}

#define write_func(type)                                 \
  ssize_t write_## type(int fd, type val) {              \
    return write_loop(fd, &val, sizeof(type));           \
  }

#define read_func(type)                                  \
  ssize_t read_## type(int fd, type *val) {              \
    return read_loop(fd, val, sizeof(type));             \
  }

write_func(size_t)
read_func(size_t)

write_func(uint32_t)
read_func(uint32_t)

write_func(uint8_t)
read_func(uint8_t)

ssize_t write_string(int fd, const char *restrict str) {
  size_t str_len = strlen(str);
  ssize_t written_bytes = write_loop(fd, &str_len, sizeof(size_t));
  if (written_bytes != (ssize_t)sizeof(size_t)) {
    LOGE("Failed to write string length: Not all bytes were written (%zd != %zu).", written_bytes, sizeof(size_t));

    return -1;
  }

  written_bytes = write_loop(fd, str, str_len);
  if ((size_t)written_bytes != str_len) {
    LOGE("Failed to write string: Not all bytes were written.");

    return -1;
  }

  return written_bytes;
}

ssize_t read_string(int fd, char *restrict buf, size_t buf_size) {
  size_t str_len = 0;
  ssize_t read_bytes = read_loop(fd, &str_len, sizeof(size_t));
  if (read_bytes != (ssize_t)sizeof(size_t)) {
    LOGE("Failed to read string length: Not all bytes were read (%zd != %zu).", read_bytes, sizeof(size_t));

    return -1;
  }

  if (buf_size == 0 || str_len > buf_size - 1) {
    LOGE("Failed to read string: Buffer is too small (%zu > %zu - 1).", str_len, buf_size);

    return -1;
  }

  read_bytes = read_loop(fd, buf, str_len);
  if (read_bytes != (ssize_t)str_len) {
    LOGE("Failed to read string: Promised bytes doesn't exist (%zd != %zu).", read_bytes, str_len);

    return -1;
  }

  buf[str_len] = '\0';

  return read_bytes;
}

bool check_unix_socket(int fd, bool block) {
  struct pollfd pfd = {
    .fd = fd,
    .events = POLLIN,
    .revents = 0
  };

  int timeout = block ? -1 : 0;
  if (poll(&pfd, 1, timeout) == -1) {
    LOGE("poll: %s", strerror(errno));

    return false;
  }

  return pfd.revents & ~POLLIN ? false : true;
}

void stringify_root_impl_name(struct root_impl impl, char *restrict output) {
#ifdef ROOT_IMPL_APATCH
  switch (impl.impl) {
    case APatch: {
      strcpy(output, "APatch");

      break;
    }
  }
#else
  switch (impl.impl) {
    case KernelSU: {
      strcpy(output, "KernelSU");

      break;
    }
  }
#endif
}

/* INFO: Only the fields consumed by umount_root are kept: the mount point
         itself plus the source and root it matches against. */
struct mountinfo {
  char *root;
  char *target;
  char *source;
};

struct mountinfos {
  struct mountinfo *mounts;
  size_t length;
};

void free_mounts(struct mountinfos *restrict mounts) {
  for (size_t i = 0; i < mounts->length; i++) {
    free(mounts->mounts[i].root);
    free(mounts->mounts[i].target);
    free(mounts->mounts[i].source);
  }

  free(mounts->mounts);
}

/* INFO: One mountinfo line, split on the " - " separator, which is the only
         delimiter that cannot appear inside a field. The line is cut in place
         so arbitrarily long paths cost nothing beyond the getline buffer:

           36 35 98:0 /root /target rw,... - type source rw,...
*/
static bool mountinfo_parse_line(char *line, struct mountinfo *out) {
  char *separator = strstr(line, " - ");
  if (separator == NULL) return false;

  *separator = '\0';

  char root[4096], target[4096], source[4096], type[128];

  if (sscanf(line, "%*u %*u %*u:%*u %4095s %4095s", root, target) != 2) return false;

  /* INFO: After the separator come the filesystem type and the source; some
            pseudo-filesystems carry no source and cannot be a root mount. */
  if (sscanf(separator + 3, "%127s %4095s", type, source) != 2) return false;

  out->root = strdup(root);
  out->target = strdup(target);
  out->source = strdup(source);

  if (out->root == NULL || out->target == NULL || out->source == NULL) {
    free(out->root);
    free(out->target);
    free(out->source);

    out->root = NULL;
    out->target = NULL;
    out->source = NULL;

    return false;
  }

  return true;
}

bool parse_mountinfo(const char *restrict pid, struct mountinfos *restrict mounts) {
  char path[PATH_MAX];
  snprintf(path, PATH_MAX, "/proc/%s/mountinfo", pid);

  FILE *mountinfo = fopen(path, "re");
  if (mountinfo == NULL) {
    LOGE("fopen: %s", strerror(errno));

    return false;
  }

  char *line = NULL;
  size_t line_capacity = 0;
  size_t i = 0;

  mounts->mounts = NULL;
  mounts->length = 0;

  while (getline(&line, &line_capacity, mountinfo) > 0) {
    size_t length = strlen(line);
    while (length > 0 && (line[length - 1] == '\n' || line[length - 1] == '\r')) line[--length] = '\0';

    struct mountinfo *tmp_mounts = (struct mountinfo *)realloc(mounts->mounts, (i + 1) * sizeof(struct mountinfo));
    if (!tmp_mounts) {
      LOGE("Failed to allocate memory for mounts->mounts");

      goto cleanup_mount_allocs;
    }
    mounts->mounts = tmp_mounts;

    struct mountinfo *mount = &mounts->mounts[i];

    if (!mountinfo_parse_line(line, mount)) {
      /* INFO: Lines without a source (pseudo-filesystems) are routine here,
                so a skipped line is not worth a log entry. The slot is left
                to be reused by the next line; the length only counts fully
                parsed entries, so consumers never see NULL fields. */
      continue;
    }

    mounts->length = ++i;
  }

  free(line);
  fclose(mountinfo);

  return true;

  cleanup_mount_allocs:
    /* INFO: The length counts every allocated entry, so free_mounts
             releases exactly what was built. */
    free_mounts(mounts);
    free(line);
    fclose(mountinfo);

    return false;
}

/* INFO: The overlay mounts of each root solution carry its own source name:
         KernelSU reports "KSU", APatch reports "APatch" or "kpatch". The
         flavour is fixed at build time, so only the matching names are
         compiled in — the same table the loader keeps in injector/unmount.c. */
#ifdef ROOT_IMPL_APATCH
  static const char *const kRootSources[] = { "APatch", "kpatch" };
  #define ROOT_SOURCE_COUNT 2
#else
  static const char *const kRootSources[] = { "KSU" };
  #define ROOT_SOURCE_COUNT 1
#endif

bool umount_root(void) {
  /* INFO: This runs in a child that already setns'ed into the target pid's
            mount namespace, so "self" here is the namespace to clean. */
  struct mountinfos mounts;
  if (!parse_mountinfo("self", &mounts)) {
    LOGE("Failed to parse mountinfo");

    return false;
  }

  const char *source_name = kRootSources[0];

  LOGI("[%s] Unmounting root", source_name);

  char **targets_to_unmount = NULL;
  size_t num_targets = 0;

  for (size_t i = 0; i < mounts.length; i++) {
    struct mountinfo mount = mounts.mounts[i];

    bool should_unmount = false;
    for (size_t s = 0; s < ROOT_SOURCE_COUNT && !should_unmount; s++) {
      if (strcmp(mount.source, kRootSources[s]) == 0) should_unmount = true;
    }
    if (strncmp(mount.target, "/data/adb/modules", strlen("/data/adb/modules")) == 0) should_unmount = true;
    if (strncmp(mount.root, "/adb/modules/", strlen("/adb/modules/")) == 0) should_unmount = true;

    if (!should_unmount) continue;

    char **tmp_targets = realloc(targets_to_unmount, (num_targets + 1) * sizeof(char*));
    if (tmp_targets == NULL) {
      LOGE("[%s] Failed to allocate memory for targets_to_unmount", source_name);

      free(targets_to_unmount);

      free_mounts(&mounts);

      return false;
    }
    targets_to_unmount = tmp_targets;

    num_targets++;

    targets_to_unmount[num_targets - 1] = mount.target;
  }

  for (size_t i = num_targets; i > 0; i--) {
    const char *target = targets_to_unmount[i - 1];
    if (umount2(target, MNT_DETACH) == -1) {
      LOGE("[%s] Failed to unmount %s: %s", source_name, target, strerror(errno));

      continue;
    }

    LOGI("[%s] Unmounted %s", source_name, target);
  }

  free(targets_to_unmount);

  free_mounts(&mounts);

  return true;
}

int save_mns_fd(int pid, enum MountNamespaceState mns_state) {
  /* INFO: The clean namespace is requested for every denylisted process, so it
            is cached for the daemon's lifetime instead of forked per process. */
  static int clean_namespace_fd = -1;

  if (mns_state == Clean && clean_namespace_fd != -1) return clean_namespace_fd;

  int sockets[2];
  if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) == -1) {
    LOGE("socketpair: %s", strerror(errno));

    return -1;
  }

  int socket_parent = sockets[0];
  int socket_child = sockets[1];

  /* INFO: The handshake runs inside a request handler; a helper wedged on a
            strange /proc entry must not block the daemon for good. On a
            timeout the socket is closed, which makes the child's next write
            fail and lets it exit for the reap below. */
  struct timeval timeout = { .tv_sec = 5, .tv_usec = 0 };
  setsockopt(socket_parent, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
  setsockopt(socket_parent, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

  pid_t fork_pid = fork();
  if (fork_pid < 0) {
    LOGE("fork: %s", strerror(errno));

    close(socket_parent);
    close(socket_child);

    return -1;
  }

  /* INFO: Every early return below leaves the helper child running or dead;
            reaping it keeps a long-lived daemon from collecting zombies. */
  #define FAIL_MNS(message)                                    \
    do {                                                       \
      LOGE("%s: %s", message, strerror(errno));                \
                                                                 \
      close(socket_parent);                                    \
      waitpid(fork_pid, NULL, 0);                              \
                                                                 \
      return -1;                                               \
    } while (0)

  if (fork_pid == 0) {
    close(socket_parent);

    if (switch_mount_namespace(pid) == false) {
      LOGE("Failed to switch mount namespace");

      if (write_uint8_t(socket_child, 0) == -1)
        LOGE("Failed to write to socket_child: %s", strerror(errno));

      goto finalize_mns_fork;
    }

    if (mns_state == Clean) {
      unshare(CLONE_NEWNS);

      if (!umount_root()) {
        LOGE("Failed to umount root");

        if (write_uint8_t(socket_child, 0) == -1)
          LOGE("Failed to write to socket_child: %s", strerror(errno));

        goto finalize_mns_fork;
      }
    }

    if (write_uint8_t(socket_child, 1) == -1) {
      LOGE("Failed to write to socket_child: %s", strerror(errno));

      close(socket_child);

      _exit(1);
    }

    uint8_t has_opened = 0;
    if (read_uint8_t(socket_child, &has_opened) == -1)
      LOGE("Failed to read from socket_child: %s", strerror(errno));

    finalize_mns_fork:
      close(socket_child);

      _exit(0);
  }

  close(socket_child);

  uint8_t has_succeeded = 0;
  if (read_uint8_t(socket_parent, &has_succeeded) == -1) FAIL_MNS("Failed to read from socket_parent");

  if (!has_succeeded) {
    LOGE("Failed to umount root");

    close(socket_parent);
    waitpid(fork_pid, NULL, 0);

    return -1;
  }

  char ns_path[PATH_MAX];
  snprintf(ns_path, PATH_MAX, "/proc/%d/ns/mnt", fork_pid);

  /* INFO: CLOEXEC only matters at exec time; the fd stays open in the daemon
            for the loader to reach through /proc, but never leaks into a
            companion spawned afterwards. */
  int ns_fd = open(ns_path, O_RDONLY | O_CLOEXEC);
  if (ns_fd == -1) FAIL_MNS("open");

  uint8_t opened_signal = 1;
  if (write_uint8_t(socket_parent, opened_signal) == -1) {
    close(ns_fd);
    FAIL_MNS("Failed to write to socket_parent");
  }

  if (close(socket_parent) == -1) {
    close(ns_fd);
    FAIL_MNS("Failed to close socket_parent");
  }

  if (waitpid(fork_pid, NULL, 0) == -1) {
    LOGE("waitpid: %s", strerror(errno));

    close(ns_fd);

    return -1;
  }

  clean_namespace_fd = ns_fd;

  return ns_fd;

  #undef FAIL_MNS
}
