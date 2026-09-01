#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>

#include <unistd.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>

#include "daemon.h"
#include "socket_utils.h"
#include "utils.h"

#include "monitor.h"

#define SOCKET_NAME "init_monitor"

#define STOPPED_WITH(sig, event) (WIFSTOPPED(sigchld_status) && (sigchld_status >> 8 == ((sig) | ((event) << 8))))

#ifdef __LP64__
  #define MONITOR_ABI "64"
  #define APP_PROCESS_NAME "/system/bin/app_process64"
  #define CMD_ZYGOTE_INJECTED ZYGOTE64_INJECTED
  #define CMD_DAEMON_SET_INFO DAEMON64_SET_INFO
  #define CMD_DAEMON_SET_ERROR_INFO DAEMON64_SET_ERROR_INFO
#else
  #define MONITOR_ABI "32"
  #define APP_PROCESS_NAME "/system/bin/app_process32"
  #define CMD_ZYGOTE_INJECTED ZYGOTE32_INJECTED
  #define CMD_DAEMON_SET_INFO DAEMON32_SET_INFO
  #define CMD_DAEMON_SET_ERROR_INFO DAEMON32_SET_ERROR_INFO
#endif

static bool update_status(const char *message);

const char *monitor_stop_reason = NULL;

struct environment_information {
  char *root_impl;
  char **modules;
  bool *modules_zn;
  bool *modules_companion;
  char ***modules_targets;
  uint32_t *modules_targets_len;
  uint32_t modules_len;
};

static struct environment_information environment_information;

enum ptracer_tracing_state {
  TRACING,
  STOPPING,
  STOPPED,
  EXITING
};

enum ptracer_tracing_state tracing_state = TRACING;

struct rezygiskd_status {
  bool supported;
  bool zygote_injected;
  bool daemon_running;
  pid_t daemon_pid;
  char *daemon_error_info;
};

struct rezygiskd_status status = {
  .supported = false,
  .zygote_injected = false,
  .daemon_running = false,
  .daemon_pid = -1,
  .daemon_error_info = NULL
};

int monitor_epoll_fd;
bool monitor_events_running = true;
typedef void (*monitor_event_callback_t)();

bool monitor_events_init() {
  monitor_epoll_fd = epoll_create(1);
  if (monitor_epoll_fd == -1) {
    PLOGE("epoll_create");

    return false;
  }

  return true;
}

bool monitor_events_register_event(monitor_event_callback_t event_cb, int fd, uint32_t events) {
  struct epoll_event ev = {
    .data.ptr = (void *)event_cb,
    .events = events
  };

  if (epoll_ctl(monitor_epoll_fd, EPOLL_CTL_ADD, fd, &ev) == -1) {
    PLOGE("epoll_ctl");

    return false;
  }

  return true;
}

void monitor_events_stop() {
  monitor_events_running = false;
}

void monitor_events_loop() {
  struct epoll_event events[2];
  while (monitor_events_running) {
    int nfds = epoll_wait(monitor_epoll_fd, events, 2, -1);
    if (nfds == -1 && errno != EINTR) {
      PLOGE("epoll_wait");

      monitor_events_running = false;

      break;
    }

    for (int i = 0; i < nfds; i++) {
      if (events[i].events & (EPOLLERR | EPOLLHUP)) {
        LOGE("Failed event on fd %d: %s", ((struct epoll_event *)&events[i])->data.fd, strerror(errno));

        monitor_events_running = false;

        break;
      }

      ((monitor_event_callback_t)events[i].data.ptr)();

      if (!monitor_events_running) break;
    }
  }

  if (monitor_epoll_fd >= 0) close(monitor_epoll_fd);
  monitor_epoll_fd = -1;
}

int monitor_sock_fd;

bool rezygiskd_listener_init() {
  monitor_sock_fd = socket(PF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
  if (monitor_sock_fd == -1) {
    PLOGE("socket create");

    return false;
  }

  struct sockaddr_un addr = {
    .sun_family = AF_UNIX,
    .sun_path = { 0 }
  };

  size_t sun_path_len = sprintf(addr.sun_path, "%s/%s", rezygiskd_get_path(), SOCKET_NAME);

  socklen_t socklen = sizeof(sa_family_t) + sun_path_len;
  if (bind(monitor_sock_fd, (struct sockaddr *)&addr, socklen) == -1) {
    PLOGE("bind socket");

    return false;
  }

  return true;
}

void rezygiskd_listener_callback() {
  while (1) {
    uint8_t cmd;
    ssize_t nread = TEMP_FAILURE_RETRY(read(monitor_sock_fd, &cmd, sizeof(cmd)));
    if (nread == -1) {
      if (errno == EINTR || errno == EWOULDBLOCK) break;

      PLOGE("read socket");

      continue;
    }

    switch (cmd) {
      case START: {
        if (tracing_state == STOPPING) {
          LOGI("Continue tracing init");

          tracing_state = TRACING;
        } else if (tracing_state == STOPPED) {
          LOGI("Start tracing init");

          ptrace(PTRACE_SEIZE, 1, 0, PTRACE_O_TRACEFORK);

          tracing_state = TRACING;
        }

        update_status(NULL);

        break;
      }
      case STOP: {
        if (tracing_state == TRACING) {
          LOGI("Stop tracing requested");

          tracing_state = STOPPING;
          monitor_stop_reason = "user requested";

          ptrace(PTRACE_INTERRUPT, 1, 0, 0);
          update_status(NULL);
        }

        break;
      }
      case EXIT: {
        LOGI("Prepare for exit ...");

        tracing_state = EXITING;
        monitor_stop_reason = "user requested";

        update_status(NULL);
        monitor_events_stop();

        break;
      }
      case CMD_ZYGOTE_INJECTED: {
        LOGI("Received Zygote%s injected command", MONITOR_ABI);

        status.zygote_injected = true;

        update_status(NULL);

        break;
      }
      case CMD_DAEMON_SET_INFO: {
        LOGD("Received VexZygiskd%s info", MONITOR_ABI);

        uint32_t root_impl_len;
        if (read_uint32_t(monitor_sock_fd, &root_impl_len) != sizeof(root_impl_len)) {
          LOGE("read VexZygiskd%s root impl len", MONITOR_ABI);

          break;
        }

        if (environment_information.root_impl) {
          LOGD("freeing old VexZygiskd%s root impl", MONITOR_ABI);

          free((void *)environment_information.root_impl);
          environment_information.root_impl = NULL;
        }

        environment_information.root_impl = malloc(root_impl_len + 1);
        if (environment_information.root_impl == NULL) {
          PLOGE("malloc VexZygiskd%s root impl", MONITOR_ABI);

          break;
        }

        if (read_loop(monitor_sock_fd, (void *)environment_information.root_impl, root_impl_len) != (ssize_t)root_impl_len) {
          LOGE("read VexZygiskd%s root impl", MONITOR_ABI);

          free((void *)environment_information.root_impl);
          environment_information.root_impl = NULL;

          break;
        }

        environment_information.root_impl[root_impl_len] = '\0';
        LOGD("VexZygiskd%s root impl: %s", MONITOR_ABI, environment_information.root_impl);

        if (read_uint32_t(monitor_sock_fd, &environment_information.modules_len) != sizeof(environment_information.modules_len)) {
          LOGE("read VexZygiskd%s modules len", MONITOR_ABI);

          free((void *)environment_information.root_impl);
          environment_information.root_impl = NULL;

          break;
        }

        if (environment_information.modules) {
          LOGD("freeing old VexZygiskd%s modules", MONITOR_ABI);

          for (size_t i = 0; i < environment_information.modules_len; i++) {
            free((void *)environment_information.modules[i]);

            if (environment_information.modules_targets && environment_information.modules_targets[i]) {
              for (uint32_t t = 0; t < environment_information.modules_targets_len[i]; t++) {
                free(environment_information.modules_targets[i][t]);
              }

              free(environment_information.modules_targets[i]);
            }
          }

          free((void *)environment_information.modules);
          environment_information.modules = NULL;

          free((void *)environment_information.modules_zn);
          environment_information.modules_zn = NULL;

          free((void *)environment_information.modules_companion);
          environment_information.modules_companion = NULL;

          free((void *)environment_information.modules_targets);
          environment_information.modules_targets = NULL;

          free((void *)environment_information.modules_targets_len);
          environment_information.modules_targets_len = NULL;
        }

        environment_information.modules = malloc(environment_information.modules_len * sizeof(char *));
        if (environment_information.modules == NULL) {
          PLOGE("malloc VexZygiskd%s modules", MONITOR_ABI);

          free((void *)environment_information.root_impl);
          environment_information.root_impl = NULL;

          break;
        }

        environment_information.modules_zn = malloc(environment_information.modules_len * sizeof(bool));
        if (environment_information.modules_zn == NULL) {
          PLOGE("malloc VexZygiskd%s modules type", MONITOR_ABI);

          free((void *)environment_information.root_impl);
          environment_information.root_impl = NULL;

          free((void *)environment_information.modules);
          environment_information.modules = NULL;

          break;
        }

        environment_information.modules_companion = malloc(environment_information.modules_len * sizeof(bool));
        if (environment_information.modules_companion == NULL) {
          PLOGE("malloc VexZygiskd%s modules companion", MONITOR_ABI);

          free((void *)environment_information.root_impl);
          environment_information.root_impl = NULL;

          free((void *)environment_information.modules);
          environment_information.modules = NULL;

          free((void *)environment_information.modules_zn);
          environment_information.modules_zn = NULL;

          break;
        }

        environment_information.modules_targets = malloc(environment_information.modules_len * sizeof(char **));
        if (environment_information.modules_targets == NULL) {
          PLOGE("malloc VexZygiskd%s modules targets", MONITOR_ABI);

          free((void *)environment_information.root_impl);
          environment_information.root_impl = NULL;

          free((void *)environment_information.modules);
          environment_information.modules = NULL;

          free((void *)environment_information.modules_zn);
          environment_information.modules_zn = NULL;

          free((void *)environment_information.modules_companion);
          environment_information.modules_companion = NULL;

          break;
        }

        environment_information.modules_targets_len = malloc(environment_information.modules_len * sizeof(uint32_t));
        if (environment_information.modules_targets_len == NULL) {
          PLOGE("malloc VexZygiskd%s modules targets len", MONITOR_ABI);

          free((void *)environment_information.root_impl);
          environment_information.root_impl = NULL;

          free((void *)environment_information.modules);
          environment_information.modules = NULL;

          free((void *)environment_information.modules_zn);
          environment_information.modules_zn = NULL;

          free((void *)environment_information.modules_companion);
          environment_information.modules_companion = NULL;

          free((void *)environment_information.modules_targets);
          environment_information.modules_targets = NULL;

          break;
        }

        for (size_t i = 0; i < environment_information.modules_len; i++) {
          /* INFO: Kept null so the cleanup below can free the entry unconditionally */
          environment_information.modules[i] = NULL;

          uint32_t module_name_len;
          if (read_uint32_t(monitor_sock_fd, &module_name_len) != sizeof(module_name_len)) {
            LOGE("read VexZygiskd%s module name len", MONITOR_ABI);

            goto set_info_modules_cleanup;
          }

          environment_information.modules[i] = malloc(module_name_len + 1);
          if (environment_information.modules[i] == NULL) {
            PLOGE("malloc VexZygiskd%s module name", MONITOR_ABI);

            goto set_info_modules_cleanup;
          }

          if (read_loop(monitor_sock_fd, (void *)environment_information.modules[i], module_name_len) != (ssize_t)module_name_len) {
            LOGE("read VexZygiskd%s module name", MONITOR_ABI);

            free((void *)environment_information.modules[i]);
            environment_information.modules[i] = NULL;

            goto set_info_modules_cleanup;
          }

          environment_information.modules[i][module_name_len] = '\0';

          uint8_t module_type;
          if (read_uint8_t(monitor_sock_fd, &module_type) != sizeof(module_type)) {
            LOGE("read VexZygiskd%s module type", MONITOR_ABI);

            free((void *)environment_information.modules[i]);
            environment_information.modules[i] = NULL;

            goto set_info_modules_cleanup;
          }

          environment_information.modules_zn[i] = module_type == 1;
          environment_information.modules_companion[i] = false;
          environment_information.modules_targets[i] = NULL;
          environment_information.modules_targets_len[i] = 0;

          if (module_type == 1) {
            uint8_t companion;
            if (read_uint8_t(monitor_sock_fd, &companion) != sizeof(companion)) {
              LOGE("read VexZygiskd%s module companion", MONITOR_ABI);

              free((void *)environment_information.modules[i]);
              environment_information.modules[i] = NULL;

              goto set_info_modules_cleanup;
            }
            environment_information.modules_companion[i] = companion == 1;

            uint32_t targets_len;
            if (read_uint32_t(monitor_sock_fd, &targets_len) != sizeof(targets_len)) {
              LOGE("read VexZygiskd%s module targets len", MONITOR_ABI);

              free((void *)environment_information.modules[i]);
              environment_information.modules[i] = NULL;

              goto set_info_modules_cleanup;
            }
            environment_information.modules_targets_len[i] = targets_len;

            if (targets_len > 0) {
              environment_information.modules_targets[i] = malloc(targets_len * sizeof(char *));
              if (environment_information.modules_targets[i] == NULL) {
                PLOGE("malloc VexZygiskd%s module targets", MONITOR_ABI);

                free((void *)environment_information.modules[i]);
                environment_information.modules[i] = NULL;

                goto set_info_modules_cleanup;
              }

              for (uint32_t t = 0; t < targets_len; t++) {
                environment_information.modules_targets[i][t] = NULL;

                uint32_t target_len;
                if (read_uint32_t(monitor_sock_fd, &target_len) != sizeof(target_len)) {
                  LOGE("read VexZygiskd%s module target len", MONITOR_ABI);

                  goto set_info_modules_cleanup;
                }

                environment_information.modules_targets[i][t] = malloc(target_len + 1);
                if (environment_information.modules_targets[i][t] == NULL) {
                  PLOGE("malloc VexZygiskd%s module target", MONITOR_ABI);

                  goto set_info_modules_cleanup;
                }

                if (read_loop(monitor_sock_fd, environment_information.modules_targets[i][t], target_len) != (ssize_t)target_len) {
                  LOGE("read VexZygiskd%s module target", MONITOR_ABI);

                  goto set_info_modules_cleanup;
                }

                environment_information.modules_targets[i][t][target_len] = '\0';
              }
            }
          }

          LOGD("VexZygiskd%s module %zu: %s (%s)", MONITOR_ABI, i, environment_information.modules[i], environment_information.modules_zn[i] ? "next" : "zygisk");

          continue;

          set_info_modules_cleanup:
            free((void *)environment_information.root_impl);
            environment_information.root_impl = NULL;

            for (size_t j = 0; j <= i; j++) {
              free((void *)environment_information.modules[j]);

              if (environment_information.modules_targets && environment_information.modules_targets[j]) {
                for (uint32_t t = 0; t < environment_information.modules_targets_len[j]; t++) {
                  free(environment_information.modules_targets[j][t]);
                }

                free(environment_information.modules_targets[j]);
              }
            }

            free((void *)environment_information.modules);
            environment_information.modules = NULL;

            free((void *)environment_information.modules_zn);
            environment_information.modules_zn = NULL;

            free((void *)environment_information.modules_companion);
            environment_information.modules_companion = NULL;

            free((void *)environment_information.modules_targets);
            environment_information.modules_targets = NULL;

            free((void *)environment_information.modules_targets_len);
            environment_information.modules_targets_len = NULL;

            break;
        }

        update_status(NULL);

        break;
      }
      case CMD_DAEMON_SET_ERROR_INFO: {
        LOGD("Received VexZygiskd%s error info", MONITOR_ABI);

        uint32_t error_info_len;
        if (read_uint32_t(monitor_sock_fd, &error_info_len) != sizeof(error_info_len)) {
          LOGE("read VexZygiskd%s error info len", MONITOR_ABI);

          break;
        }

        if (status.daemon_error_info) {
          LOGD("freeing old VexZygiskd%s error info", MONITOR_ABI);

          free(status.daemon_error_info);
          status.daemon_error_info = NULL;
        }

        status.daemon_error_info = malloc(error_info_len + 1);
        if (status.daemon_error_info == NULL) {
          PLOGE("malloc VexZygiskd%s error info", MONITOR_ABI);

          break;
        }

        if (read_loop(monitor_sock_fd, status.daemon_error_info, error_info_len) != (ssize_t)error_info_len) {
          LOGE("read VexZygiskd%s error info", MONITOR_ABI);

          free(status.daemon_error_info);
          status.daemon_error_info = NULL;

          break;
        }

        status.daemon_error_info[error_info_len] = '\0';
        LOGD("VexZygiskd%s error info: %s", MONITOR_ABI, status.daemon_error_info);

        update_status(NULL);

        break;
      }
    }
  }
}

void rezygiskd_listener_stop() {
  if (monitor_sock_fd >= 0) close(monitor_sock_fd);
  monitor_sock_fd = -1;
}

#define MAX_RETRY_COUNT 5

struct timespec last_zygote = {
  .tv_sec = 0,
  .tv_nsec = 0
};

int count_zygote = 0;
static bool should_stop_inject() {
  struct timespec now = {};
  clock_gettime(CLOCK_MONOTONIC, &now);
  if (now.tv_sec - last_zygote.tv_sec < 30)
    count_zygote++;
  else
    count_zygote = 0;

  last_zygote = now;

  return count_zygote >= MAX_RETRY_COUNT;
}

static bool ensure_daemon_created() {
  if (status.daemon_pid != -1) {
    LOGI("VexZygiskd%s already running", MONITOR_ABI);

    return status.daemon_running;
  }

  pid_t pid = fork();
  if (pid < 0) {
    PLOGE("create VexZygiskd%s", MONITOR_ABI);

    return false;
  }

  if (pid == 0) {
    char daemon_name[PATH_MAX] = "./bin/zygiskd";
    strcat(daemon_name, MONITOR_ABI);

    execl(daemon_name, daemon_name, NULL);

    PLOGE("exec VexZygiskd%s failed", MONITOR_ABI);

    exit(1);
  }

  status.supported = true;
  status.daemon_pid = pid;
  status.daemon_running = true;

  return true;
}

#define APP_PROCESS "/system/bin/app_process"
#define APP_PROCESS_64 APP_PROCESS "64"
#define APP_PROCESS_32 APP_PROCESS "32"

int sigchld_signal_fd;
struct signalfd_siginfo sigchld_fdsi;
int sigchld_status;

pid_t *sigchld_process;
size_t sigchld_process_count = 0;

static bool claim_init_tracer() {
  if (ptrace(PTRACE_SEIZE, 1, 0, PTRACE_O_TRACEFORK) == -1) {
    /* INFO: In cases where, for example, 2 VexZygisks were executed, the second
               process won't be able to seize init due to limitations of ptrace.
               In this case, we should just exit the second process to avoid
               conflicts. */
    if (errno == EPERM) {
      LOGW("Another process is already tracing init");

      update_status("❌ Multiple Zygisks functioning");
    } else {
      PLOGE("failed to seize init");
    }

    return false;
  }

  return true;
}

bool sigchld_listener_init() {
  sigchld_process = NULL;

  sigset_t mask;
  sigemptyset(&mask);
  sigaddset(&mask, SIGCHLD);

  if (sigprocmask(SIG_BLOCK, &mask, NULL) == -1) {
    PLOGE("set sigprocmask");

    return false;
  }

  sigchld_signal_fd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
  if (sigchld_signal_fd == -1) {
    PLOGE("create signalfd");

    return false;
  }

  return true;
}

void sigchld_listener_callback() {
  while (1) {
    ssize_t s = read(sigchld_signal_fd, &sigchld_fdsi, sizeof(sigchld_fdsi));
    if (s == -1) {
      if (errno == EAGAIN) break;

      PLOGE("read signalfd");

      continue;
    }

    if (s != sizeof(sigchld_fdsi)) {
      LOGE("read %zu != %zu", s, sizeof(sigchld_fdsi));

      continue;
    }

    if (sigchld_fdsi.ssi_signo != SIGCHLD) {
      LOGE("No sigchld received");

      continue;
    }

    int pid;
    while ((pid = waitpid(-1, &sigchld_status, __WALL | WNOHANG)) != 0) {
      if (pid == -1) {
        if (tracing_state == STOPPED && errno == ECHILD) break;
        PLOGE("waitpid");
      }

      if (pid == 1) {
        if (STOPPED_WITH(SIGTRAP, PTRACE_EVENT_FORK)) {
          long child_pid;

          ptrace(PTRACE_GETEVENTMSG, pid, 0, &child_pid);

          LOGV("Forked %ld", child_pid);
        } else if (STOPPED_WITH(SIGTRAP, PTRACE_EVENT_STOP) && tracing_state == STOPPING) {
          if (ptrace(PTRACE_DETACH, 1, 0, 0) == -1) PLOGE("failed to detach init");

          tracing_state = STOPPED;

          LOGI("Stopped tracing init");

          continue;
        }

        if (WIFSTOPPED(sigchld_status)) {
          if (WPTEVENT(sigchld_status) == 0) {
            if (WSTOPSIG(sigchld_status) != SIGSTOP && WSTOPSIG(sigchld_status) != SIGTSTP && WSTOPSIG(sigchld_status) != SIGTTIN && WSTOPSIG(sigchld_status) != SIGTTOU) {
              LOGW("Injecting signal sent to init: %s %d", sigabbrev_np(WSTOPSIG(sigchld_status)), WSTOPSIG(sigchld_status));

              ptrace(PTRACE_CONT, pid, 0, WSTOPSIG(sigchld_status));

              continue;
            } else {
              LOGW("Suppressing stop signal sent to init: %s %d", sigabbrev_np(WSTOPSIG(sigchld_status)), WSTOPSIG(sigchld_status));
            }
          }

          ptrace(PTRACE_CONT, pid, 0, 0);
        }

        continue;
      }

      if (status.supported && pid == status.daemon_pid) {
        char status_str[64];
        parse_status(sigchld_status, status_str, sizeof(status_str));

        LOGW("daemon%s pid %d exited: %s", MONITOR_ABI, pid, status_str);
        status.daemon_running = false;

        if (!status.daemon_error_info) {
          status.daemon_error_info = strdup(status_str);
          if (!status.daemon_error_info) {
            LOGE("malloc daemon%s error info failed", MONITOR_ABI);

            return;
          }
        }

        continue;
      }

      pid_t state = 0;
      for (size_t i = 0; i < sigchld_process_count; i++) {
        if (sigchld_process[i] != pid) continue;

        state = sigchld_process[i];

        break;
      }

      if (state == 0) {
        LOGV("New process %d attached", pid);

        for (size_t i = 0; i < sigchld_process_count; i++) {
          if (sigchld_process[i] != 0) continue;

          sigchld_process[i] = pid;

          goto ptrace_process;
        }

        pid_t *new_sigchld_process = (pid_t *)realloc(sigchld_process, sizeof(pid_t) * (sigchld_process_count + 1));
        if (new_sigchld_process == NULL) {
          PLOGE("realloc sigchld_process");

          continue;
        }
        sigchld_process = new_sigchld_process;

        sigchld_process[sigchld_process_count] = pid;
        sigchld_process_count++;

        ptrace_process:

        ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACEEXEC);
        ptrace(PTRACE_CONT, pid, 0, 0);

        continue;
      } else {
        if (STOPPED_WITH(SIGTRAP, PTRACE_EVENT_EXEC)) {
          char program[PATH_MAX];
          if (get_program(pid, program, sizeof(program)) == -1) {
            LOGW("failed to get program %d", pid);

            continue;
          }

          LOGV("%d program %s", pid, program);

          const char *tracer = NULL;
          bool is_tango = false;

          do {
            if (tracing_state != TRACING) {
              LOGD("Stopped injecting %d because status is not set to tracing", pid);

              break;
            }

            if (strcmp(program, APP_PROCESS_NAME) == 0) {
              tracer = "./bin/zygisk-ptrace" MONITOR_ABI;
              is_tango = false;

              if (should_stop_inject()) {
                LOGW("Zygote%s restart too much times, stop injecting", MONITOR_ABI);

                tracing_state = STOPPING;
                monitor_stop_reason = "Zygote crashed";
                ptrace(PTRACE_INTERRUPT, 1, 0, 0);

                break;
              }

              if (!ensure_daemon_created()) {
                LOGW("VexZygiskd%s not running, stop injecting", MONITOR_ABI);

                tracing_state = STOPPING;
                monitor_stop_reason = "VexZygiskd not running";
                ptrace(PTRACE_INTERRUPT, 1, 0, 0);

                break;
              }
            }
#ifdef __LP64__
            else if (strcmp(program, APP_PROCESS_32) == 0) {
              LOGD("Skipping 32-bit Zygote %d", pid);
            }
#else
            else if (strcmp(program, "/system_ext/bin/tango_translator") == 0) {
              tracer = "./bin/zygisk-ptrace" MONITOR_ABI;
              is_tango = true;

              if (should_stop_inject()) {
                LOGW("Tango restart too many times, stop injecting");

                tracing_state = STOPPING;
                monitor_stop_reason = "Zygote crashed";
                ptrace(PTRACE_INTERRUPT, 1, 0, 0);

                break;
              }

              if (!ensure_daemon_created()) {
                LOGW("VexZygiskd%s not running, stop injecting", MONITOR_ABI);

                tracing_state = STOPPING;
                monitor_stop_reason = "VexZygiskd not running";
                ptrace(PTRACE_INTERRUPT, 1, 0, 0);

                break;
              }
            }
#endif

            if (tracer != NULL) {
              LOGD("Stopping %d (program: %s, tracer: %s, tango: %s)", pid, program, tracer, is_tango ? "yes" : "no");

              kill(pid, SIGSTOP);
              ptrace(PTRACE_CONT, pid, 0, 0);
              waitpid(pid, &sigchld_status, __WALL);

              if (!STOPPED_WITH(SIGSTOP, 0)) {
                LOGE("Failed to stop process %d", pid);

                break;
              }

              LOGD("Detaching %d", pid);
              ptrace(PTRACE_DETACH, pid, 0, SIGSTOP);

              {
                sigchld_status = 0;
                int p = fork_dont_care();

                if (p == 0) {
                  char pid_str[32];
                  sprintf(pid_str, "%d", pid);

                  LOGI("exec tracer command: %s trace %s --restart%s", tracer, pid_str, is_tango ? " --tango" : "");

                  /* INFO: Only restart companions if it's not the first time */
                  if (count_zygote > 1) {
                    if (is_tango) {
                      execl(tracer, basename(tracer), "trace", pid_str, "--restart", "--tango", NULL);
                    } else {
                      execl(tracer, basename(tracer), "trace", pid_str, "--restart", NULL);
                    }
                  } else {
                    if (is_tango) {
                      execl(tracer, basename(tracer), "trace", pid_str, "--tango", NULL);
                    } else {
                      execl(tracer, basename(tracer), "trace", pid_str, NULL);
                    }
                  }

                  PLOGE("exec");

                  kill(pid, SIGKILL);
                  exit(1);
                } else if (p == -1) {
                  PLOGE("fork");

                  kill(pid, SIGKILL);
                }
              }
            }
          } while (false);
        } else {
          char status_str[64];
          parse_status(sigchld_status, status_str, sizeof(status_str));

          LOGW("process %d received unknown sigchld_status %s", pid, status_str);
        }

        for (size_t i = 0; i < sigchld_process_count; i++) {
          if (sigchld_process[i] != pid) continue;

          sigchld_process[i] = 0;

          break;
        }

        if (WIFSTOPPED(sigchld_status)) {
          LOGV("detach process %d", pid);

          ptrace(PTRACE_DETACH, pid, 0, 0);
        }
      }
    }
  }
}

void sigchld_listener_stop() {
  if (sigchld_signal_fd >= 0) close(sigchld_signal_fd);
  sigchld_signal_fd = -1;

  if (sigchld_process != NULL) free(sigchld_process);
  sigchld_process = NULL;
  sigchld_process_count = 0;
}

static char pre_section[1024];
static char post_section[1024];

static bool update_status(const char *message) {
  FILE *prop = fopen("/data/adb/modules/rezygisk/module.prop", "w");
  if (prop == NULL) {
    PLOGE("failed to open prop");

    return false;
  }

  if (message) {
    fprintf(prop, "%s[%s] %s", pre_section, message, post_section);
    fclose(prop);

    return true;
  }

  char status_text[256] = "Monitor: ";
  switch (tracing_state) {
    case TRACING: {
      strcat(status_text, "✅");

      break;
    }
    case STOPPING: [[fallthrough]];
    case STOPPED: {
      strcat(status_text, "⛔");

      break;
    }
    case EXITING: {
      strcat(status_text, "❌");

      break;
    }
  }

  if (status.supported) {
    strcat(status_text, ", VexZygisk ");
    strcat(status_text, MONITOR_ABI);
    strcat(status_text, "-bit: ");

    if (tracing_state != TRACING) strcat(status_text, "❌");
    else if (status.zygote_injected && status.daemon_running) strcat(status_text, "✅");
    else strcat(status_text, "⚠️");

    if (!status.daemon_running) {
      if (status.daemon_error_info) {
        strcat(status_text, "(VexZygiskd: ");
        strcat(status_text, status.daemon_error_info);
        strcat(status_text, ")");
      } else {
        strcat(status_text, "(VexZygiskd: not running)");
      }
    }
  }

  fprintf(prop, "%s[%s] %s", pre_section, status_text, post_section);
  fclose(prop);

  if (environment_information.root_impl) {
    FILE *json = fopen("/data/adb/rezygisk/state.json", "w");
    if (json == NULL) {
      PLOGE("failed to open state.json");

      return false;
    }

    fprintf(json, "{\n");
    fprintf(json, "  \"root\": \"%s\",\n", environment_information.root_impl);

    fprintf(json, "  \"monitor\": {\n");
    fprintf(json, "    \"state\": \"%d\"", tracing_state);
    if (monitor_stop_reason) fprintf(json, ",\n    \"reason\": \"%s\",\n", monitor_stop_reason);
    else fprintf(json, "\n");

    if (status.supported) fprintf(json, "  },\n");
    else fprintf(json, "  }\n");

    if (status.supported) {
      fprintf(json, "  \"rezygiskd\": {\n");
      fprintf(json, "    \"%s\": {\n", MONITOR_ABI);
      fprintf(json, "      \"state\": %d,\n", status.daemon_running);
      if (status.daemon_error_info) fprintf(json, "      \"reason\": \"%s\",\n", status.daemon_error_info);
      fprintf(json, "      \"modules\": [");

      if (environment_information.modules) for (uint32_t i = 0; i < environment_information.modules_len; i++) {
        if (i > 0) fprintf(json, ", ");
        fprintf(json, "{\"id\": \"%s\", \"next\": %s, \"companion\": %s",
                environment_information.modules[i],
                environment_information.modules_zn[i] ? "true" : "false",
                environment_information.modules_companion[i] ? "true" : "false");

        if (environment_information.modules_targets && environment_information.modules_targets[i]) {
          fprintf(json, ", \"targets\": [");
          for (uint32_t t = 0; t < environment_information.modules_targets_len[i]; t++) {
            if (t > 0) fprintf(json, ", ");
            fprintf(json, "\"%s\"", environment_information.modules_targets[i][t]);
          }
          fprintf(json, "]");
        }

        fprintf(json, "}");
      }

      fprintf(json, "]\n");
      fprintf(json, "    }\n");
      fprintf(json, "  },\n");

      fprintf(json, "  \"zygote\": {\n");
      fprintf(json, "    \"%s\": %d\n", MONITOR_ABI, status.zygote_injected);
      fprintf(json, "  }\n");
    }

    fprintf(json, "}\n");

    fclose(json);
  } else {
    if (remove("/data/adb/rezygisk/state.json") == -1) {
      PLOGE("failed to remove state.json");
    }
  }

  LOGI("status updated: %s", status_text);

  return true;
}

static bool prepare_environment() {
  FILE *orig_prop = fopen("/data/adb/modules/rezygisk/module.prop", "r");
  if (orig_prop == NULL) {
    PLOGE("failed to open orig prop");

    return false;
  }

  bool after_description = false;

  char line[1024];
  while (fgets(line, sizeof(line), orig_prop) != NULL) {
    if (strncmp(line, "description=", strlen("description=")) == 0) {
      strcat(pre_section, "description=");
      strcat(post_section, line + strlen("description="));
      after_description = true;

      continue;
    }

    if (after_description) strcat(post_section, line);
    else strcat(pre_section, line);
  }

  fclose(orig_prop);

  return true;
}

void init_monitor() {
  LOGI("VexZygisk %s", ZKSU_VERSION);

  if (!prepare_environment()) exit(1);

  if (!claim_init_tracer()) exit(1);

  monitor_events_init();

  if (!rezygiskd_listener_init()) {
    LOGE("failed to create socket");

    close(monitor_epoll_fd);

    exit(1);
  }

  monitor_events_register_event(rezygiskd_listener_callback, monitor_sock_fd, EPOLLIN | EPOLLET);

  if (sigchld_listener_init() == false) {
    LOGE("failed to create signalfd");

    rezygiskd_listener_stop();
    close(monitor_epoll_fd);

    exit(1);
  }

  monitor_events_register_event(sigchld_listener_callback, sigchld_signal_fd, EPOLLIN | EPOLLET);

  monitor_events_loop();

  /* INFO: Once it stops the loop, we cannot access the epool data, so we
             either manually call the stops or save to a structure. */
  rezygiskd_listener_stop();
  sigchld_listener_stop();

  if (status.daemon_error_info) free(status.daemon_error_info);

  if (environment_information.root_impl) free((void *)environment_information.root_impl);
  if (environment_information.modules) {
    for (uint32_t i = 0; i < environment_information.modules_len; i++) {
      free((void *)environment_information.modules[i]);

      if (environment_information.modules_targets && environment_information.modules_targets[i]) {
        for (uint32_t t = 0; t < environment_information.modules_targets_len[i]; t++) {
          free(environment_information.modules_targets[i][t]);
        }

        free(environment_information.modules_targets[i]);
      }
    }
    free((void *)environment_information.modules);
    free((void *)environment_information.modules_zn);
    free((void *)environment_information.modules_companion);
    free((void *)environment_information.modules_targets);
    free((void *)environment_information.modules_targets_len);
  }

  LOGI("Terminating VexZygisk monitor");
}

int send_control_command(enum rezygiskd_command cmd) {
  int sockfd = socket(PF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (sockfd == -1) return -1;

  struct sockaddr_un addr = {
    .sun_family = AF_UNIX,
    .sun_path = { 0 }
  };

  size_t sun_path_len = snprintf(addr.sun_path, sizeof(addr.sun_path), "%s/%s", rezygiskd_get_path(), SOCKET_NAME);

  socklen_t socklen = sizeof(sa_family_t) + sun_path_len;

  uint8_t cmd_op = cmd;
  ssize_t nsend = sendto(sockfd, (void *)&cmd_op, sizeof(cmd_op), 0, (struct sockaddr *)&addr, socklen);

  close(sockfd);

  return nsend != sizeof(cmd_op) ? -1 : 0;
}
