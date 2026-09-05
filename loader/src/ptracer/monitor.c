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

#ifdef __LP64__
  #define MONITOR_ABI "64"
  #define APP_PROCESS_NAME "/system/bin/app_process64"
  #define OTHER_ZYGOTE_NAME "/system/bin/app_process32"
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

static const char *monitor_stop_reason = NULL;

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

/* INFO: Releases every module list of the environment. Safe on a zeroed or
         partially filled state: the arrays are kept calloc'ed, so slots that
         were never filled read as NULL. */
static void free_environment_information(void) {
  if (environment_information.modules != NULL) {
    for (uint32_t i = 0; i < environment_information.modules_len; i++) {
      free(environment_information.modules[i]);

      if (environment_information.modules_targets != NULL && environment_information.modules_targets[i] != NULL) {
        for (uint32_t t = 0; t < environment_information.modules_targets_len[i]; t++)
          free(environment_information.modules_targets[i][t]);

        free(environment_information.modules_targets[i]);
      }
    }
  }

  free(environment_information.modules);
  free(environment_information.modules_zn);
  free(environment_information.modules_companion);
  free(environment_information.modules_targets);
  free(environment_information.modules_targets_len);

  environment_information.modules = NULL;
  environment_information.modules_zn = NULL;
  environment_information.modules_companion = NULL;
  environment_information.modules_targets = NULL;
  environment_information.modules_targets_len = NULL;
}

enum ptracer_tracing_state {
  TRACING,
  STOPPING,
  STOPPED,
  EXITING
};

static enum ptracer_tracing_state tracing_state = TRACING;

struct rezygiskd_status {
  bool supported;
  bool zygote_injected;
  bool daemon_running;
  pid_t daemon_pid;
  char *daemon_error_info;
};

static struct rezygiskd_status status = {
  .supported = false,
  .zygote_injected = false,
  .daemon_running = false,
  .daemon_pid = -1,
  .daemon_error_info = NULL
};

static int monitor_epoll_fd;
static bool monitor_events_running = true;
typedef void (*monitor_event_callback_t)(void);

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
        LOGE("Failed event (mask %u)", events[i].events);

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

static int monitor_sock_fd;

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

  int sun_path_len = snprintf(addr.sun_path, sizeof(addr.sun_path), "%s/%s", rezygiskd_get_path(), SOCKET_NAME);
  if (sun_path_len < 0 || (size_t)sun_path_len >= sizeof(addr.sun_path)) {
    LOGE("The monitor socket path does not fit into sockaddr_un");

    close(monitor_sock_fd);
    monitor_sock_fd = -1;

    return false;
  }

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

          free(environment_information.root_impl);
          environment_information.root_impl = NULL;
        }

        environment_information.root_impl = malloc(root_impl_len + 1);
        if (environment_information.root_impl == NULL) {
          PLOGE("malloc VexZygiskd%s root impl", MONITOR_ABI);

          break;
        }

        if (read_loop(monitor_sock_fd, environment_information.root_impl, root_impl_len) != (ssize_t)root_impl_len) {
          LOGE("read VexZygiskd%s root impl", MONITOR_ABI);

          free(environment_information.root_impl);
          environment_information.root_impl = NULL;

          break;
        }

        environment_information.root_impl[root_impl_len] = '\0';
        LOGD("VexZygiskd%s root impl: %s", MONITOR_ABI, environment_information.root_impl);

        /* INFO: Read into a local first: the old lists are freed through the
                  length they were allocated with, so the stored length must
                  not be overwritten before that. */
        uint32_t modules_len;
        if (read_uint32_t(monitor_sock_fd, &modules_len) != sizeof(modules_len)) {
          LOGE("read VexZygiskd%s modules len", MONITOR_ABI);

          free(environment_information.root_impl);
          environment_information.root_impl = NULL;

          break;
        }

        free_environment_information();

        environment_information.modules_len = modules_len;

        environment_information.modules = calloc(modules_len, sizeof(char *));
        environment_information.modules_zn = calloc(modules_len, sizeof(bool));
        environment_information.modules_companion = calloc(modules_len, sizeof(bool));
        environment_information.modules_targets = calloc(modules_len, sizeof(char **));
        environment_information.modules_targets_len = calloc(modules_len, sizeof(uint32_t));

        if (environment_information.modules == NULL || environment_information.modules_zn == NULL ||
            environment_information.modules_companion == NULL || environment_information.modules_targets == NULL ||
            environment_information.modules_targets_len == NULL) {
          PLOGE("malloc VexZygiskd%s module lists", MONITOR_ABI);

          free(environment_information.root_impl);
          environment_information.root_impl = NULL;

          free_environment_information();

          break;
        }

        for (size_t i = 0; i < environment_information.modules_len; i++) {
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

          if (read_loop(monitor_sock_fd, environment_information.modules[i], module_name_len) != (ssize_t)module_name_len) {
            LOGE("read VexZygiskd%s module name", MONITOR_ABI);

            goto set_info_modules_cleanup;
          }

          environment_information.modules[i][module_name_len] = '\0';

          uint8_t module_type;
          if (read_uint8_t(monitor_sock_fd, &module_type) != sizeof(module_type)) {
            LOGE("read VexZygiskd%s module type", MONITOR_ABI);

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

              goto set_info_modules_cleanup;
            }
            environment_information.modules_companion[i] = companion == 1;

            uint32_t targets_len;
            if (read_uint32_t(monitor_sock_fd, &targets_len) != sizeof(targets_len)) {
              LOGE("read VexZygiskd%s module targets len", MONITOR_ABI);

              goto set_info_modules_cleanup;
            }
            environment_information.modules_targets_len[i] = targets_len;

            if (targets_len > 0) {
              environment_information.modules_targets[i] = calloc(targets_len, sizeof(char *));
              if (environment_information.modules_targets[i] == NULL) {
                PLOGE("malloc VexZygiskd%s module targets", MONITOR_ABI);

                goto set_info_modules_cleanup;
              }

              for (uint32_t t = 0; t < targets_len; t++) {
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
        }

        update_status(NULL);

        break;

        /* INFO: Reached from any failed read above. Every slot was calloc'ed,
                  so free_environment_information can walk the full lists. */
        set_info_modules_cleanup:
          free(environment_information.root_impl);
          environment_information.root_impl = NULL;

          free_environment_information();

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

static struct timespec last_zygote = {
  .tv_sec = 0,
  .tv_nsec = 0
};

static int count_zygote = 0;
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
    char daemon_name[] = "./bin/zygiskd" MONITOR_ABI;

    execl(daemon_name, daemon_name, NULL);

    PLOGE("exec VexZygiskd%s failed", MONITOR_ABI);

    exit(1);
  }

  status.supported = true;
  status.daemon_pid = pid;
  status.daemon_running = true;

  return true;
}

static int sigchld_signal_fd;
static struct signalfd_siginfo sigchld_fdsi;
static int sigchld_status;

static pid_t *sigchld_process;
static size_t sigchld_process_count = 0;

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
        /* INFO: EINTR is retried by the loop; ECHILD simply means every child
                  is reaped. Any other error is logged once and drained here,
                  otherwise pid -1 would flow into the handling below forever. */
        if (errno == EINTR) continue;

        if (errno != ECHILD) PLOGE("waitpid");

        break;
      }

      if (pid == 1) {
        if (STOPPED_WITH(sigchld_status, SIGTRAP, PTRACE_EVENT_FORK)) {
          long child_pid;

          ptrace(PTRACE_GETEVENTMSG, pid, 0, &child_pid);

          LOGV("Forked %ld", child_pid);
        } else if (STOPPED_WITH(sigchld_status, SIGTRAP, PTRACE_EVENT_STOP) && tracing_state == STOPPING) {
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

        /* INFO: Resetting the pid lets ensure_daemon_created fork a fresh
                  daemon at the next zygote start instead of reporting "already
                  running" forever; without it a single daemon crash disabled
                  injection until reboot. */
        status.daemon_pid = -1;

        if (!status.daemon_error_info) {
          status.daemon_error_info = strdup(status_str);
          if (!status.daemon_error_info) {
            LOGE("malloc daemon%s error info failed", MONITOR_ABI);

            return;
          }
        }

        continue;
      }

      bool known = false;
      for (size_t i = 0; i < sigchld_process_count; i++) {
        if (sigchld_process[i] == pid) {
          known = true;

          break;
        }
      }

      if (!known) {
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
        if (STOPPED_WITH(sigchld_status, SIGTRAP, PTRACE_EVENT_EXEC)) {
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
            }
#ifdef __LP64__
            else if (strcmp(program, OTHER_ZYGOTE_NAME) == 0) {
              /* INFO: The 64-bit monitor owns only the primary Zygote; the
                        secondary one is left for a 32-bit monitor, if any. */
              LOGD("Skipping 32-bit Zygote %d", pid);
            }
#else
            else if (strcmp(program, "/system_ext/bin/tango_translator") == 0) {
              tracer = "./bin/zygisk-ptrace" MONITOR_ABI;
              is_tango = true;
            }
#endif

            if (tracer == NULL) break;

            if (should_stop_inject()) {
              LOGW("%s restart too many times, stop injecting", is_tango ? "Tango" : "Zygote" MONITOR_ABI);

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

            LOGD("Stopping %d (program: %s, tracer: %s, tango: %s)", pid, program, tracer, is_tango ? "yes" : "no");

            kill(pid, SIGSTOP);
            ptrace(PTRACE_CONT, pid, 0, 0);
            if (waitpid(pid, &sigchld_status, __WALL) == -1) {
              PLOGE("waitpid");

              break;
            }

            if (!STOPPED_WITH(sigchld_status, SIGSTOP, 0)) {
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
                snprintf(pid_str, sizeof(pid_str), "%d", pid);

                LOGI("exec tracer command: %s trace %s --restart%s", tracer, pid_str, is_tango ? " --tango" : "");

                const char *tracer_name = position_after(tracer, '/');

                /* INFO: Only restart companions if it's not the first time */
                char *exec_argv[6];
                int exec_argc = 0;
                exec_argv[exec_argc++] = (char *)tracer_name;
                exec_argv[exec_argc++] = "trace";
                exec_argv[exec_argc++] = pid_str;
                if (count_zygote > 1) exec_argv[exec_argc++] = "--restart";
                if (is_tango) exec_argv[exec_argc++] = "--tango";
                exec_argv[exec_argc] = NULL;

                execv(tracer, exec_argv);

                PLOGE("exec");

                kill(pid, SIGKILL);
                exit(1);
              } else if (p == -1) {
                PLOGE("fork");

                kill(pid, SIGKILL);
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
static char module_text[2048];

/* INFO: A module that ships both a Zygisk library and a zn_modules.txt lands in
         both the plain and the Zygisk Next lists, so check for a Next twin
         before listing the plain copy. */
static bool has_zn_twin(const char *name) {
  if (environment_information.modules_zn == NULL) return false;

  for (uint32_t j = 0; j < environment_information.modules_len; j++) {
    if (environment_information.modules_zn[j] &&
        environment_information.modules[j] != NULL &&
        strcmp(environment_information.modules[j], name) == 0) return true;
  }

  return false;
}

/* INFO: Folds the detected Zygisk modules into the module description so the
         manager shows them right on the module card, Mountify-style. */
static void build_module_text(void) {
  module_text[0] = '\0';

  if (environment_information.modules == NULL || environment_information.modules_len == 0) return;

  size_t off = snprintf(module_text, sizeof(module_text), "Modules: ");
  bool first = true;

  for (uint32_t i = 0; i < environment_information.modules_len && off < sizeof(module_text); i++) {
    const char *name = environment_information.modules[i];
    if (name == NULL) continue;

    bool is_next = environment_information.modules_zn && environment_information.modules_zn[i];

    if (!is_next && has_zn_twin(name)) continue;

    if (!first) off += snprintf(module_text + off, sizeof(module_text) - off, ", ");
    first = false;

    off += snprintf(module_text + off, sizeof(module_text) - off, "%s%s", name, is_next ? " (Next)" : "");
  }

  /* INFO: snprintf reports what it would have written, so off can point past
            the buffer after a truncated append; clamp before the final one. */
  if (off > sizeof(module_text) - 2) off = sizeof(module_text) - 2;

  snprintf(module_text + off, sizeof(module_text) - off, " · ");
}

/* INFO: JSON string writer used by the state file below; quotes, backslashes
         and control characters would otherwise produce invalid JSON. Writes
         at most cap - 1 bytes plus the terminator. */
static void json_escape_into(char *dst, size_t cap, const char *src) {
  size_t off = 0;

  for (const unsigned char *cursor = (const unsigned char *)src; *cursor != '\0' && off + 1 < cap; cursor++) {
    unsigned char c = *cursor;
    const char *escape = NULL;
    char short_escape[3] = { 0 };

    switch (c) {
      case '"': escape = "\\\""; break;
      case '\\': escape = "\\\\"; break;
      case '\n': escape = "\\n"; break;
      case '\r': escape = "\\r"; break;
      case '\t': escape = "\\t"; break;
      default: {
        if (c < 0x20) {
          snprintf(short_escape, sizeof(short_escape), "\\u%04x", (unsigned)c);
          escape = short_escape;
        }

        break;
      }
    }

    if (escape != NULL) {
      size_t escape_len = strlen(escape);
      if (off + escape_len >= cap) break;

      memcpy(dst + off, escape, escape_len);
      off += escape_len;

      continue;
    }

    dst[off++] = (char)c;
  }

  dst[off] = '\0';
}

static bool update_status(const char *message) {
  build_module_text();

  FILE *prop = fopen("/data/adb/modules/rezygisk/module.prop", "w");
  if (prop == NULL) {
    PLOGE("failed to open prop");

    return false;
  }

  if (message) {
    fprintf(prop, "%s[%s] %s%s", pre_section, message, module_text, post_section);
    fclose(prop);

    return true;
  }

  /* INFO: Appends bounded to the destination: the daemon error text is read
            off the socket and may be longer than the status line can hold. */
  #define STATUS_APPEND(text) strncat(status_text, (text), sizeof(status_text) - strlen(status_text) - 1)

  char status_text[256] = "Monitor: ";
  switch (tracing_state) {
    case TRACING: {
      STATUS_APPEND("✅");

      break;
    }
    case STOPPING: [[fallthrough]];
    case STOPPED: {
      STATUS_APPEND("⛔");

      break;
    }
    case EXITING: {
      STATUS_APPEND("❌");

      break;
    }
  }

  if (status.supported) {
    STATUS_APPEND(", VexZygisk ");
    STATUS_APPEND(MONITOR_ABI);
    STATUS_APPEND("-bit: ");

    if (tracing_state != TRACING) STATUS_APPEND("❌");
    else if (status.zygote_injected && status.daemon_running) STATUS_APPEND("✅");
    else STATUS_APPEND("⚠️");

    if (!status.daemon_running) {
      if (status.daemon_error_info) {
        STATUS_APPEND("(VexZygiskd: ");
        STATUS_APPEND(status.daemon_error_info);
        STATUS_APPEND(")");
      } else {
        STATUS_APPEND("(VexZygiskd: not running)");
      }
    }
  }

  #undef STATUS_APPEND

  fprintf(prop, "%s[%s] %s%s", pre_section, status_text, module_text, post_section);
  fclose(prop);

  if (environment_information.root_impl) {
    FILE *json = fopen("/data/adb/rezygisk/state.json", "w");
    if (json == NULL) {
      PLOGE("failed to open state.json");

      return false;
    }

    char root_impl_json[256];
    json_escape_into(root_impl_json, sizeof(root_impl_json), environment_information.root_impl);

    fprintf(json, "{\n");
    fprintf(json, "  \"root\": \"%s\",\n", root_impl_json);

    fprintf(json, "  \"monitor\": {\n");
    fprintf(json, "    \"state\": %d", tracing_state);

    if (monitor_stop_reason) {
      char reason_json[256];
      json_escape_into(reason_json, sizeof(reason_json), monitor_stop_reason);

      fprintf(json, ",\n    \"reason\": \"%s\"\n", reason_json);
    } else fprintf(json, "\n");

    if (status.supported) fprintf(json, "  },\n");
    else fprintf(json, "  }\n");

    if (status.supported) {
      char reason_json[256];
      if (status.daemon_error_info) json_escape_into(reason_json, sizeof(reason_json), status.daemon_error_info);

      fprintf(json, "  \"rezygiskd\": {\n");
      fprintf(json, "    \"%s\": {\n", MONITOR_ABI);
      fprintf(json, "      \"state\": %d,\n", status.daemon_running);
      if (status.daemon_error_info) fprintf(json, "      \"reason\": \"%s\",\n", reason_json);
      fprintf(json, "      \"modules\": [");

      if (environment_information.modules) for (uint32_t i = 0; i < environment_information.modules_len; i++) {
        if (i > 0) fprintf(json, ", ");

        char module_json[256];
        json_escape_into(module_json, sizeof(module_json), environment_information.modules[i] ? environment_information.modules[i] : "");

        fprintf(json, "{\"id\": \"%s\", \"next\": %s, \"companion\": %s",
                module_json,
                environment_information.modules_zn[i] ? "true" : "false",
                environment_information.modules_companion[i] ? "true" : "false");

        if (environment_information.modules_targets && environment_information.modules_targets[i]) {
          fprintf(json, ", \"targets\": [");
          for (uint32_t t = 0; t < environment_information.modules_targets_len[i]; t++) {
            if (t > 0) fprintf(json, ", ");

            char target_json[256];
            json_escape_into(target_json, sizeof(target_json), environment_information.modules_targets[i][t] ? environment_information.modules_targets[i][t] : "");

            fprintf(json, "\"%s\"", target_json);
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
    /* INFO: strncat keeps every append inside the buffers even if a module.prop
              carries lines longer than expected. */
    if (strncmp(line, "description=", strlen("description=")) == 0) {
      strncat(pre_section, "description=", sizeof(pre_section) - strlen(pre_section) - 1);
      strncat(post_section, line + strlen("description="), sizeof(post_section) - strlen(post_section) - 1);
      after_description = true;

      continue;
    }

    if (after_description) strncat(post_section, line, sizeof(post_section) - strlen(post_section) - 1);
    else strncat(pre_section, line, sizeof(pre_section) - strlen(pre_section) - 1);
  }

  fclose(orig_prop);

  return true;
}

void init_monitor() {
  LOGI("VexZygisk %s", ZKSU_VERSION);

  if (!prepare_environment()) exit(1);

  if (!claim_init_tracer()) exit(1);

  if (!monitor_events_init()) exit(1);

  if (!rezygiskd_listener_init()) {
    LOGE("failed to create socket");

    close(monitor_epoll_fd);

    exit(1);
  }

  if (!monitor_events_register_event(rezygiskd_listener_callback, monitor_sock_fd, EPOLLIN | EPOLLET)) {
    rezygiskd_listener_stop();
    close(monitor_epoll_fd);

    exit(1);
  }

  if (!sigchld_listener_init()) {
    LOGE("failed to create signalfd");

    rezygiskd_listener_stop();
    close(monitor_epoll_fd);

    exit(1);
  }

  if (!monitor_events_register_event(sigchld_listener_callback, sigchld_signal_fd, EPOLLIN | EPOLLET)) {
    sigchld_listener_stop();
    rezygiskd_listener_stop();
    close(monitor_epoll_fd);

    exit(1);
  }

  monitor_events_loop();

  /* INFO: Once it stops the loop, we cannot access the epoll data, so we
             either manually call the stops or save to a structure. */
  rezygiskd_listener_stop();
  sigchld_listener_stop();

  if (status.daemon_error_info) free(status.daemon_error_info);

  if (environment_information.root_impl) free(environment_information.root_impl);
  free_environment_information();

  LOGI("Terminating VexZygisk monitor");
}

int send_control_command(enum rezygiskd_command cmd) {
  int sockfd = socket(PF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (sockfd == -1) return -1;

  struct sockaddr_un addr = {
    .sun_family = AF_UNIX,
    .sun_path = { 0 }
  };

  int sun_path_len = snprintf(addr.sun_path, sizeof(addr.sun_path), "%s/%s", rezygiskd_get_path(), SOCKET_NAME);
  if (sun_path_len < 0 || (size_t)sun_path_len >= sizeof(addr.sun_path)) {
    close(sockfd);

    return -1;
  }

  socklen_t socklen = sizeof(sa_family_t) + (size_t)sun_path_len;

  uint8_t cmd_op = cmd;
  ssize_t nsend = sendto(sockfd, (void *)&cmd_op, sizeof(cmd_op), 0, (struct sockaddr *)&addr, socklen);

  close(sockfd);

  return nsend != sizeof(cmd_op) ? -1 : 0;
}
