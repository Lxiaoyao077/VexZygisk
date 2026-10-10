#include <stdlib.h>
#include <stdio.h>
#include <dirent.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <signal.h>

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

#define MONITOR_ABI "64"
#define APP_PROCESS_NAME "/system/bin/app_process64"
#define CMD_ZYGOTE_INJECTED ZYGOTE64_INJECTED
#define CMD_DAEMON_SET_INFO DAEMON64_SET_INFO
#define CMD_DAEMON_SET_ERROR_INFO DAEMON64_SET_ERROR_INFO

/* INFO: HyperOS's app spawner, the third process (besides the two zygotes)
         that forks application processes. Both ABI monitors match it, each
         injecting its own bitness into its own bitness spawner.

         Matched by file name rather than by one fixed path: HyperOS has shipped
         the binary from more than one directory across releases, so whichever
         directory the running build uses has to be followed. */
#define HYOS_SPAWNER_BASE_NAME "hyos_spawner"

static bool update_status(const char *message);

static const char *monitor_stop_reason = NULL;

/* INFO: One module as the daemon reported it. A record rather than the five
         arrays this used to be: the name, whether it is a Zygisk Next module,
         whether it wants a companion and the targets it asked for only mean
         anything next to each other, and keeping them apart cost five
         allocations that had to succeed together and five indices that had to
         agree. */
struct daemon_module {
  char *name;
  bool is_zn;
  bool companion;
  char **targets;
  uint32_t targets_len;
};

struct environment_information {
  char *root_impl;
  struct daemon_module *modules;
  uint32_t modules_len;
  /* INFO: How many of those are Zygisk Next modules. The listing asks whether
             a plain module has a Next twin, and that question is decided by a
             scan of the whole list - but when not one module is a Next module
             the answer is no without looking, which is the usual machine. */
  uint32_t zn_len;
};

static struct environment_information environment_information;

/* INFO: Releases every module of the environment. Safe on a zeroed or partially
         filled state: the array is kept calloc'ed, so a slot that was never
         filled reads as an empty record. */
static void free_environment_information(void) {
  if (environment_information.modules != NULL) {
    for (uint32_t i = 0; i < environment_information.modules_len; i++) {
      struct daemon_module *module = &environment_information.modules[i];

      free(module->name);

      if (module->targets != NULL) {
        for (uint32_t t = 0; t < module->targets_len; t++) free(module->targets[t]);

        free(module->targets);
      }
    }
  }

  free(environment_information.modules);
  environment_information.modules = NULL;
}

enum ptracer_tracing_state {
  TRACING,
  STOPPING,
  STOPPED,
  EXITING
};

static enum ptracer_tracing_state tracing_state = TRACING;

/* INFO: The crash-loop guard's memory: how many zygote restarts have been seen
         back to back, and when the one before the current call was. Only
         should_stop_inject() below reads them; the injection report resets the
         count, because a zygote that ran far enough to report back was
         injected, and the restarts counted before it were therefore not a
         loop. Declared up here rather than beside that guard because the
         report is handled above it. */
static struct timespec last_zygote = {
  .tv_sec = 0,
  .tv_nsec = 0
};

static int count_zygote = 0;

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
  /* INFO: Close-on-exec, like every other descriptor this process opens. The
            events are set up before the daemon and the tracer are forked, and
            without the flag the poll fd would be inherited by both of them. */
  monitor_epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  if (monitor_epoll_fd == -1) {
    PLOGE("epoll_create1");

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

/* INFO: The monitor's own socket address, which the listener and a one-shot
         control sender both have to build. Only the path not fitting can fail,
         and each caller turns that into its own error, so the length it returns
         is all that has to travel back: the socklen to hand bind(2)/sendto(2),
         or -1. */
static int controller_addr(struct sockaddr_un *addr) {
  memset(addr, 0, sizeof(*addr));

  addr->sun_family = AF_UNIX;

  int path_len = snprintf(addr->sun_path, sizeof(addr->sun_path), "%s", ZYGISK_CONTROLLER_SOCKET);
  if (path_len < 0 || (size_t)path_len >= sizeof(addr->sun_path)) return -1;

  return (int)(sizeof(sa_family_t) + (size_t)path_len);
}

bool rezygiskd_listener_init() {
  monitor_sock_fd = socket(PF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
  if (monitor_sock_fd == -1) {
    PLOGE("socket create");

    return false;
  }

  struct sockaddr_un addr = { 0 };

  int socklen = controller_addr(&addr);
  if (socklen == -1) {
    LOGE("The monitor socket path does not fit into sockaddr_un");

    close(monitor_sock_fd);
    monitor_sock_fd = -1;

    return false;
  }

  if (bind(monitor_sock_fd, (struct sockaddr *)&addr, (socklen_t)socklen) == -1) {
    PLOGE("bind socket");

    /* INFO: Closed here as on the path above that also gives up, so the fd does
              not outlive the function that decided it is useless. */
    close(monitor_sock_fd);
    monitor_sock_fd = -1;

    return false;
  }

  return true;
}

/* INFO: Upper bound for one length-prefixed string the daemon sends. Every one
         of them is a name or a message — a module id, a target, the root
         solution, an error text — so this ceiling is generous by orders of
         magnitude while still keeping a corrupted length from being trusted. */
#define MONITOR_STRING_MAX (64u * 1024u)

/* INFO: Reads one length-prefixed string off the daemon socket, or NULL.

          The length is validated before use: a uint32_t of 0xffffffff wraps to
          zero in `length + 1`, so the allocation would hand back a minimal block
          that read_loop then fills with four gigabytes of datagram. On NULL the
          caller abandons the datagram - the stream is already out of step with
          the daemon, so dispatching on what follows would act on garbage. */
static char *read_socket_string(const char *what) {
  uint32_t length = 0;

  if (read_uint32_t(monitor_sock_fd, &length) != sizeof(length)) {
    LOGE("read VexZygiskd%s %s len", MONITOR_ABI, what);

    return NULL;
  }

  if (length > MONITOR_STRING_MAX) {
    LOGE("VexZygiskd%s %s length %u is out of range", MONITOR_ABI, what, length);

    return NULL;
  }

  char *value = malloc((size_t)length + 1);
  if (value == NULL) {
    PLOGE("malloc VexZygiskd%s %s", MONITOR_ABI, what);

    return NULL;
  }

  if (read_loop(monitor_sock_fd, value, length) != (ssize_t)length) {
    LOGE("read VexZygiskd%s %s", MONITOR_ABI, what);

    free(value);

    return NULL;
  }

  value[length] = '\0';

  return value;
}

/* INFO: The module list the daemon sends, one entry at a time: the name, a
         type byte, and for a Zygisk Next module a companion flag and the
         targets it was registered for.

         Every slot is allocated before anything is read into it, so the cleanup
         path can walk the full lists - which is what the label at the end is
         for, and why the failure paths jump to it rather than unwinding by
         hand. A read that fails partway leaves the lists empty rather than half
         filled: the status line says so instead of naming modules that were
         never delivered. */
static void read_daemon_modules(void) {
  /* INFO: Read into a local first: the old list is freed through the length it
            was allocated with, so the stored length must not be overwritten
            before that. */
  uint32_t modules_len;
  if (read_uint32_t(monitor_sock_fd, &modules_len) != sizeof(modules_len)) {
    LOGE("read VexZygiskd%s modules len", MONITOR_ABI);

    free(environment_information.root_impl);
    environment_information.root_impl = NULL;

    return;
  }

  free_environment_information();

  environment_information.modules_len = modules_len;
  environment_information.zn_len = 0;
  environment_information.modules = calloc(modules_len, sizeof(struct daemon_module));

  if (environment_information.modules == NULL) {
    PLOGE("malloc VexZygiskd%s module list", MONITOR_ABI);

    free(environment_information.root_impl);
    environment_information.root_impl = NULL;

    free_environment_information();

    return;
  }

  for (size_t i = 0; i < environment_information.modules_len; i++) {
    struct daemon_module *module = &environment_information.modules[i];

    module->name = read_socket_string("module name");
    if (module->name == NULL) goto set_info_modules_cleanup;

    uint8_t module_type;
    if (read_uint8_t(monitor_sock_fd, &module_type) != sizeof(module_type)) {
      LOGE("read VexZygiskd%s module type", MONITOR_ABI);

      goto set_info_modules_cleanup;
    }

    module->is_zn = module_type == 1;
    if (module->is_zn) environment_information.zn_len++;

    if (module->is_zn) {
      uint8_t companion;
      if (read_uint8_t(monitor_sock_fd, &companion) != sizeof(companion)) {
        LOGE("read VexZygiskd%s module companion", MONITOR_ABI);

        goto set_info_modules_cleanup;
      }
      module->companion = companion == 1;

      if (read_uint32_t(monitor_sock_fd, &module->targets_len) != sizeof(module->targets_len)) {
        LOGE("read VexZygiskd%s module targets len", MONITOR_ABI);

        goto set_info_modules_cleanup;
      }

      if (module->targets_len > 0) {
        module->targets = calloc(module->targets_len, sizeof(char *));
        if (module->targets == NULL) {
          PLOGE("malloc VexZygiskd%s module targets", MONITOR_ABI);

          goto set_info_modules_cleanup;
        }

        for (uint32_t t = 0; t < module->targets_len; t++) {
          module->targets[t] = read_socket_string("module target");
          if (module->targets[t] == NULL) goto set_info_modules_cleanup;
        }
      }
    }

    LOGD("VexZygiskd%s module %zu: %s (%s)", MONITOR_ABI, i, module->name, module->is_zn ? "next" : "zygisk");
  }

  update_status(NULL);

  return;

  /* INFO: Reached from any failed read above. The array was calloc'ed, so
            free_environment_information walks the full list. */
  set_info_modules_cleanup:
    free(environment_information.root_impl);
    environment_information.root_impl = NULL;

    free_environment_information();

    update_status(NULL);

    return;
}


void rezygiskd_listener_callback() {
  while (1) {
    uint8_t cmd = 0;
    ssize_t nread = TEMP_FAILURE_RETRY(read(monitor_sock_fd, &cmd, sizeof(cmd)));
    if (nread == -1) {
      if (errno == EINTR || errno == EWOULDBLOCK) break;

      /* INFO: Any other error is permanent for this socket — continuing
                would spin the monitor at 100% CPU on the same failure. The
                next datagram the daemon sends re-arms the edge event. */
      PLOGE("read socket");

      break;
    }

    /* INFO: A zero-length datagram carries no command; skip it and keep
              draining instead of dispatching on stale state. */
    if (nread == 0) continue;

    switch (cmd) {
      case START: {
        if (tracing_state == STOPPING) {
          LOGI("Continue tracing init");

          tracing_state = TRACING;
          monitor_stop_reason = NULL;
        } else if (tracing_state == STOPPED) {
          LOGI("Start tracing init");

          /* INFO: Checked here the way claim_init_tracer() checks it. A seize
                    that failed would leave this monitor believing it was tracing
                    init, and every later decision - the fork handling, the
                    status line the manager reads - made on that belief. Staying
                    where it is the honest answer, and the status reports it. */
          if (ptrace(PTRACE_SEIZE, 1, 0, PTRACE_O_TRACEFORK) == -1) {
            PLOGE("seize init");
          } else {
            tracing_state = TRACING;
            monitor_stop_reason = NULL;
          }
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

        /* INFO: A zygote that ran far enough to report back was injected, so
                  the restarts counted before it were not a crash loop. Only a
                  zygote that dies between its exec and this report keeps
                  counting, which is what the guard is for.

                  WebView's zygote is why this reset exists: it runs as the same
                  binary and restarts on its own schedule, and it reports back
                  exactly like the main one - so a device that merely used
                  WebView often enough was read as a crash loop and had its
                  injection shut off on it. */
        count_zygote = 0;

        update_status(NULL);

        break;
      }
      case CMD_DAEMON_SET_INFO: {
        LOGD("Received VexZygiskd%s info", MONITOR_ABI);

        /* INFO: Read into a local first: a failed read then leaves the previous
                  value in place instead of dropping it. */
        char *root_impl = read_socket_string("root impl");
        if (root_impl == NULL) break;

        free(environment_information.root_impl);
        environment_information.root_impl = root_impl;

        LOGD("VexZygiskd%s root impl: %s", MONITOR_ABI, environment_information.root_impl);

        read_daemon_modules();

        break;
      }
      case CMD_DAEMON_SET_ERROR_INFO: {
        LOGD("Received VexZygiskd%s error info", MONITOR_ABI);

        /* INFO: Same ordering as the info case above: the old text survives a
                  failed read. */
        char *error_info = read_socket_string("error info");
        if (error_info == NULL) break;

        free(status.daemon_error_info);
        status.daemon_error_info = error_info;

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

/* INFO: Left behind by the module's post-fs-data.sh when it finds this monitor
         already running, which only happens when the boot stages have just been
         replayed around a session that stayed up.

         That mark is the one thing that tells a soft reboot apart from a crash
         on this side: both are a zygote that went away and came back. Counting
         a soft reboot towards the crash-loop stop is what shuts injection off
         on the third one in a row, and a single reboot costs more than one
         count - every process matched here is /system/bin/app_process64, which
         is also what the WebView zygote runs as, and the reboot restarts both. */
#define SOFT_REBOOT_MARKER ZYGISK_TMP_PATH "/soft-reboot"

static bool should_stop_inject() {
  struct timespec now = {};
  clock_gettime(CLOCK_MONOTONIC, &now);

  /* INFO: Consumed as it is read, so one replayed stage restarts the count
            once. Done before the count is touched: this exec belongs to the
            reboot, and must not also be read as the first restart of a new
            crash loop. */
  if (unlink(SOFT_REBOOT_MARKER) == 0) {
    LOGI("The boot stages were replayed around this session, restarting the zygote count");

    count_zygote = 0;
    last_zygote = now;

    return false;
  }

  if (now.tv_sec - last_zygote.tv_sec < 30)
    count_zygote++;
  else
    count_zygote = 0;

  last_zygote = now;

  return count_zygote >= MAX_RETRY_COUNT;
}

/* INFO: How long a freshly forked daemon is given to bind its socket before the
         socket's absence is read as "unreachable". Only exists so the zygote
         and the spawner, which exec within milliseconds of each other on a
         normal boot, cannot have the daemon that was just forked for them
         mistaken for a stale one and killed. */
#define DAEMON_SETTLE_SECONDS 5

/* INFO: How long the spawner waits for a daemon this monitor could not fork,
         before it is injected without one. The loader on the other side of that
         injection waits seconds for the same daemon, so a spawner injected here
         is not a spawner lost - which is the whole point: the alternative was to
         skip it, and a skipped spawner means no HyperOS runtime and no Zygisk
         Next module in that boot. */
#define SPAWNER_DAEMON_ATTEMPTS 4
#define SPAWNER_DAEMON_RETRY_US 250000

/* INFO: When the current daemon was forked, on the monotonic clock. */
static struct timespec daemon_forked_at = {};

/* INFO: A daemon is reachable through its socket, not through its pid: one that
         is still alive but whose socket file has been removed cannot be
         connected to at all, and answering "already running" for it disables
         every module while the process sits there looking healthy.

         That is not hypothetical. A soft reboot replays the boot stages, and
         the module's post-fs-data.sh clears the directory holding these sockets
         while a monitor and daemon from the previous session are still running.
         The pid alone left that session permanently unreachable.

         Only an outright missing file counts as "gone". Any other failure -
         EACCES if the policy denies the check itself, ELOOP, a transient
         ENOMEM - is answered as present on purpose, because reading it as
         missing would kill a daemon that may be perfectly reachable, once per
         process start, and the replacement would hit the same wall. */
static bool daemon_socket_present() {
  if (access(ZYGISK_CP_SOCKET, F_OK) == 0) return true;

  return errno != ENOENT;
}

static bool ensure_daemon_created() {
  pid_t stale_pid = -1;

  if (status.daemon_pid != -1) {
    struct timespec now = {};
    clock_gettime(CLOCK_MONOTONIC, &now);

    if (now.tv_sec - daemon_forked_at.tv_sec < DAEMON_SETTLE_SECONDS || daemon_socket_present()) {
      LOGD("VexZygiskd%s already running", MONITOR_ABI);

      return status.daemon_running;
    }

    LOGW("VexZygiskd%s is alive but %s is gone, replacing it", MONITOR_ABI, ZYGISK_CP_SOCKET);

    /* INFO: Recorded rather than killed on the spot. Killing here and forking
              afterwards would let a failed fork leave nothing behind at all,
              turning a transient failure - ENOMEM on a loaded device - into the
              permanent "not running" answer below. The old daemon keeps its
              socket until the replacement has taken the path over. */
    stale_pid = status.daemon_pid;

    status.daemon_pid = -1;
    status.daemon_running = false;
  }

  pid_t pid = fork();
  if (pid < 0) {
    PLOGE("create VexZygiskd%s", MONITOR_ABI);

    /* INFO: Put the daemon that was about to be replaced back as the current
              one. It cannot be connected to, but neither can nothing, and the
              next attempt is still free to replace it. */
    if (stale_pid != -1) {
      status.daemon_pid = stale_pid;
      status.daemon_running = true;
    }

    return false;
  }

  if (pid == 0) {
    char daemon_name[] = "./bin/zygiskd" MONITOR_ABI;

    execl(daemon_name, daemon_name, NULL);

    PLOGE("exec VexZygiskd%s failed", MONITOR_ABI);

    exit(1);
  }

  if (stale_pid != -1) {
    /* INFO: The stale daemon is killed rather than abandoned: it holds a socket
              nobody can reach any more, and leaving it behind would leak one
              daemon per replacement. Its own exit is then reaped by the generic
              child handling, which no longer matches it against the pid below,
              and answers it as what it is - a process that already exited. */
    kill(stale_pid, SIGKILL);
  }

  /* INFO: A daemon that has just come up answers whatever the last one said on
            its way out. The text is deliberately not cleared where it is set -
            the first failure explains the most - so it is cleared here, at the
            point it stops being true, instead of being reported for the rest of
            the session. */
  if (status.daemon_error_info) {
    free(status.daemon_error_info);
    status.daemon_error_info = NULL;
  }

  status.supported = true;
  status.daemon_pid = pid;
  status.daemon_running = true;

  clock_gettime(CLOCK_MONOTONIC, &daemon_forked_at);

  return true;
}

static int sigchld_signal_fd;
static struct signalfd_siginfo sigchld_fdsi;
static int sigchld_status;

static pid_t *sigchld_process;
static size_t sigchld_process_count = 0;
static size_t sigchld_process_capacity = 0;
/* INFO: Every slot below this one is known to be taken, so the search for a
         free slot starts here instead of at the beginning. The array is walked
         once per fork and holds every process under trace, so starting over
         each time made a burst cost a scan of everything recorded so far. */
static size_t sigchld_process_free = 0;

/* INFO: Who holds init right now, or 0 when nobody does. Read out of
         /proc/1/status instead of inferred, because it answers the only
         question a failed seizure leaves open. */
static pid_t init_tracer_pid() {
  FILE *status = fopen("/proc/1/status", "re");
  if (status == NULL) return 0;

  char line[256];
  pid_t tracer = 0;

  while (fgets(line, sizeof(line), status) != NULL) {
    if (sscanf(line, "TracerPid: %d", &tracer) == 1) break;
  }

  fclose(status);

  return tracer;
}

/* INFO: Whether the process tracing init is one of ours. A second monitor
         losing the race is a normal outcome of a soft reboot - the boot stages
         replay and two of them can look at the same untraced init within
         milliseconds - and it is worth saying nothing about. A seizure held by
         anything else is the conflict the status line below exists to report.
         The two are only told apart by looking at who is holding it. */
static bool init_traced_by_monitor() {
  pid_t tracer = init_tracer_pid();
  if (tracer <= 0) return false;

  char path[PATH_MAX];
  snprintf(path, sizeof(path), "/proc/%d/comm", tracer);

  FILE *comm = fopen(path, "re");
  if (comm == NULL) return false;

  char name[64] = { 0 };
  /* INFO: The comm is capped at fifteen characters, which both monitor names
            fit exactly; the prefix leaves the ABI out of it. */
  bool matched = fgets(name, sizeof(name), comm) != NULL &&
                 strncmp(name, "zygisk-ptrace", sizeof("zygisk-ptrace") - 1) == 0;

  fclose(comm);

  return matched;
}

static bool claim_init_tracer() {
  if (ptrace(PTRACE_SEIZE, 1, 0, PTRACE_O_TRACEFORK) == -1) {
    /* INFO: In cases where, for example, 2 VexZygisks were executed, the second
               process won't be able to seize init due to limitations of ptrace.
               In this case, we should just exit the second process to avoid
               conflicts. */
    if (errno == EPERM) {
      if (init_traced_by_monitor()) {
        /* INFO: Another monitor of ours holds init. Nothing is wrong, this
                  process simply has nothing to do, and reporting it as a
                  conflict would put a failure into the manager's status for a
                  session that is working. */
        LOGD("A VexZygisk monitor is already tracing init, leaving it to that one");
      } else {
        LOGW("Another process is already tracing init");

        update_status("❌ Multiple Zygisks functioning");
      }
    } else {
      PLOGE("failed to seize init");
    }

    return false;
  }

  return true;
}

bool sigchld_listener_init() {
  sigchld_process = NULL;
  sigchld_process_count = 0;
  sigchld_process_capacity = 0;

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

/* INFO: A path whose last component is the spawner's file name. The leading
         slash is required so a longer name that merely ends with it (say
         "xhyos_spawner") is not mistaken for the spawner. */
static bool is_spawner_program(const char *program) {
  static const char kBase[] = HYOS_SPAWNER_BASE_NAME;

  size_t program_len = strlen(program);
  size_t base_len = sizeof(kBase) - 1;

  if (program_len <= base_len) return false;

  const char *base = program + program_len - base_len;

  return base[-1] == '/' && strcmp(base, kBase) == 0;
}

/* INFO: Which executable this monitor owns and how the tracer has to be told
         about it. False for anything left to another monitor. The tracer and
         the spawner flag describe the fork path's hand-off only, so a caller
         that just needs the ownership answer - the respawn below - passes NULL
         for both instead of keeping a second copy of the table. */
static bool match_target(const char *program, const char **tracer, bool *is_spawner) {
  bool program_is_spawner = is_spawner_program(program);
  if (strcmp(program, APP_PROCESS_NAME) != 0 && !program_is_spawner) return false;

  if (tracer != NULL) *tracer = "./bin/zygisk-ptrace" MONITOR_ABI;
  if (is_spawner != NULL) *is_spawner = program_is_spawner;

  return true;
}

/* INFO: The hand-off leaves the target stopped and untraced. Detaching with
         SIGSTOP is what lets a fresh tracer seize a process that is already
         past its exec. */
static void launch_tracer(pid_t pid, const char *tracer, bool is_spawner) {
  LOGD("Detaching %d", pid);
  ptrace(PTRACE_DETACH, pid, 0, SIGSTOP);

  int p = fork_dont_care();

  if (p == 0) {
    char pid_str[32];
    snprintf(pid_str, sizeof(pid_str), "%d", pid);

    /* INFO: Only a later zygote exec restarts the companions: the first one
              has none yet, and the spawner is not a zygote restart at all -
              telling the daemon otherwise makes it drop every companion and
              leaves the apps it already forked talking to nothing. */
    bool restart = count_zygote > 1 && !is_spawner;

    LOGI("exec tracer command: %s trace %s%s", tracer, pid_str, restart ? " --restart" : "");

    const char *tracer_name = position_after(tracer, '/');

    char *exec_argv[6];
    int exec_argc = 0;
    exec_argv[exec_argc++] = (char *)tracer_name;
    exec_argv[exec_argc++] = "trace";
    exec_argv[exec_argc++] = pid_str;
    if (restart) exec_argv[exec_argc++] = "--restart";
    exec_argv[exec_argc] = NULL;

    execv(tracer, exec_argv);

    PLOGE("exec");

    kill(pid, SIGKILL);

    /* INFO: _exit, not exit: this fork shares the monitor's stdio
              buffers and atexit handlers. */
    _exit(1);
  } else if (p == -1) {
    PLOGE("fork");

    kill(pid, SIGKILL);
  }
}

/* INFO: get_program() is written for a single, known target: it reports a
         readlink failure as an error. A /proc sweep is the opposite case -
         most entries are kernel threads, zombies or otherwise unreadable, and
         none of that is worth a line - so the bulk scan uses this silent
         variant instead. The (deleted) suffix is stripped by the shared
         helper, so a program the kernel annotated still matches its path. */
static bool program_matches(int pid, char *buf, size_t size) {
  return read_exe_path(pid, buf, size) > 0;
}

/* INFO: The parent of a pid, or 0 when it cannot be determined. Field four of
         /proc/<pid>/stat is the ppid, but the second field is the command name
         in parentheses and may itself contain spaces and parentheses, so the
         fields are counted from the last ')' rather than from the start of the
         line. */
static pid_t parent_of(int pid) {
  char path[PATH_MAX];
  snprintf(path, sizeof(path), "/proc/%d/stat", pid);

  /* INFO: open/read rather than stdio on purpose. This is called once for
            every entry under /proc by the scan that looks for a target which a
            normal boot does not have, so it is called to read one bounded line
            a few hundred times and find nothing. fopen, fgets and fclose
            allocate and release a FILE and its buffer on each of those calls;
            the line wanted here is at the front of the file either way, and a
            short read still leaves the closing paren in place or returns 0. */
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd == -1) return 0;

  char line[512];
  ssize_t got = TEMP_FAILURE_RETRY(read(fd, line, sizeof(line) - 1));

  close(fd);

  if (got <= 0) return 0;

  line[got] = '\0';

  char *rparen = strrchr(line, ')');
  if (rparen == NULL) return 0;

  int ppid = 0;

  /* INFO: After the ')' come the state, then the ppid. */
  if (sscanf(rparen + 1, " %*c %d", &ppid) != 1) return 0;

  return (pid_t)ppid;
}

/* INFO: A TRACEFORK monitor sees only the forks made after init was seized, so
         anything already running when this monitor starts is invisible to that
         path. That is the whole of a late-load session - KernelSU loaded from
         an LKM once the boot stages have passed - and also the case for a
         monitor that had to be restarted.

         Taking those processes over in place does not work. Every injection
         entry point waits on a step of the target's own start-up that a process
         which finished starting minutes ago never takes again: the tracer on
         the linker resolving app_process's __libc_init slot, the injected GOT
         break on the call through that slot. A tracer handed such a process
         ends up stepping a live target instead of injecting it, and every
         Zygisk module stays dead.

         The one event that does work is the fresh fork+exec the fork path
         already handles, so a target that predates this monitor is respawned
         rather than taken over. init owns both the zygote and the HyperOS
         spawner as services and forks them itself, so killing one makes init
         start a fresh process that this monitor catches exactly the way it
         catches them on a normal boot. The zygote is the framework's parent, so
         its restart also replays the boot stages and re-forks system_server -
         the one-time bootstrap a late-load user otherwise triggers by hand with
         the root manager's "soft restart", and what makes a framework that is
         already up agree to be injected at all.

         On a normal boot this finds nothing, because the monitor starts well
         before init ever execs either target; the scan only ever matches in a
         late-load session or after a monitor restart.

         A target is identified by three things together - its executable, its
         parent being init, and being the lowest-pid match - because none of
         them is enough on its own. See the scan below. */
static void respawn_stale_targets(void) {
  DIR *proc = opendir("/proc");
  if (proc == NULL) {
    PLOGE("opendir /proc");

    return;
  }

  /* INFO: The whole directory is read before anything is killed, and each
           target is then killed at most once - the lowest pid that matched.

           Two reasons it cannot be a kill-as-you-go scan. The executable alone
           does not identify a target: every app process is a fork of the
           zygote and reads back as app_process64, and there is more than one
           init service using that executable (the secondary zygote uses the
           32-bit one, but a WebView zygote does not). readdir returns entries
           in directory order, so whichever one happens to come first would be
           the one killed - possibly a user app, while the real zygote is left
           alone and injection silently never happens. Restricting to init's
           children removes the app processes, and taking the lowest pid picks
           the zygote over any later, on-demand service. The zygote is init's
           first Java process and so carries the lowest pid of any of them.

           Killing one target also cannot disturb the other: init can bring a
           fresh one up while this scan is still reading /proc, and killing that
           one too would turn the respawn into a loop. */
  pid_t stale_zygote = 0;
  pid_t stale_spawner = 0;

  struct dirent *entry;
  while ((entry = readdir(proc)) != NULL) {
    if (entry->d_name[0] < '0' || entry->d_name[0] > '9') continue;

    char *endptr = NULL;
    long pid_value = strtol(entry->d_name, &endptr, 10);
    if (endptr == entry->d_name || *endptr != '\0' || pid_value <= 1) continue;

    char program[PATH_MAX];
    if (!program_matches((int)pid_value, program, sizeof(program))) continue;

    bool is_spawner = false;
    if (!match_target(program, NULL, &is_spawner)) continue;

    /* INFO: The zygote and the spawner are init's own services, so both are
             direct children of pid 1 - which no app process ever is. */
    if (parent_of((int)pid_value) != 1) continue;

    pid_t *stale = is_spawner ? &stale_spawner : &stale_zygote;
    if (*stale == 0 || (pid_t)pid_value < *stale) *stale = (pid_t)pid_value;
  }

  closedir(proc);

  pid_t targets[2] = { stale_zygote, stale_spawner };

  for (size_t i = 0; i < sizeof(targets) / sizeof(targets[0]); i++) {
    if (targets[i] == 0) continue;

    LOGI("pid %d predates this monitor; killing it so init hands us a fresh one to inject", targets[i]);

    kill(targets[i], SIGKILL);
  }
}

/* INFO: A child this monitor traces rather than one it spawned: the init it
         seized. Two things matter here - the forks init makes, which is how the
         monitor learns about the processes worth injecting, and the stop signals
         it receives, which have to be passed through with the signal intact, or
         suppressed when they are the job-control ones the zygote has no handler
         for.

         Every return in here means this child is done with, which is what the
         loop this was lifted out of did with a continue. */
static void handle_init_event(int pid, long sigchld_status) {
  if (STOPPED_WITH(sigchld_status, SIGTRAP, PTRACE_EVENT_FORK)) {
    /* INFO: Initialised and checked: the call fills this in only on
              success, and the line below would otherwise print whatever
              the stack held. It is a debug line, so nothing acts on the
              value - but a pid out of nowhere costs a search. */
    long child_pid = 0;
    if (ptrace(PTRACE_GETEVENTMSG, pid, 0, &child_pid) == -1)
      PLOGE("read the pid of the process %d forked", pid);

    LOGV("Forked %ld", child_pid);
  } else if (STOPPED_WITH(sigchld_status, SIGTRAP, PTRACE_EVENT_STOP) && tracing_state == STOPPING) {
    if (ptrace(PTRACE_DETACH, 1, 0, 0) == -1) PLOGE("failed to detach init");

    tracing_state = STOPPED;

    LOGI("Stopped tracing init");

    return;
  }

  if (WIFSTOPPED(sigchld_status)) {
    if (WPTEVENT(sigchld_status) == 0) {
      if (WSTOPSIG(sigchld_status) != SIGSTOP && WSTOPSIG(sigchld_status) != SIGTSTP && WSTOPSIG(sigchld_status) != SIGTTIN && WSTOPSIG(sigchld_status) != SIGTTOU) {
        LOGW("Injecting signal sent to init: %s %d", sigabbrev_np(WSTOPSIG(sigchld_status)), WSTOPSIG(sigchld_status));

        ptrace(PTRACE_CONT, pid, 0, WSTOPSIG(sigchld_status));

        return;
      } else {
        LOGW("Suppressing stop signal sent to init: %s %d", sigabbrev_np(WSTOPSIG(sigchld_status)), WSTOPSIG(sigchld_status));
      }
    }

    ptrace(PTRACE_CONT, pid, 0, 0);
  }

  return;
}

/* INFO: The daemon this monitor forked, reporting its own exit.

         False means the pass should be abandoned. That is the one case where
         something went wrong on this side rather than on the child's: the text
         explaining the exit could not be kept, and walking the rest of the list
         would go on reporting an exit nothing recorded. */
static bool handle_daemon_exit(int pid, long sigchld_status) {
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

      return false;
    }
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
        handle_init_event(pid, sigchld_status);

        continue;
      }

      if (status.supported && pid == status.daemon_pid) {
        if (!handle_daemon_exit(pid, sigchld_status)) return;

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
        /* INFO: A process that has already exited is not "newly attached": there
                  is nothing left to set ptrace options on, and a slot taken here
                  is never handed back. This is the path a replaced daemon takes -
                  the branch above no longer matches it, because the pid it was
                  recorded under already names the replacement. Letting it fall
                  through would leak that slot and, once the kernel hands the pid
                  to somebody else, make an unrelated process look like one that
                  is already under trace. */
        if (WIFEXITED(sigchld_status) || WIFSIGNALED(sigchld_status)) continue;

        LOGV("New process %d attached", pid);

        for (size_t i = sigchld_process_free; i < sigchld_process_count; i++) {
          if (sigchld_process[i] != 0) continue;

          sigchld_process[i] = pid;
          sigchld_process_free = i + 1;

          goto ptrace_process;
        }

        /* INFO: Grown in powers of two rather than one slot at a time. Every
                  process the zygote forks passes through here, and they arrive
                  in bursts - an application launch is one - so growing by a
                  single element made each of those pay for a realloc and a copy
                  of the whole array. The array only ever holds the pids of live
                  processes, so the water mark it reaches is the high-water mark
                  of a burst, not of the session. */
        if (sigchld_process_count == sigchld_process_capacity) {
          size_t capacity = sigchld_process_capacity == 0 ? 64 : sigchld_process_capacity * 2;

          pid_t *new_sigchld_process = (pid_t *)realloc(sigchld_process, sizeof(pid_t) * capacity);
          if (new_sigchld_process == NULL) {
            PLOGE("realloc sigchld_process");

            /* INFO: This process is stopped and under this monitor's control,
                      and the slot it would have been recorded in is exactly what
                      just failed to allocate - so nothing later in the loop will
                      pick it up. Continuing without it leaves it stopped for
                      good, which is one hung application per allocation failure.
                      It is detached and let run instead: this monitor loses track
                      of the process, which the failed allocation already cost,
                      but the process itself survives and the fork it was making
                      completes. */
            ptrace(PTRACE_DETACH, pid, 0, 0);

            continue;
          }

          sigchld_process = new_sigchld_process;
          sigchld_process_capacity = capacity;
        }

        sigchld_process[sigchld_process_count] = pid;
        sigchld_process_count++;
        sigchld_process_free = sigchld_process_count;

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
          bool is_spawner = false;

          do {
            if (tracing_state != TRACING) {
              LOGD("Stopped injecting %d because status is not set to tracing", pid);

              break;
            }

            if (!match_target(program, &tracer, &is_spawner)) break;

            /* INFO: The crash-loop counter is about the zygote restarting. The
                     spawner has its own lifecycle and execs on its own
                     schedule, so counting those execs the same way would trip
                     the crash-loop stop after a burst of app launches. */
            if (!is_spawner && should_stop_inject()) {
              LOGW("Zygote" MONITOR_ABI " restart too many times, stop injecting");

              tracing_state = STOPPING;
              monitor_stop_reason = "Zygote crashed";
              ptrace(PTRACE_INTERRUPT, 1, 0, 0);

              break;
            }

            /* INFO: Both targets need the daemon, and the spawner can exec
                     before the zygote ever does, so creating it cannot be left
                     to the zygote injection. */
            bool daemon_ready = ensure_daemon_created();

            /* INFO: The one way that answers false is a fork that failed - the
                     device was out of memory at the instant the spawner exec'd.
                     It is retried for the spawner and not for the zygote
                     because nothing comes after the spawner: the runtime this
                     injection sets up is what every app of this boot registers
                     against, and the next chance to install it is the next
                     boot. */
            for (int attempt = 0; !daemon_ready && is_spawner && attempt < SPAWNER_DAEMON_ATTEMPTS; attempt++) {
              usleep(SPAWNER_DAEMON_RETRY_US);
              daemon_ready = ensure_daemon_created();
            }

            if (!daemon_ready && !is_spawner) {
              LOGW("VexZygiskd%s not running, stop injecting", MONITOR_ABI);

              tracing_state = STOPPING;
              monitor_stop_reason = "VexZygiskd not running";
              ptrace(PTRACE_INTERRUPT, 1, 0, 0);

              break;
            }

            if (!daemon_ready) {
              /* INFO: The spawner is injected anyway. Skipping it - which is
                       what this used to do - loses the whole boot's runtime
                       rather than the one thing the skip was protecting: the
                       loader waits for the daemon on its side, and the spawner
                       is the target whose window is measured in seconds
                       exactly because its daemon may have been forked in the
                       same breath as its own exec. The cost of being wrong is
                       that wait; the cost of this was a boot with no HyperOS
                       runtime and no Zygisk Next module in it. */
              LOGW("VexZygiskd%s not running, injecting hyos_spawner %d anyway for its loader to wait out",
                   MONITOR_ABI, pid);
            }

            LOGD("Stopping %d (program: %s, tracer: %s)", pid, program, tracer);

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

            sigchld_status = 0;

            launch_tracer(pid, tracer, is_spawner);
          } while (false);
        } else {
          char status_str[64];
          parse_status(sigchld_status, status_str, sizeof(status_str));

          LOGW("process %d received unknown sigchld_status %s", pid, status_str);
        }

        for (size_t i = 0; i < sigchld_process_count; i++) {
          if (sigchld_process[i] != pid) continue;

          sigchld_process[i] = 0;
          if (i < sigchld_process_free) sigchld_process_free = i;

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
  sigchld_process_capacity = 0;
  sigchld_process_free = 0;
  sigchld_process_free = 0;
}

static char pre_section[1024];
static char post_section[1024];
static char module_text[2048];

/* INFO: A module that ships both a Zygisk library and a zn_modules.txt lands in
         both the plain and the Zygisk Next lists, so check for a Next twin
         before listing the plain copy. */
static bool has_zn_twin(const char *name) {
  if (environment_information.zn_len == 0) return false;

  for (uint32_t j = 0; j < environment_information.modules_len; j++) {
    const struct daemon_module *twin = &environment_information.modules[j];

    if (twin->is_zn && twin->name != NULL && strcmp(twin->name, name) == 0) return true;
  }

  return false;
}

/* INFO: Folds the detected Zygisk modules into the module description so the
         manager shows them right on the module card, Mountify-style. */
/* INFO: Appends to a bounded buffer and keeps the offset inside it. snprintf
         reports the length it would have written rather than the length it did,
         so a truncated append advances the offset past the end of the buffer -
         and the next call would then be handed a negative size as a size_t,
         along with a pointer past the array, and write into whatever follows it
         in memory. Every append goes through here for that reason. */
static void append_bounded(char *buf, size_t cap, size_t *off, const char *text) {
  if (*off >= cap) return;

  int written = snprintf(buf + *off, cap - *off, "%s", text);
  if (written > 0) *off += (size_t)written;

  if (*off >= cap) *off = cap - 1;
}

/* INFO: The same append for a caller that only holds the buffer, taking the
         offset from the string itself. Both forms exist because a loop wants to
         carry the offset and a single statement does not, and writing either
         one out by hand is where the strncat calls below went wrong: with the
         string already filling the buffer, `cap - strlen(buf) - 1` underflows
         into a size_t so large that strncat stops bounding anything. */
static void str_append_bounded(char *buf, size_t cap, const char *text) {
  size_t off = strlen(buf);

  append_bounded(buf, cap, &off, text);
}

static void build_module_text(void) {
  module_text[0] = '\0';

  if (environment_information.modules == NULL || environment_information.modules_len == 0) return;

  size_t off = 0;
  append_bounded(module_text, sizeof(module_text), &off, "Modules: ");

  bool first = true;

  for (uint32_t i = 0; i < environment_information.modules_len && off < sizeof(module_text) - 1; i++) {
    const struct daemon_module *module = &environment_information.modules[i];
    if (module->name == NULL) continue;

    if (!module->is_zn && has_zn_twin(module->name)) continue;

    if (!first) append_bounded(module_text, sizeof(module_text), &off, ", ");
    first = false;

    append_bounded(module_text, sizeof(module_text), &off, module->name);

    if (module->is_zn) append_bounded(module_text, sizeof(module_text), &off, " (Next)");
  }

  append_bounded(module_text, sizeof(module_text), &off, " \u00b7 ");
}

/* INFO: JSON string writer used by the state file below; quotes, backslashes
         and control characters would otherwise produce invalid JSON. Writes
         at most cap - 1 bytes plus the terminator. */
static void json_escape_into(char *dst, size_t cap, const char *src) {
  size_t off = 0;

  for (const unsigned char *cursor = (const unsigned char *)src; *cursor != '\0' && off + 1 < cap; cursor++) {
    unsigned char c = *cursor;
    const char *escape = NULL;
    /* INFO: \uXXXX plus the terminator; a three byte buffer truncated
              every control character to a broken escape. */
    char short_escape[8] = { 0 };

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

/* INFO: Appends the live status to `out`, every append bounded to its
         capacity: the daemon error text arrives over a socket and can be
         longer than the line is allowed to hold. */
static void append_status_text(char *out, size_t cap) {
  #define STATUS_APPEND(text) str_append_bounded(out, cap, (text))

  /* INFO: Read from the module's point of view rather than the monitor's. An
            injection is a one-shot inside the zygote, and a monitor that stops
            afterwards does not undo it - every application forked since already
            carries it, and the modules keep working. The monitor's own state
            therefore chooses the wording but never decides whether the module
            counts as working: only "the injection never landed" is a failure.
            Reporting the raw state as one is what made a working session read
            as broken on the manager's card. */
  const bool injected = status.zygote_injected;

  switch (tracing_state) {
    case TRACING: {
      STATUS_APPEND("✅");

      break;
    }
    case STOPPING: {
      /* INFO: A transition rather than a verdict: the stop is in flight, and
                the next update reports where it landed. */
      STATUS_APPEND(injected ? "⏸" : "⏳");

      break;
    }
    case STOPPED: {
      STATUS_APPEND(injected ? "⏸" : "⛔");

      break;
    }
    case EXITING: {
      STATUS_APPEND(injected ? "⏸" : "❌");

      break;
    }
  }

  if (status.supported) {
    STATUS_APPEND(", VexZygisk ");
    STATUS_APPEND(MONITOR_ABI);
    STATUS_APPEND("-bit: ");

    if (tracing_state == TRACING) {
      if (injected && status.daemon_running) STATUS_APPEND("✅");
      else STATUS_APPEND("⚠️");
    } else if (injected) {
      /* INFO: "paused" is already said by the emoji at the start of this line,
                and why by the reason appended at the end; repeating it here
                pushed the line longer without adding anything. */
      STATUS_APPEND("✅ injected");
    } else {
      STATUS_APPEND("❌");
    }

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

  /* INFO: Why the monitor is not tracing, once that is known. The state alone
            says what happened but not why, and the reason is what tells a stop
            that was asked for apart from one that went wrong. */
  if (tracing_state != TRACING && monitor_stop_reason != NULL) {
    STATUS_APPEND(" — ");
    STATUS_APPEND(monitor_stop_reason);
  }

  #undef STATUS_APPEND
}

/* INFO: Mirrors the status into the JSON a frontend reads. Written only once a
         root solution has been identified — without one the file would
         describe a run that never named itself — and an existing file is
         removed in that case rather than left describing a previous run. */
static bool write_state_json(void) {
  if (environment_information.root_impl == NULL) {
    if (remove(ZYGISK_STATE_JSON) == -1) {
      PLOGE("failed to remove state.json");
    }

    return true;
  }

  FILE *json = fopen(ZYGISK_STATE_JSON, "w");
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
      const struct daemon_module *module = &environment_information.modules[i];

      if (i > 0) fprintf(json, ", ");

      char module_json[256];
      json_escape_into(module_json, sizeof(module_json), module->name ? module->name : "");

      fprintf(json, "{\"id\": \"%s\", \"next\": %s, \"companion\": %s",
              module_json,
              module->is_zn ? "true" : "false",
              module->companion ? "true" : "false");

      if (module->targets) {
        fprintf(json, ", \"targets\": [");
        for (uint32_t t = 0; t < module->targets_len; t++) {
          if (t > 0) fprintf(json, ", ");

          char target_json[256];
          json_escape_into(target_json, sizeof(target_json), module->targets[t] ? module->targets[t] : "");

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

  return true;
}

static bool update_status(const char *message) {
  build_module_text();

  FILE *prop = fopen(ZYGISK_MODULE_PROP, "w");
  if (prop == NULL) {
    PLOGE("failed to open prop");

    return false;
  }

  /* INFO: A caller-supplied message replaces the generated line and ends the
            update there: that path carries a transient note, not a status. */
  if (message) {
    fprintf(prop, "%s[%s] %s%s", pre_section, message, module_text, post_section);
    fclose(prop);

    return true;
  }

  char status_text[256] = "Monitor: ";
  append_status_text(status_text, sizeof(status_text));

  fprintf(prop, "%s[%s] %s%s", pre_section, status_text, module_text, post_section);
  fclose(prop);

  if (!write_state_json()) return false;

  LOGI("status updated: %s", status_text);

  return true;
}

static bool prepare_environment() {
  FILE *orig_prop = fopen(ZYGISK_MODULE_PROP, "r");
  if (orig_prop == NULL) {
    PLOGE("failed to open orig prop");

    return false;
  }

  bool after_description = false;

  char line[1024];
  while (fgets(line, sizeof(line), orig_prop) != NULL) {
    /* INFO: The appends go through the same bounded helper as the status line,
              so a module.prop with lines longer than expected cannot walk
              either section past its end. */
    if (strncmp(line, "description=", strlen("description=")) == 0) {
      str_append_bounded(pre_section, sizeof(pre_section), "description=");
      str_append_bounded(post_section, sizeof(post_section), line + strlen("description="));
      after_description = true;

      continue;
    }

    if (after_description) str_append_bounded(post_section, sizeof(post_section), line);
    else str_append_bounded(pre_section, sizeof(pre_section), line);
  }

  fclose(orig_prop);

  return true;
}

void init_monitor() {
  LOGI("VexZygisk %s", ZKSU_VERSION);

  if (!prepare_environment()) exit(1);

  if (!claim_init_tracer()) exit(1);

  /* INFO: Targets that predate this monitor are not forks of init and so
            never reach the TRACEFORK path; a late-load session is made
            entirely of them, so they are respawned here. Ordered after the
            seize on purpose: the fresh fork init makes in response is what
            the fork path below then catches. */
  respawn_stale_targets();

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

  struct sockaddr_un addr = { 0 };

  int socklen = controller_addr(&addr);
  if (socklen == -1) {
    close(sockfd);

    return -1;
  }

  uint8_t cmd_op = cmd;
  ssize_t nsend = sendto(sockfd, (void *)&cmd_op, sizeof(cmd_op), 0, (struct sockaddr *)&addr, (socklen_t)socklen);

  close(sockfd);

  return nsend != sizeof(cmd_op) ? -1 : 0;
}
