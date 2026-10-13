#ifndef DAEMON_H
#define DAEMON_H

#include <stdbool.h>
#include <stdint.h>

#include "zygisk_paths.h"
#include "zn_control_protocol.h"

#include <unistd.h>

/* INFO: How long one unproductive daemon connection attempt waits before the
         next one. The default is short because the socket either accepts at
         once or is refused outright, so a full second only stalls the
         injection of every process while the daemon is down - it is still long
         enough to ride out a daemon restart. */
#define REZYGISKD_RETRY_DELAY_US 100000

/* INFO: The HyperOS spawner passes the long one. Its daemon may have been
         forked in the same breath as the spawner's own exec, and its module
         plan is loaded once for every app the spawner will ever fork: the
         children inherit it, and nothing asks again. Five attempts a second
         apart is the window that race needs; the retry only ever costs anything
         while the daemon is unreachable. */
#define REZYGISKD_RETRY_DELAY_SPAWNER_US 1000000

/* INFO: Must stay in step with enum DaemonSocketAction on the daemon. */
enum rezygiskd_actions {
  ZygoteInjected,
  GetProcessFlags,
  GetInfo,
  ReadModules,
  RequestCompanionSocket,
  GetModuleDir,
  ZygoteRestart,
  UpdateMountNamespace,
  RemoveModule,
  ReadZnModules,
  SpawnZnCompanion,
  OpenZnControlSession,
  ReportZnRuntime
};

struct zygisk_modules {
  char **modules;
  size_t modules_count;
};

/* INFO: A Zygisk Next library as handed over by the daemon: the path it was
         resolved from, the module it belongs to, whether the module asked for a
         companion, and the fd of the already opened file. */
struct zn_module_file {
  char *lib_path;
  char *module_id;
  bool companion;
  int fd;
};

/* INFO: The flavour this loader was built for. Only the matching member is
         compiled in, and its name deliberately differs from the
         ROOT_IMPL_APATCH compile macro that selects it: a -D would otherwise
         expand the enumerator to 1. */
#ifdef ROOT_IMPL_APATCH
enum root_impl {
  ROOT_APATCH
};
#else
enum root_impl {
  ROOT_KERNELSU
};
#endif

struct rezygisk_info {
  struct zygisk_modules modules;
  enum root_impl root_impl;
  pid_t pid;
  bool running;
};

/* INFO: The loader only ever needs the clean namespace: a denylisted process
         is switched into it when the in-place revert could not be applied.
         Reverting in place needs no namespace from the daemon at all. */
enum mount_namespace_state {
  Clean
};

bool rezygiskd_zygote_injected(void);

uint32_t rezygiskd_get_process_flags(uid_t uid, const char *const process);

void rezygiskd_get_info(struct rezygisk_info *info);

void free_rezygisk_info(struct rezygisk_info *info);

bool rezygiskd_read_modules(struct zygisk_modules *modules);

void free_modules(struct zygisk_modules *modules);

/* INFO: Asks the daemon for the Zygisk Next libraries targeting this process.
         Returns false when the daemon cannot be reached, which is the signal to
         fall back to reading the modules directly. `retry` is the number of
         extra attempts after the first, spaced `retry_delay_us` apart, so the
         call makes retry + 1 attempts and waits at most retry * retry_delay_us
         while the daemon is unreachable. */
bool rezygiskd_read_zn_modules(const char *process_name, const char *process_path, const char *image_path, uint8_t retry, uint32_t retry_delay_us, struct zn_module_file **out, size_t *out_len);

void free_zn_module_files(struct zn_module_file *files, size_t len);

/* INFO: Opens the control session the HyperOS runtime reports over, and returns
         its descriptor or -1. The connection is kept by the daemon rather than
         answered and closed, and the descriptor is inherited by the
         applications the spawner forks - they are the ones that report. */
int rezygiskd_open_zn_control_session(void);

/* INFO: Writes one module report over an open session: this module was told
         about a specialization. Returns false when the record could not be
         written, which no caller acts on - the module has been told either
         way, and the report is the record of it. */
bool rezygiskd_report_zn_runtime(int session_fd, const char *module_id);

/* INFO: Has the daemon spawn a companion for this library and returns its
         control socket, or -1 when it is unavailable. */
int rezygiskd_spawn_zn_companion(const char *lib_path);

int rezygiskd_connect_companion(size_t index);

int rezygiskd_get_module_dir(size_t index);

void rezygiskd_zygote_restart(void);

bool rezygiskd_update_mns(enum mount_namespace_state nms_state, char *buf, size_t buf_size);

bool rezygiskd_remove_module(size_t index);

#endif /* DAEMON_H */
