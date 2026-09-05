#ifndef DAEMON_H
#define DAEMON_H

#include <stdbool.h>

#include <unistd.h>

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
  SpawnZnCompanion
};

struct zygisk_modules {
  char **modules;
  size_t modules_count;
};

/* INFO: A Zygisk Next library as handed over by the daemon: the path it was
         resolved from, whether the module asked for a companion, and the fd of
         the already opened file. */
struct zn_module_file {
  char *lib_path;
  bool companion;
  int fd;
};

enum root_impl {
  ROOT_IMPL_KERNELSU,
  ROOT_IMPL_APATCH
};

struct rezygisk_info {
  struct zygisk_modules modules;
  enum root_impl root_impl;
  pid_t pid;
  bool running;
};

enum mount_namespace_state {
  Clean,
  Mounted
};

#define TMP_PATH "/data/adb/rezygisk"

static inline const char *rezygiskd_get_path() {
  return TMP_PATH;
}

bool rezygiskd_zygote_injected(void);

uint32_t rezygiskd_get_process_flags(uid_t uid, const char *const process);

void rezygiskd_get_info(struct rezygisk_info *info);

void free_rezygisk_info(struct rezygisk_info *info);

bool rezygiskd_read_modules(struct zygisk_modules *modules);

void free_modules(struct zygisk_modules *modules);

/* INFO: Asks the daemon for the Zygisk Next libraries targeting this process.
         Returns false when the daemon cannot be reached, which is the signal to
         fall back to reading the modules directly. */
bool rezygiskd_read_zn_modules(const char *process_name, const char *process_path, struct zn_module_file **out, size_t *out_len);

void free_zn_module_files(struct zn_module_file *files, size_t len);

/* INFO: Has the daemon spawn a companion for this library and returns its
         control socket, or -1 when it is unavailable. */
int rezygiskd_spawn_zn_companion(const char *lib_path);

int rezygiskd_connect_companion(size_t index);

int rezygiskd_get_module_dir(size_t index);

void rezygiskd_zygote_restart(void);

bool rezygiskd_update_mns(enum mount_namespace_state nms_state, char *buf, size_t buf_size);

bool rezygiskd_remove_module(size_t index);

#endif /* DAEMON_H */
