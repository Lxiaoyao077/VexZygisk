/* INFO: Host-side tests for the HyperOS runtime's own logic.

         What cannot be reproduced on a device after the fact is exactly what
         this file holds still: whether a process is taken for the runtime at
         all, which modules may register and when the window closes, what the
         hooks are asked for and what is left behind when they cannot be placed,
         and whether a specialization reaches the modules once - and only once.

         The .c is included rather than linked so its static parts are
         reachable. Three things it reaches for need a device or a linker and
         are stubbed here: the maps reader, which supplies the entries the
         runtime decides on, and the two LSPlt entry points, which stand in for
         the hooking engine. */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <elf.h>
#include <fcntl.h>
#include <link.h>
#include <unistd.h>

#include "check.h"
#include "zn_control_protocol.h"
#include "zn_spawner.h"

#include "../../loader/src/injector/zn_hyos.c"

/* INFO: The maps the scan is asked to walk. `start` is only ever a pointer for
         a mapping that is readable, which is what the runtime's own permission
         check is there to guarantee - the fixture for the unreadable case points
         at address 1 on purpose, so a read that should not happen segfaults the
         test rather than passing quietly. */
struct fake_mapping {
  uintptr_t start;
  uintptr_t end;
  int perms;
  uintptr_t offset;
  dev_t dev;
  ino_t inode;
  const char *path;
};

static const struct fake_mapping *g_mappings = NULL;
static size_t g_mappings_len = 0;

bool scan_maps_safe(const char *pid, maps_visitor visit, void *userdata) {
  (void)pid;

  for (size_t i = 0; i < g_mappings_len; i++) {
    const struct fake_mapping *fake = &g_mappings[i];

    struct map_entry entry = {
      .start = fake->start,
      .end = fake->end,
      .perms = fake->perms,
      .is_private = true,
      .offset = fake->offset,
      .dev = fake->dev,
      .inode = fake->inode,
      .path = (char *)fake->path
    };

    if (!visit(&entry, userdata)) return true;
  }

  return true;
}

/* INFO: What LSPlt is told, and what it answers. The engine itself needs a
         device; what the runtime does with its answers does not. */
static bool g_lsplt_accept = true;
static bool g_lsplt_hand_back = true;
static bool g_lsplt_commit_ok = true;
static const char *g_lsplt_symbols[16];
static size_t g_lsplt_symbols_len = 0;
static size_t g_lsplt_commits = 0;

static pid_t fake_original_fork(void) {
  return 4242;
}

static int fake_original_setcontext(uid_t uid, int is_system_server, const char *se_info, const char *package_name) {
  (void)uid;
  (void)is_system_server;
  (void)se_info;
  (void)package_name;

  return 0;
}

int zn_lsplt_register_hook(dev_t dev, ino_t inode, const char *symbol, void *hook, void **backup) {
  (void)dev;
  (void)inode;
  (void)hook;

  if (g_lsplt_symbols_len < 16) g_lsplt_symbols[g_lsplt_symbols_len++] = symbol;

  if (backup != NULL) {
    if (!g_lsplt_hand_back) {
      /* INFO: What LSPlt answers for a symbol the image does not import: the
                registration is accepted and no original comes back. */
      *backup = NULL;
    } else if (strcmp(symbol, "fork") == 0) {
      *backup = (void *)(uintptr_t)fake_original_fork;
    } else if (strcmp(symbol, "selinux_android_setcontext") == 0) {
      *backup = (void *)(uintptr_t)fake_original_setcontext;
    } else {
      *backup = NULL;
    }
  }

  return g_lsplt_accept ? 0 : -1;
}

int zn_lsplt_commit_hook(void) {
  g_lsplt_commits++;

  return g_lsplt_commit_ok ? 0 : -1;
}

/* INFO: The control session, as the loader hands it to the runtime: a real
         descriptor, because the runtime closes the one it probes with. */
static int g_session_result = 0;
static size_t g_sessions_opened = 0;

static int fake_open_session(void) {
  g_sessions_opened++;

  if (g_session_result < 0) return g_session_result;

  return open("/dev/null", O_RDONLY);
}

static pid_t g_fork_result = 4242;

static pid_t fake_fork(void) {
  return g_fork_result;
}

static char g_reported_ids[8][64];
static size_t g_reported_len = 0;

static bool fake_report(const char *module_id) {
  if (g_reported_len < 8) snprintf(g_reported_ids[g_reported_len], sizeof(g_reported_ids[0]), "%s", module_id);

  g_reported_len++;

  return true;
}

static size_t g_specialized_count = 0;
static char g_specialized_process[256];
static char g_specialized_package[128];
static char g_specialized_se_info[128];

static void fake_specialized(const struct ZnHyosAppSpecializeArgs *args) {
  g_specialized_count++;

  snprintf(g_specialized_process, sizeof(g_specialized_process), "%s", args->process_name);
  snprintf(g_specialized_package, sizeof(g_specialized_package), "%s", args->package_name);
  snprintf(g_specialized_se_info, sizeof(g_specialized_se_info), "%s", args->se_info);
}

static unsigned char g_image[256];

static void make_image(void) {
  ElfW(Ehdr) header;

  memset(&header, 0, sizeof(header));
  memcpy(header.e_ident, ELFMAG, SELFMAG);
  header.e_ident[EI_CLASS] = sizeof(void *) == 8 ? ELFCLASS64 : ELFCLASS32;
  header.e_ident[EI_DATA] = ELFDATA2LSB;
  header.e_type = ET_DYN;
  header.e_machine = ZN_SPAWNER_ELF_MACHINE;

  memset(g_image, 0, sizeof(g_image));
  memcpy(g_image, &header, sizeof(header));
}

static void reset_fixture(void) {
  make_image();

  static const struct fake_mapping spawner[] = {
    {
      .start = (uintptr_t)g_image,
      .end = (uintptr_t)g_image + sizeof(g_image),
      .perms = PROT_READ | PROT_EXEC,
      .offset = 0,
      .dev = 253,
      .inode = 42,
      .path = "/system_ext/bin/hyos_spawner"
    }
  };

  g_mappings = spawner;
  g_mappings_len = 1;

  g_lsplt_accept = true;
  g_lsplt_hand_back = true;
  g_lsplt_commit_ok = true;
  g_lsplt_symbols_len = 0;
  g_lsplt_commits = 0;

  g_session_result = 0;
  g_sessions_opened = 0;

  g_fork_result = 4242;

  g_reported_len = 0;
  g_specialized_count = 0;
  g_specialized_process[0] = '\0';
  g_specialized_package[0] = '\0';
  g_specialized_se_info[0] = '\0';
}

static void check_predicates(void) {
  printf("-- which modules the runtime will take\n");

  CHECK(zn_hyos_module_api_matches(ZYGISK_NEXT_HYOS_API_VERSION), "the runtime's own API version was refused");
  CHECK(!zn_hyos_module_api_matches(ZYGISK_NEXT_HYOS_API_VERSION - 1), "an older HYOS module was accepted");
  CHECK(!zn_hyos_module_api_matches(ZYGISK_NEXT_HYOS_API_VERSION + 1), "a newer HYOS module was accepted");
}

/* INFO: The record a report travels in is written by one half of this fork and
         read by the other, and the two are not linked together anywhere the rest
         of this suite can see. What is held still here is the shape they have to
         agree on - the fields, their order, and the size - so that an edit to
         zn_control_protocol.h that breaks the framing fails in a test rather
         than on a device as a module that was never told anything.

         The framing itself is exercised by hand, at the offsets both halves use:
         an action byte, the header, the id. */
static void check_report_record(void) {
  printf("-- the report record\n");

  CHECK(sizeof(struct zn_control_report_header) == 2 * sizeof(uint32_t),
        "a report header is %zu bytes, wanted %zu",
        sizeof(struct zn_control_report_header), 2 * sizeof(uint32_t));
  CHECK(offsetof(struct zn_control_report_header, pid) == 0, "the reporting pid is not the first field");
  CHECK(offsetof(struct zn_control_report_header, module_id_len) == sizeof(uint32_t),
        "the module id length does not follow the pid");

  CHECK(ZN_CONTROL_MODULE_ID_MAX == 257, "the module id bound is %d", ZN_CONTROL_MODULE_ID_MAX);
  CHECK(zn_control_report_size(0) == sizeof(struct zn_control_report_header), "an empty report is not one header");
  CHECK(zn_control_report_size(7) == sizeof(struct zn_control_report_header) + 7,
        "a report's size does not follow its id");

  const char *module_id = "com.example";
  const uint32_t pid_written = 4242;
  const struct zn_control_report_header header = {
    .pid = pid_written,
    .module_id_len = (uint32_t)strlen(module_id)
  };

  uint8_t record[sizeof(uint8_t) + sizeof(struct zn_control_report_header) + 16];
  size_t at = 0;

  record[at++] = (uint8_t)1;
  memcpy(record + at, &header, sizeof(header));
  at += sizeof(header);
  memcpy(record + at, module_id, strlen(module_id));
  at += strlen(module_id);

  CHECK(at == sizeof(uint8_t) + zn_control_report_size(strlen(module_id)),
        "the framed record is %zu bytes", at);

  uint32_t pid_read = 0;
  uint32_t len_read = 0;
  size_t read_at = sizeof(uint8_t);

  memcpy(&pid_read, record + read_at, sizeof(pid_read));
  read_at += sizeof(pid_read);
  memcpy(&len_read, record + read_at, sizeof(len_read));
  read_at += sizeof(len_read);

  CHECK(pid_read == pid_written, "the pid came back as %u", pid_read);
  CHECK(len_read == strlen(module_id), "the id length came back as %u", len_read);
  CHECK(read_at + len_read == at, "the reader and the writer disagree about where the record ends");
  CHECK(memcmp(record + read_at, module_id, len_read) == 0, "the module id came back wrong");
}

static void check_initialize(void) {
  printf("-- finding the runtime\n");

  reset_fixture();
  g_mappings_len = 0;

  CHECK(!zn_hyos_initialize(fake_open_session, fake_report), "the runtime was found with an empty maps listing");
  CHECK(zn_hyos_runtime() == NULL, "a runtime was handed out with none in the process");

  /* INFO: The mapping is named right and is not readable. The header behind it
            must not be read at all - the address is one that would fault. */
  static const struct fake_mapping unreadable[] = {
    {
      .start = 1,
      .end = 2,
      .perms = PROT_NONE,
      .offset = 0,
      .dev = 253,
      .inode = 42,
      .path = "/system_ext/bin/hyos_spawner"
    }
  };

  reset_fixture();
  g_mappings = unreadable;
  g_mappings_len = 1;

  CHECK(!zn_hyos_initialize(fake_open_session, fake_report), "an unreadable mapping was taken for the runtime");

  /* INFO: The name is right and the bytes are not: a mapping that merely
            carries the spawner's path is not the runtime. */
  reset_fixture();
  g_image[0] = 'X';

  CHECK(!zn_hyos_initialize(fake_open_session, fake_report), "a mapping that is not an image was taken for the runtime");
  CHECK(zn_hyos_image_path()[0] == '\0', "an image path was kept for a runtime that was not found");

  reset_fixture();

  CHECK(zn_hyos_initialize(fake_open_session, fake_report), "the runtime was not found");

  /* INFO: The image's own path, which is the second answer a path target gets
            when the executable is not the file the manifest means. */
  CHECK(strcmp(zn_hyos_image_path(), "/system_ext/bin/hyos_spawner") == 0,
        "the runtime kept \"%s\" instead of the image's path", zn_hyos_image_path());
  CHECK(zn_hyos_runtime() != NULL, "no runtime was handed out");
  CHECK(zn_hyos_runtime()->type == ZN_RUNTIME_HYOS, "the runtime was handed out with the wrong type");
  CHECK(zn_hyos_runtime()->api_version == ZYGISK_NEXT_HYOS_API_VERSION, "the runtime was handed out with the wrong version");
  CHECK(zn_hyos_child_session() < 0, "a session appeared before any fork");

  /* INFO: Being an application is a separate question from having a session,
            and it is the one the cached commit is picked on. Nothing here has
            been forked, so the answer is no. */
  CHECK(!zn_hyos_in_child(), "a process was taken for an application before any fork");
}

static void check_registration_window(void) {
  printf("-- who may register, and when\n");

  static const struct ZygiskNextHyosModule module = {
    .target_api_version = ZYGISK_NEXT_HYOS_API_VERSION,
    .onAppSpecialized = fake_specialized
  };

  /* INFO: A process the runtime is not in has no table to register through, and
            that is the whole answer for it: the module is refused the table
            rather than a slot in it. */
  reset_fixture();
  g_mappings_len = 0;

  CHECK(!zn_hyos_initialize(fake_open_session, fake_report), "the runtime was found with an empty maps listing");
  CHECK(zn_hyos_runtime() == NULL, "a runtime was handed out with none in the process");

  reset_fixture();

  if (!zn_hyos_initialize(fake_open_session, fake_report)) {
    CHECK(false, "the runtime was not found");

    return;
  }

  struct ZygiskNextHyosModule wrong_version = module;
  wrong_version.target_api_version = ZYGISK_NEXT_HYOS_API_VERSION + 1;
  CHECK(zn_hyos_runtime()->registerModule(&wrong_version) == ZN_FAILED, "a module for another HYOS version registered");

  struct ZygiskNextHyosModule no_callback = module;
  no_callback.onAppSpecialized = NULL;
  CHECK(zn_hyos_runtime()->registerModule(&no_callback) == ZN_FAILED, "a module without a callback registered");

  CHECK(zn_hyos_runtime()->registerModule(NULL) == ZN_FAILED, "a NULL module registered");

  zn_hyos_begin_module_registration("com.example.module");
  CHECK(zn_hyos_runtime()->registerModule(&module) == ZN_SUCCESS, "a valid module was refused");
  zn_hyos_end_module_registration();

  /* INFO: More modules than the first allocation holds, so the growth path is
            the one that is exercised. */
  for (size_t i = 0; i < 8; i++) {
    CHECK(zn_hyos_runtime()->registerModule(&module) == ZN_SUCCESS, "registering module %zu failed", i);
  }
}

static void check_hooks(void) {
  printf("-- arming the runtime\n");

  static const struct ZygiskNextHyosModule module = {
    .target_api_version = ZYGISK_NEXT_HYOS_API_VERSION,
    .onAppSpecialized = fake_specialized
  };

  /* INFO: No module registered: nothing to arm, and the call is not a failure. */
  reset_fixture();
  zn_hyos_initialize(fake_open_session, fake_report);
  CHECK(zn_hyos_install_hooks(), "arming a runtime with no module failed");
  CHECK(g_lsplt_symbols_len == 0, "hooks were asked for with no module registered");

  /* A registration that arrived before the hooks were asked for is served. */
  reset_fixture();
  zn_hyos_initialize(fake_open_session, fake_report);
  zn_hyos_begin_module_registration("com.example.module");
  zn_hyos_runtime()->registerModule(&module);
  zn_hyos_end_module_registration();

  CHECK(zn_hyos_install_hooks(), "arming the runtime failed");
  CHECK(g_lsplt_symbols_len == 2, "the runtime asked for %zu hook(s), wanted 2", g_lsplt_symbols_len);
  CHECK(strcmp(g_lsplt_symbols[0], "fork") == 0, "the first hook was not fork");
  CHECK(strcmp(g_lsplt_symbols[1], "selinux_android_setcontext") == 0, "the second hook was not setcontext");
  CHECK(g_lsplt_commits == 1, "the hooks were committed %zu time(s), wanted once", g_lsplt_commits);
  CHECK(g_sessions_opened == 1, "the session was opened %zu time(s), wanted once", g_sessions_opened);

  /* INFO: The window is closed by arming, whatever happens next. */
  CHECK(zn_hyos_runtime()->registerModule(&module) == ZN_FAILED, "a module registered after the hooks were installed");

  /* A registration that fails leaves nothing armed: the engine refused the call. */
  reset_fixture();
  zn_hyos_initialize(fake_open_session, fake_report);
  zn_hyos_begin_module_registration("com.example.module");
  zn_hyos_runtime()->registerModule(&module);
  zn_hyos_end_module_registration();

  g_lsplt_accept = false;
  CHECK(!zn_hyos_install_hooks(), "arming succeeded although the engine refused the hook");
  CHECK(g_sessions_opened == 0, "a session was opened for a runtime that was not armed");

  /* INFO: The engine accepted the registration and handed back no original -
            what LSPlt answers for a symbol the image does not import. There is
            nothing to hook and nothing to call, so the runtime is not armed. */
  reset_fixture();
  zn_hyos_initialize(fake_open_session, fake_report);
  zn_hyos_begin_module_registration("com.example.module");
  zn_hyos_runtime()->registerModule(&module);
  zn_hyos_end_module_registration();

  g_lsplt_hand_back = false;
  CHECK(!zn_hyos_install_hooks(), "arming succeeded with no original to hook");
  CHECK(g_lsplt_commits == 1, "the rollback was not committed");

  /* And a session that cannot be opened leaves nothing armed either. */
  reset_fixture();
  zn_hyos_initialize(fake_open_session, fake_report);
  zn_hyos_begin_module_registration("com.example.module");
  zn_hyos_runtime()->registerModule(&module);
  zn_hyos_end_module_registration();

  g_session_result = -1;
  CHECK(!zn_hyos_install_hooks(), "arming succeeded without a session");
  /* INFO: Two commits: the one that placed the hooks and the one that took
            them back off again, because this is the case where both hooks were
            really there. */
  CHECK(g_lsplt_commits == 2, "the hooks were committed %zu time(s), wanted two", g_lsplt_commits);
}

static void check_specialization(void) {
  printf("-- what a specialization reaches\n");

  static const struct ZygiskNextHyosModule module = {
    .target_api_version = ZYGISK_NEXT_HYOS_API_VERSION,
    .onAppSpecialized = fake_specialized
  };

  /* INFO: The whole path, in the order a device runs it: the runtime is found,
            the module registers while it loads, the hooks go in, the spawner
            forks an application, and the application specializes. */
  reset_fixture();
  CHECK(zn_hyos_initialize(fake_open_session, fake_report), "the runtime was not found");

  zn_hyos_begin_module_registration("com.example.module");
  CHECK(zn_hyos_runtime()->registerModule(&module) == ZN_SUCCESS, "the module did not register");
  zn_hyos_end_module_registration();

  CHECK(zn_hyos_install_hooks(), "arming the runtime failed");

  /* INFO: The fork is the runtime's own, and the test process plays the child:
            what the hook does to the process that comes back is what is checked
            here, and none of it needs a second process. */
  zn_hyos_original_fork = fake_fork;
  g_fork_result = 0;

  CHECK(zn_hyos_replacement_fork() == 0, "the fork hook did not pass the result through");
  CHECK(zn_hyos_child_session() >= 0, "the child was left without a session");

  CHECK(zn_hyos_replacement_setcontext(10000, false, "u:r:untrusted_app:s0", "com.example") == 0,
        "the setcontext hook did not pass the result through");
  CHECK(g_specialized_count == 1, "the module was told %zu time(s), wanted once", g_specialized_count);
  CHECK(g_specialized_package[0] != '\0' && strcmp(g_specialized_package, "com.example") == 0,
        "the module was told the wrong package (\"%s\")", g_specialized_package);
  CHECK(strcmp(g_specialized_se_info, "u:r:untrusted_app:s0") == 0,
        "the module was told the wrong context (\"%s\")", g_specialized_se_info);
  CHECK(g_specialized_process[0] != '\0', "the module was told no process name");
  CHECK(g_reported_len == 1 && strcmp(g_reported_ids[0], "com.example.module") == 0,
        "the module was not reported (or reported under the wrong id)");

  /* INFO: Once, whatever the platform does afterwards. */
  CHECK(zn_hyos_replacement_setcontext(10000, false, "u:r:untrusted_app:s0", "com.example") == 0,
        "the second specialize failed");
  CHECK(g_specialized_count == 1, "the module was told twice for one specialization");

  /* INFO: A child whose session could not be opened is armed but told nothing:
            the contract promises a runtime that reports, and a callback fired
            without one is a half-answer that reads as a whole one. */
  zn_hyos_reset_child_state(false);
  zn_hyos_replacement_setcontext(10000, false, "u:r:untrusted_app:s0", "com.example");
  CHECK(g_specialized_count == 1, "a child without a session was told anyway");

  /* INFO: And a specialization string that does not fit is refused rather than
            truncated - the module is not told at all. */
  char too_long[ZN_HYOS_VALUE_MAX + 16];
  memset(too_long, 'a', sizeof(too_long) - 1);
  too_long[sizeof(too_long) - 1] = '\0';

  zn_hyos_reset_child_state(true);
  zn_hyos_replacement_setcontext(10000, false, too_long, "com.example");
  CHECK(g_specialized_count == 1, "a specialization that does not fit was truncated and delivered");
}

int main(void) {
  check_predicates();
  check_report_record();
  check_initialize();
  check_registration_window();
  check_hooks();
  check_specialization();

  if (g_failures == 0) {
    printf("all HYOS runtime checks passed\n");

    return 0;
  }

  printf("%d HYOS runtime check(s) failed\n", g_failures);

  return 1;
}
