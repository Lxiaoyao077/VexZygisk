#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <unistd.h>

#include "../utils.h"
#include "apatch.h"

/* INFO: APatch (https://github.com/bmax121/APatch) is a KernelPatch based
         root solution. Its daemon mirrors KernelSU's layout:

           - the daemon binary lives at /data/adb/ap/bin/apd;
           - per-package policy lives in /data/adb/ap/package_config, a CSV
             with the header pkg,exclude,allow,uid,to_uid,sctx. "to_uid"
             extends a grant over a uid range, which is how work profiles
             and multi-user setups are handled;
           - the manager app is me.bmax.apatch and may live in any user
             profile (FolkPatch, an APatch branch, keeps the layout but
             ships its manager as me.yuki.folk).

         The kernel-side authorization runs through the KernelPatch supercall
         interface and is not touched here. */
#define AP_BIN_DIR "/data/adb/ap/bin/apd"
#define AP_CONFIG_FILE "/data/adb/ap/package_config"
#define AP_MANAGER_PKG "me.bmax.apatch"
#define AP_FOLKPATCH_PKG "me.yuki.folk"

/* INFO: Rows are bounded because this file is walked for every process flag
         query; a grant that does not fit the table is not one this daemon can
         serve anyway. */
#define AP_MAX_ROWS 256
#define AP_CONFIG_MAX_SIZE (1u << 16)
#define AP_PKG_NAME_MAX 255

struct ap_package_entry {
  char pkg[AP_PKG_NAME_MAX + 1];
  bool exclude;
  bool allow;
  uid_t uid;
  uid_t to_uid;
};

/* INFO: One CSV line may quote its fields ("a""b" is a literal quote inside a
         quoted field, RFC 4180). The fields are written back into out_fields
         as NUL-terminated strings. Returns the number of fields parsed, at
         most max_fields. */
static size_t ap_parse_csv_line(const char *line, char out_fields[][AP_PKG_NAME_MAX + 1], size_t max_fields) {
  size_t field_count = 0;
  size_t field_len = 0;
  bool in_quotes = false;

  while (*line != '\0' && *line != '\n' && *line != '\r') {
    char c = *line++;

    if (c == '"') {
      if (in_quotes && *line == '"') {
        if (field_len < AP_PKG_NAME_MAX) out_fields[field_count][field_len++] = '"';

        line++;
      } else {
        in_quotes = !in_quotes;
      }

      continue;
    }

    if (c == ',' && !in_quotes) {
      out_fields[field_count][field_len] = '\0';
      field_count++;
      field_len = 0;

      if (field_count >= max_fields) break;

      continue;
    }

    if (field_len < AP_PKG_NAME_MAX) out_fields[field_count][field_len++] = c;
  }

  if (field_count < max_fields) {
    out_fields[field_count][field_len] = '\0';
    field_count++;
  }

  return field_count;
}

static bool ap_parse_bool_field(const char *field) {
  return strcmp(field, "1") == 0;
}

/* INFO: Reads the package configuration, retrying like upstream apd does: the
         file is rewritten atomically (tmp + rename) and a reader can still
         catch the moment between the two. Returns the number of rows parsed. */
static size_t ap_read_package_config(struct ap_package_entry *out, size_t max_rows) {
  size_t rows = 0;

  for (int attempt = 0; attempt < 5; attempt++) {
    FILE *file = fopen(AP_CONFIG_FILE, "re");
    if (file == NULL) {
      if (errno == ENOENT) return 0;

      usleep(1000 * 1000);

      continue;
    }

    char line[1024];
    size_t line_number = 0;

    while (fgets(line, sizeof(line), file) != NULL) {
      line_number++;

      /* INFO: The first line is the header. */
      if (line_number == 1) continue;

      char fields[6][AP_PKG_NAME_MAX + 1];
      size_t field_count = ap_parse_csv_line(line, fields, 6);
      if (field_count < 6) continue;

      char *endptr = NULL;
      long exclude = strtol(fields[1], &endptr, 10);
      if (*endptr != '\0') continue;

      endptr = NULL;
      long allow = strtol(fields[2], &endptr, 10);
      if (*endptr != '\0') continue;

      endptr = NULL;
      long long uid = strtoll(fields[3], &endptr, 10);
      if (*endptr != '\0' || uid < 0 || uid > (long long)UINT_MAX) continue;

      endptr = NULL;
      long long to_uid = strtoll(fields[4], &endptr, 10);
      if (*endptr != '\0' || to_uid < 0 || to_uid > (long long)UINT_MAX) continue;

      if (fields[0][0] == '\0' || rows >= max_rows) continue;

      struct ap_package_entry *entry = &out[rows];

      strncpy(entry->pkg, fields[0], AP_PKG_NAME_MAX);
      entry->pkg[AP_PKG_NAME_MAX] = '\0';
      entry->exclude = ap_parse_bool_field(fields[1]);
      entry->allow = ap_parse_bool_field(fields[2]);
      entry->uid = (uid_t)uid;
      entry->to_uid = (uid_t)to_uid;

      rows++;
    }

    fclose(file);

    return rows;
  }

  return rows;
}

/* INFO: Whether a uid falls inside this row's (possibly ranged) grant. */
static bool ap_uid_in_range(const struct ap_package_entry *entry, uid_t uid) {
  if (entry->to_uid <= entry->uid) return uid == entry->uid;

  return uid >= entry->uid && uid <= entry->to_uid;
}

static bool ap_config_matches(uid_t uid, bool wanted_flag) {
  struct ap_package_entry entries[AP_MAX_ROWS];
  size_t rows = ap_read_package_config(entries, AP_MAX_ROWS);

  for (size_t i = 0; i < rows; i++) {
    bool flag = wanted_flag ? entries[i].allow : entries[i].exclude;
    if (flag && ap_uid_in_range(&entries[i], uid)) return true;
  }

  return false;
}

void ap_get_existence(struct root_impl_state *state) {
  /* INFO: The apd binary and the package configuration are the two things the
           daemon depends on. The APatch Manager runs its own version gate at
           install time, so checking presence here is enough; spawning apd to
           parse "-V" would only add a dependency on its SELinux domain. */
  if (access(AP_BIN_DIR, F_OK) == -1 || access(AP_CONFIG_FILE, F_OK) == -1) {
    LOGI("APatch not found (missing %s or %s).", AP_BIN_DIR, AP_CONFIG_FILE);

    state->state = Inexistent;

    return;
  }

  state->state = Supported;
}

bool ap_uid_granted_root(uid_t uid) {
  return ap_config_matches(uid, true);
}

bool ap_uid_should_umount(uid_t uid) {
  return ap_config_matches(uid, false);
}

/* INFO: The manager may be installed for any user profile, so both /data/user
         and /data/user_de are scanned (the device owner's profile lives at
         /data/user/0). FolkPatch keeps the layout but ships its manager under
         me.yuki.folk. */
static bool ap_dir_belongs_to_manager(const char *base, uid_t uid) {
  DIR *dir = opendir(base);
  if (dir == NULL) return false;

  struct dirent *entry;
  bool found = false;

  while (!found && (entry = readdir(dir)) != NULL) {
    if (entry->d_type != DT_DIR) continue;
    if (entry->d_name[0] == '.') continue;

    char user_dir[PATH_MAX];
    snprintf(user_dir, PATH_MAX, "%s/%s", base, entry->d_name);

    char manager_dir[PATH_MAX];
    snprintf(manager_dir, PATH_MAX, "%s/%s", user_dir, AP_MANAGER_PKG);

    struct stat st;
    if (stat(manager_dir, &st) == 0 && st.st_uid == uid) {
      found = true;

      break;
    }

    snprintf(manager_dir, PATH_MAX, "%s/%s", user_dir, AP_FOLKPATCH_PKG);

    if (stat(manager_dir, &st) == 0 && st.st_uid == uid) {
      found = true;

      break;
    }
  }

  closedir(dir);

  return found;
}

bool ap_uid_is_manager(uid_t uid) {
  if (ap_dir_belongs_to_manager("/data/user_de", uid)) return true;

  return ap_dir_belongs_to_manager("/data/user", uid);
}
