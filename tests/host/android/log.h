#ifndef ANDROID_LOG_H
#define ANDROID_LOG_H

/* INFO: Stand-in for bionic's <android/log.h> so the loader sources can be
         compiled on the build host. Tests assert on return values, so the log
         only goes to stderr, where it is visible when a run fails. */

#include <stdarg.h>
#include <stdio.h>

#define ANDROID_LOG_UNKNOWN 0
#define ANDROID_LOG_DEFAULT 1
#define ANDROID_LOG_VERBOSE 2
#define ANDROID_LOG_DEBUG   3
#define ANDROID_LOG_INFO    4
#define ANDROID_LOG_WARN    5
#define ANDROID_LOG_ERROR   6
#define ANDROID_LOG_FATAL   7

static inline int __android_log_print(int prio, const char *tag, const char *fmt, ...) {
  (void) prio;

  va_list args;
  va_start(args, fmt);

  fprintf(stderr, "[%s] ", tag);
  vfprintf(stderr, fmt, args);
  fputc('\n', stderr);

  va_end(args);

  return 0;
}

#endif /* ANDROID_LOG_H */
