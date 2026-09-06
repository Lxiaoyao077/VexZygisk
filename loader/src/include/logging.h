#ifndef LOGGING_H
#define LOGGING_H

#include <errno.h>
#include <string.h>

#include <android/log.h>

#include "misc.h"

#ifndef LOG_TAG
  #define LOG_TAG "zygisk-core" LP_SELECT("32", "64")
#endif

/* INFO: Release builds are completely silent — every level compiles away
         under NDEBUG, so the injected library never writes to logd. Debug
         packages keep everything for troubleshooting. */
#ifdef NDEBUG
  #define LOGD(...)
  #define LOGV(...)
  #define LOGI(...)
  #define LOGW(...)
  #define LOGE(...)
  #define PLOGE(fmt, args...)
#else
  #define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
  #define LOGV(...) __android_log_print(ANDROID_LOG_VERBOSE, LOG_TAG, __VA_ARGS__)
  #define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
  #define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)
  #define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
  #define PLOGE(fmt, args...) LOGE(fmt " failed with %d: %s", ##args, errno, strerror(errno))
#endif

#endif /* LOGGING_H */
