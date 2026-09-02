#ifndef CONSTANTS_H
#define CONSTANTS_H

#include <stdbool.h>
#include <stdint.h>

#define PROCESS_NAME_MAX_LEN (256 + 1)

#define ZYGOTE_INJECTED LP_SELECT(5, 4)
#define DAEMON_SET_INFO LP_SELECT(7, 6)

/* INFO: Plain macros rather than a typed enum: 1u << 31 does not fit an int,
         and a fixed underlying type is a C23 extension. */
#define PROCESS_GRANTED_ROOT (1u << 0)
#define PROCESS_ON_DENYLIST (1u << 1)
#define PROCESS_IS_MANAGER (1u << 27)
#define PROCESS_ROOT_IS_KSU (1u << 29)
#define PROCESS_IS_FIRST_STARTED (1u << 31)

enum DaemonSocketAction {
  ZygoteInjected         = 0,
  GetProcessFlags        = 1,
  GetInfo                = 2,
  ReadModules            = 3,
  RequestCompanionSocket = 4,
  GetModuleDir           = 5,
  ZygoteRestart          = 6,
  UpdateMountNamespace   = 7,
  RemoveModule           = 8,
  ReadZnModules          = 9,
  SpawnZnCompanion       = 10
};

enum RootImplState {
  Supported,
  TooOld,
  Inexistent,
  Abnormal
};

/* INFO: The loader only ever asks for the clean namespace, so no other state
         is carried over the protocol. */
enum MountNamespaceState {
  Clean
};

#endif /* CONSTANTS_H */
